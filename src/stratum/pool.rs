//! Where to mine and as whom: the settings both pool clients read.
//!
//! Its own file because there are now two clients and one configuration. The
//! V1 loop and the SV2 loop disagree about almost everything on the wire and
//! about none of this: a pool address, a worker name, a difficulty to ask
//! for, how long to wait before reconnecting. Four settings are SV2's alone
//! and they are marked as such on [`Pool`].
//!
//! The one genuinely new problem here is that **the protocol cannot be
//! discovered.** Pool A serves V1 and SV2 on the same port and
//! tells them apart from the first bytes a client sends: a V1 session opens
//! with `{`, an SV2 session with 64 bytes of ElligatorSwift-encoded public
//! key. A client guessing wrongly gets a hang rather than an error, because
//! each side is waiting for the other to say something it would recognise.
//!
//! So it is a setting — and, more usefully, it is already in the URL the pool
//! publishes. [`parse_address`] takes spec §4.7's
//! `stratum2+tcp://host:port/<base58check authority key>`, which is what
//! a pool prints on its connect panel, and one pasted string then
//! carries the protocol, the host, the port and the key to pin.

use std::time::Duration;

use bitcoin::secp256k1::XOnlyPublicKey;

use super::v2::noise::authority_key;

/// Which of the two protocols a session speaks.
///
/// **Not sniffable, and a wrong guess is a hang.** See this module's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    V1,
    V2,
}

impl Protocol {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "v1" | "1" => Ok(Self::V1),
            "v2" | "2" => Ok(Self::V2),
            _ => Err(format!("MINER_POOL_PROTOCOL must be v1 or v2, got {value}")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// What to do about BIP310 version rolling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionRolling {
    /// Roll whatever the pool's `mining.configure` reply agreed to, and nothing
    /// if it agreed to none. The only setting that is always correct.
    Auto,
    /// Never roll, and never send the sixth `mining.submit` parameter. What
    /// every client did before 2018, and still what every pool understands.
    Off,
    /// Roll bits the pool did not agree to, **loopback only**.
    ///
    /// A single deliberate misbehaviour, to test an assertion a pool is
    /// expected to make: a share whose version bits fall outside the
    /// negotiated mask must be rejected. An assertion nothing can violate is an
    /// assertion nothing has tested. Sending those shares to somebody else's
    /// production pool is not a test, which is why this refuses to run against
    /// anything that is not on this machine.
    Force,
}

impl VersionRolling {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "off" | "no" | "none" => Ok(Self::Off),
            "force" => Ok(Self::Force),
            _ => Err(format!(
                "MINER_VERSION_ROLLING must be auto, off or force, got {value}"
            )),
        }
    }

    /// The bits to roll, given what the pool agreed to.
    pub(super) fn mask(self, negotiated: Option<u32>) -> Option<u32> {
        match self {
            Self::Off => None,
            Self::Auto => negotiated,
            // **Whatever was agreed, plus one bit that never is.** Taking the
            // negotiated mask would not misbehave at all against a pool that
            // granted the whole of BIP320, which both measured pools do — and
            // a setting that exists to be rejected has to actually be
            // rejectable. [`OUTSIDE_ANY_MASK`] is the smallest way to be wrong.
            Self::Force => Some(negotiated.unwrap_or(BIP320_MASK) | OUTSIDE_ANY_MASK),
        }
    }
}

/// Whether, and against what, an SV2 pool's certificate is checked.
///
/// **Three states, not an `Option` plus a flag**, so that "pin this key" and
/// "do not verify" cannot both be set. Only [`Self::Unset`] is refused off the
/// loopback; see `v2::run`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// The certificate must verify under this key.
    Pinned(XOnlyPublicKey),
    /// `MINER_POOL_AUTHORITY=skip`: connect without checking the certificate
    /// against anything. **Only ever asked for, never a default**, and no
    /// weaker than V1, which authenticates nothing: still encrypted against a
    /// passive observer, and like V1 open to an active man-in-the-middle.
    Skipped,
    /// Nothing configured, which is refused against anything not on the
    /// loopback — a forgotten key fails loudly rather than quietly becoming
    /// "encrypted to whoever answered".
    Unset,
}

impl Authority {
    /// Read a `MINER_POOL_AUTHORITY` value.
    ///
    /// `skip` is matched before the value is read as a key. It is neither
    /// valid base58check nor 64 hex characters, so it cannot be mistaken for
    /// one.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim() {
            "" => Ok(Self::Unset),
            "skip" => Ok(Self::Skipped),
            key => authority_key(key).map(Self::Pinned),
        }
    }

    /// The key to verify the certificate under, if there is one.
    pub fn key(self) -> Option<XOnlyPublicKey> {
        match self {
            Self::Pinned(key) => Some(key),
            Self::Skipped | Self::Unset => None,
        }
    }
}

/// BIP320's sixteen bits, re-exported where both protocols already import it
/// from. Defined in `block.rs`, because the solo search rolls inside it too.
pub use crate::block::BIP320_MASK;

/// One bit immediately below BIP320's range, which no pool grants and which
/// [`VersionRolling::Force`] rolls anyway.
///
/// It is part of the version number proper, so a pool rebuilding the header as
/// `(announced & !mask) | (submitted & mask)` reconstructs a *different* header
/// than the one that was hashed — and the share then fails the pool's own
/// target check rather than merely its policy. Either refusal proves the point;
/// what matters is that the pool notices.
///
/// Half the rolled versions have it clear and are perfectly good shares, which
/// makes this a better test than one where everything is refused: a pool that
/// accepted all of them is not checking, and a pool that refused all of them is
/// not checking either.
const OUTSIDE_ANY_MASK: u32 = 0x0000_1000;

/// Where to mine, as whom, and over which protocol.
///
/// One struct for both clients rather than two, because all but four of
/// these mean the same thing under either protocol and a second copy would be
/// a second thing to keep in step. The four that are new are at the bottom.
#[derive(Clone, Debug)]
pub struct Pool {
    /// `host:port`. Empty means this mode was not configured.
    pub address: String,
    /// The worker name, conventionally `<address>.<worker>`.
    pub user: String,
    /// The password field, which on a solo pool is a difficulty request.
    pub pass: String,
    /// The share difficulty to ask for, through both levers.
    pub difficulty: f64,
    pub agent: String,
    pub reconnect: Duration,
    /// Whether to roll the header version, and whether to insist on it.
    pub version_rolling: VersionRolling,

    /// Which protocol to speak. **Cannot be discovered — see [`Protocol`].**
    pub protocol: Protocol,
    /// The pool authority key an SV2 certificate must verify under.
    ///
    /// [`Authority::Unset`] refuses to connect to anything that is not on the
    /// loopback, checked before a socket is opened. It is **not a
    /// credential** — a pool publishes it precisely so that miners pin it — so
    /// it is flag-able under the rule that keeps `MINER_POOL_PASS` from being
    /// one, and so is `skip`.
    pub authority: Authority,
    /// `nominal_hash_rate` in h/s, which SV2 sends and V1 has no field for.
    ///
    /// Zero makes no claim and leaves the pool only `max_target` to go on,
    /// which is honest for a client that has not measured itself yet.
    pub hashrate: f32,
    /// `MINER_POOL_CAPTURE`: a file to record every SV2 frame to, in
    /// plaintext, or empty for none. V2 only; see `v2::conn::Capture`.
    pub capture: String,
}

/// What a `MINER_POOL` value said, once it has been taken apart.
///
/// Each field is `None` when the value did not mention it, which is what lets
/// the caller tell "the URL chose v2" from "the URL said nothing and the
/// setting chose v2". Collapsing those two would make a disagreement
/// impossible to detect, which is the whole point of [`resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// `host:port`, always present.
    pub host_port: String,
    /// The protocol the scheme named, if it named one.
    pub protocol: Option<Protocol>,
    /// The authority key the path carried, if it carried one.
    pub authority: Option<XOnlyPublicKey>,
}

/// Take a `MINER_POOL` value apart: `host:port`, or the §4.7 URL form.
///
/// ```text
/// pool.example.com:3333                      host and port, nothing else said
/// stratum+tcp://pool.example.com:3333        …and the protocol is v1
/// stratum2+tcp://host:3350/9aujRnQPBL…        …and v2, and the key to pin
/// ```
///
/// Four rules, because a second source for a fact is a second thing that can
/// disagree with the first:
///
/// - **The scheme sets the protocol.** A bare `host:port` names none and
///   leaves `MINER_POOL_PROTOCOL` deciding, as it does today.
/// - **The path sets the authority key**, and is refused on a
///   `stratum+tcp://` URL, which has nothing to pin it to.
/// - **A missing port is refused rather than defaulted.** There is no port
///   this client could assume that is more likely right than an error saying
///   so — 3333, 3350 and 34254 are all in use by pools this repository has
///   touched.
/// - A disagreement with an explicitly set variable is refused too, but that
///   is [`resolve`]'s business rather than this function's.
pub fn parse_address(text: &str) -> Result<Address, String> {
    let text = text.trim();

    let (protocol, rest) = match text.split_once("://") {
        None => (None, text),
        Some(("stratum+tcp", rest)) => (Some(Protocol::V1), rest),
        Some(("stratum2+tcp", rest)) => (Some(Protocol::V2), rest),
        Some((scheme, _)) => {
            return Err(format!(
                "MINER_POOL has the scheme {scheme}://, and this client knows \
                 stratum+tcp:// (v1) and stratum2+tcp:// (v2). A bare host:port \
                 works too and leaves MINER_POOL_PROTOCOL to decide"
            ));
        }
    };

    let (host_port, path) = match rest.split_once('/') {
        None => (rest, ""),
        Some((host_port, path)) => (host_port, path),
    };

    // The port is checked here rather than left to `to_socket_addrs`, so that
    // the message names the setting instead of arriving as a resolver error.
    let port = host_port.rsplit_once(':').map(|(_, port)| port);
    match port {
        Some(port) if !port.is_empty() && port.parse::<u16>().is_ok() => {}
        _ => {
            return Err(format!(
                "MINER_POOL is {text:?}, which names no port. There is no port this \
                 client can assume: the three pools measured in development use \
                 3333, 3350 and 34254"
            ));
        }
    }

    // A trailing slash with nothing after it is a URL, not a key.
    let authority = match path.trim_end_matches('/') {
        "" => None,
        key => {
            if protocol == Some(Protocol::V1) {
                return Err(format!(
                    "MINER_POOL carries an authority key on a stratum+tcp:// URL, \
                     and Stratum V1 has nothing to pin it to. Did you mean \
                     stratum2+tcp://{rest}?"
                ));
            }
            Some(authority_key(key)?)
        }
    };

    Ok(Address {
        host_port: host_port.to_string(),
        protocol,
        authority,
    })
}

/// Settle a fact that two settings may both have an opinion about.
///
/// **A disagreement is refused, not resolved**, and this is deliberately
/// *not* the "a flag beats the variable" rule. That rule orders two spellings
/// of **one** setting, where both spellings mean the same thing and the only
/// question is which the user typed last. This is two *different* settings
/// disagreeing about one fact, and guessing which was meant is how a miner
/// ends up pinning a key its operator did not choose or speaking a protocol
/// its operator did not ask for.
///
/// `explicit` is whether the variable was actually set by this run rather
/// than left at its compiled-in default — a default that happens to differ
/// from the URL is not a disagreement, it is a setting the URL is there to
/// override.
fn resolve<T: PartialEq + std::fmt::Display>(
    what: &str,
    from_url: Option<T>,
    from_setting: Option<T>,
    explicit: bool,
) -> Result<Option<T>, String> {
    match (from_url, from_setting) {
        (Some(url), Some(setting)) if explicit && url != setting => Err(format!(
            "MINER_POOL's URL says the {what} is {url} and {} says it is {setting}. \
             Both were set explicitly and they disagree, so this is an error rather \
             than a guess: remove one of them",
            match what {
                "protocol" => "MINER_POOL_PROTOCOL",
                _ => "MINER_POOL_AUTHORITY",
            }
        )),
        (Some(url), _) => Ok(Some(url)),
        (None, setting) => Ok(setting),
    }
}

impl Pool {
    /// Fold a parsed `MINER_POOL` together with the two settings that can say
    /// the same things, and refuse a disagreement.
    ///
    /// Takes the pieces rather than a `Settings`, so that every rule above is
    /// testable without an environment.
    pub fn locate(
        address: &Address,
        protocol: Protocol,
        protocol_explicit: bool,
        authority: Authority,
        authority_explicit: bool,
    ) -> Result<(Protocol, Authority), String> {
        let protocol = resolve(
            "protocol",
            address.protocol.map(Spelled),
            Some(Spelled(protocol)),
            protocol_explicit,
        )?
        .expect("the setting always has a value")
        .0;

        // `skip` beside a key in the URL is a disagreement like two different
        // keys, and is refused the same way rather than settled by precedence.
        let authority = resolve(
            "authority key",
            address.authority.map(|key| Spelled(Authority::Pinned(key))),
            match authority {
                Authority::Unset => None,
                set => Some(Spelled(set)),
            },
            authority_explicit,
        )?
        .map_or(Authority::Unset, |authority| authority.0);

        Ok((protocol, authority))
    }
}

/// A `Display` wrapper, so [`resolve`] can name both sides of a disagreement.
///
/// `Protocol` and `Authority` both need one, and a blanket impl cannot be
/// written for them here.
#[derive(PartialEq)]
struct Spelled<T>(T);

impl std::fmt::Display for Spelled<Protocol> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.name())
    }
}

impl std::fmt::Display for Spelled<Authority> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Authority::Pinned(key) => write!(f, "{key}"),
            Authority::Skipped => write!(f, "skip"),
            Authority::Unset => write!(f, "unset"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test authority key, generated for these tests, in both spellings.
    const TEST_KEY_HEX: &str = "24b1551ef29e71a667310c33e8b46f9745628d3b9bdeecf86f2a18b9f20c5635";
    const TEST_KEY_B58: &str = "9aujRnQPBLwXLioR47tVsXLWawgZDRGtBF4JBLYpBc7qgnFXKXw";

    fn key(text: &str) -> XOnlyPublicKey {
        authority_key(text).expect("the test key")
    }

    #[test]
    fn the_rolling_policy_decides_what_the_negotiation_is_worth() {
        // `off` ignores an agreement, `auto` takes it, and `force` invents one.
        let agreed = Some(0x1fff_e000);

        assert_eq!(VersionRolling::Off.mask(agreed), None);
        assert_eq!(VersionRolling::Off.mask(None), None);

        assert_eq!(VersionRolling::Auto.mask(agreed), agreed);
        assert_eq!(
            VersionRolling::Auto.mask(None),
            None,
            "auto rolls nothing against a pool that agreed to nothing"
        );

        // Force is the one that must *not* come back equal to the agreement:
        // against a pool that granted the whole of BIP320 — which both measured
        // pools do — an agreed mask would misbehave in no way at all, and a
        // setting that exists to be rejected has to be rejectable.
        assert_eq!(
            VersionRolling::Force.mask(agreed),
            Some(0x1fff_f000),
            "force adds a bit outside anything a pool grants"
        );
        assert_ne!(VersionRolling::Force.mask(agreed), agreed);
        assert_eq!(
            VersionRolling::Force.mask(None),
            Some(BIP320_MASK | OUTSIDE_ANY_MASK),
            "force against a pool that refused still rolls something to be rejected for"
        );
        assert_eq!(
            OUTSIDE_ANY_MASK & BIP320_MASK,
            0,
            "the extra bit is outside the range pools grant, which is the whole point"
        );
    }

    #[test]
    fn the_rolling_setting_is_read_the_way_somebody_would_type_it() {
        assert_eq!(VersionRolling::parse("auto"), Ok(VersionRolling::Auto));
        assert_eq!(VersionRolling::parse("off"), Ok(VersionRolling::Off));
        assert_eq!(VersionRolling::parse("none"), Ok(VersionRolling::Off));
        assert_eq!(VersionRolling::parse("force"), Ok(VersionRolling::Force));
        assert!(
            VersionRolling::parse("on").is_err(),
            "on is not a setting here"
        );
        assert!(VersionRolling::parse("").is_err());
    }

    #[test]
    fn a_bare_host_and_port_still_means_exactly_what_it_did() {
        // Every existing invocation, unchanged: no scheme, no path, and
        // nothing said about either of the two new settings.
        let parsed = parse_address("pool.example.com:3333").unwrap();
        assert_eq!(parsed.host_port, "pool.example.com:3333");
        assert_eq!(parsed.protocol, None, "the setting decides");
        assert_eq!(parsed.authority, None);

        // Including an IPv6 literal, whose colons are not the port separator.
        let parsed = parse_address("[::1]:3333").unwrap();
        assert_eq!(parsed.host_port, "[::1]:3333");
    }

    #[test]
    fn the_url_the_pool_publishes_carries_all_four_facts() {
        // The string a pool prints on its connect panel, which is the
        // whole reason this form is accepted: one paste instead of four
        // chances to mistype a 51-character base58 key.
        let text = format!("stratum2+tcp://pool.example.com:3333/{TEST_KEY_B58}");
        let parsed = parse_address(&text).unwrap();

        assert_eq!(parsed.host_port, "pool.example.com:3333");
        assert_eq!(parsed.protocol, Some(Protocol::V2));
        assert_eq!(parsed.authority, Some(key(TEST_KEY_HEX)));

        // And the V1 spelling, for symmetry, which names a protocol and
        // nothing else.
        let parsed = parse_address("stratum+tcp://pool.example.com:3333").unwrap();
        assert_eq!(parsed.host_port, "pool.example.com:3333");
        assert_eq!(parsed.protocol, Some(Protocol::V1));
        assert_eq!(parsed.authority, None);

        // A trailing slash is a URL, not an empty key.
        let parsed = parse_address("stratum2+tcp://host:3350/").unwrap();
        assert_eq!(parsed.authority, None);
    }

    #[test]
    fn a_url_this_client_cannot_honour_is_refused_by_name() {
        // A scheme it does not know, rather than one it guesses at.
        let why = parse_address("stratum+ssl://host:3350").expect_err("no TLS here");
        assert!(why.contains("stratum+ssl"), "{why}");
        assert!(why.contains("stratum2+tcp"), "and what it does know: {why}");

        // A key on a V1 URL, which has nothing to pin it to. The message
        // offers the URL the reader probably meant.
        let why = parse_address(&format!("stratum+tcp://host:3350/{TEST_KEY_B58}"))
            .expect_err("V1 has no certificate");
        assert!(why.contains("stratum2+tcp://host:3350"), "{why}");

        // A key that is not a key.
        assert!(parse_address("stratum2+tcp://host:3350/nonsense").is_err());

        // No port, in both forms. There is no default worth inventing.
        for text in [
            "pool.example.com",
            "stratum2+tcp://pool.example.com",
            "host:",
            "host:notaport",
            "host:99999",
        ] {
            let why = parse_address(text).expect_err("{text} names no port");
            assert!(why.contains("no port"), "{text}: {why}");
        }
    }

    #[test]
    fn a_disagreement_is_refused_rather_than_ordered() {
        // **The rule this test exists for.** "A flag beats the variable"
        // orders two spellings of one setting; this is two settings
        // disagreeing about one fact, and guessing is how a miner pins a key
        // nobody chose.
        let url = parse_address(&format!("stratum2+tcp://host:3350/{TEST_KEY_B58}")).unwrap();

        let why = Pool::locate(&url, Protocol::V1, true, Authority::Unset, false)
            .expect_err("the URL says v2 and the setting explicitly says v1");
        assert!(why.contains("protocol"), "{why}");
        assert!(
            why.contains("v2") && why.contains("v1"),
            "both sides: {why}"
        );
        assert!(why.contains("MINER_POOL_PROTOCOL"), "{why}");

        let other = key("9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh");
        let why = Pool::locate(&url, Protocol::V2, false, Authority::Pinned(other), true)
            .expect_err("two different keys");
        assert!(why.contains("authority key"), "{why}");
        assert!(why.contains("MINER_POOL_AUTHORITY"), "{why}");
    }

    #[test]
    fn skip_beside_a_key_in_the_url_is_refused_as_a_disagreement() {
        // "Pin this key" and "do not verify" cannot both be meant, and which
        // one wins is not this client's to guess.
        let url = parse_address(&format!("stratum2+tcp://host:3350/{TEST_KEY_B58}")).unwrap();
        let why = Pool::locate(&url, Protocol::V2, false, Authority::Skipped, true)
            .expect_err("skip and a pinned key");
        assert!(why.contains("skip"), "{why}");
        assert!(why.contains("MINER_POOL_AUTHORITY"), "{why}");

        // Without a key in the URL, skip is simply what was asked for.
        let bare = parse_address("host:3350").unwrap();
        let (_, authority) =
            Pool::locate(&bare, Protocol::V2, true, Authority::Skipped, true).unwrap();
        assert_eq!(authority, Authority::Skipped);
    }

    #[test]
    fn skip_is_a_word_and_not_a_key_and_empty_is_nothing() {
        assert_eq!(Authority::parse("skip"), Ok(Authority::Skipped));
        assert_eq!(Authority::parse(" skip "), Ok(Authority::Skipped));
        assert_eq!(Authority::parse(""), Ok(Authority::Unset));
        assert_eq!(
            Authority::parse(TEST_KEY_B58),
            Ok(Authority::Pinned(key(TEST_KEY_HEX)))
        );
        assert_eq!(Authority::Skipped.key(), None);
        // Nothing near it is read as skip.
        assert!(Authority::parse("SKIP").is_err());
        assert!(Authority::parse("skipped").is_err());
    }

    #[test]
    fn a_default_that_differs_from_the_url_is_not_a_disagreement() {
        // `MINER_POOL_PROTOCOL` defaults to v1, so a `stratum2+tcp://` URL
        // would collide with it on every single run if an unset variable
        // counted as an opinion. It does not: that is what the URL is for.
        let url = parse_address(&format!("stratum2+tcp://host:3350/{TEST_KEY_B58}")).unwrap();
        let (protocol, authority) =
            Pool::locate(&url, Protocol::V1, false, Authority::Unset, false).unwrap();
        assert_eq!(protocol, Protocol::V2);
        assert_eq!(authority, Authority::Pinned(key(TEST_KEY_HEX)));

        // And agreeing explicitly is fine, however redundant.
        let (protocol, authority) = Pool::locate(
            &url,
            Protocol::V2,
            true,
            Authority::Pinned(key(TEST_KEY_HEX)),
            true,
        )
        .unwrap();
        assert_eq!(protocol, Protocol::V2);
        assert_eq!(authority, Authority::Pinned(key(TEST_KEY_HEX)));
    }

    #[test]
    fn a_setting_still_works_where_the_url_says_nothing() {
        // The third spelling: a bare host:port with the key as a flag.
        //   ./v2 pool.example.com:3333 --pool-authority 24b1…
        let url = parse_address("pool.example.com:3333").unwrap();
        let (protocol, authority) = Pool::locate(
            &url,
            Protocol::V2,
            true,
            Authority::Pinned(key(TEST_KEY_HEX)),
            true,
        )
        .unwrap();
        assert_eq!(protocol, Protocol::V2);
        assert_eq!(authority, Authority::Pinned(key(TEST_KEY_HEX)));
    }

    #[test]
    fn the_protocol_is_read_the_way_somebody_would_type_it() {
        assert_eq!(Protocol::parse("v1"), Ok(Protocol::V1));
        assert_eq!(Protocol::parse("v2"), Ok(Protocol::V2));
        assert_eq!(Protocol::parse("2"), Ok(Protocol::V2));
        assert!(Protocol::parse("sv2").is_err(), "the setting is v2");
        assert!(Protocol::parse("").is_err());
        assert_eq!(Protocol::V2.name(), "v2");
    }
}
