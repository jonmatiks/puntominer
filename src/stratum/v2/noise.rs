//! `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`: the handshake, the
//! certificate check, and the two transport cipher states it produces.
//!
//! **The one file in this repository where a bug is silent.** Everything else
//! here fails loudly: a wrong merkle fold is a rejected share, a wrong
//! hasher is caught by `rust-bitcoin` before anything is reported, a wrong
//! byte order is a header no pool recognises. A mis-ordered ECDH, a reused
//! nonce or a skipped certificate validity window produces a session that
//! works perfectly and is not secure, and nothing downstream will ever
//! mention it.
//!
//! So it is worth being precise about what is hand-rolled here and what is
//! not. **The AEAD primitive is not ours**: `chacha20poly1305` does the
//! constant-time work, and this file never touches a cipher's internals.
//! What is ours is the *key schedule* — the chaining key, the two `MixKey`
//! calls, the final HKDF — the *nonce discipline*, and the *certificate
//! check*. Those are the three that fail quietly.
//!
//! Two things mitigate that, and neither removes it:
//!
//! 1. **An independent implementation is the oracle.** `noise_sv2` is a
//!    dev-dependency for exactly the reason `sha2` is a runtime one: to be a
//!    second opinion rather than to be used. The tests below run this
//!    `Handshake` against that crate's responder and then send real traffic
//!    both ways through the resulting cipher states. Agreeing with a separate
//!    implementation on the transport keys means agreeing about the protocol
//!    name hash, the ECDH role order and the nonce layout simultaneously, and
//!    no test written against this file alone can do that.
//! 2. **There is no trust-on-first-use.** A pool that publishes an authority
//!    key and a client that ignores it is the entire authentication story
//!    thrown away for one line of convenience, so an unpinned key refuses to
//!    connect to anything that is not on the loopback — checked before a
//!    socket is opened, beside the regtest gate and the
//!    `MINER_VERSION_ROLLING=force` gate.
//!
//! The handshake is `Noise_NX`, three steps, of which the client sends one
//! message and receives one:
//!
//! ```text
//! ->  e                     64 bytes, plaintext ElligatorSwift
//! <-  e, ee, s, es          234 bytes: 64 plain + 80 encrypted static + 90 encrypted certificate
//!     (no message)          the certificate is verified against the pinned authority key
//! ```

use std::{
    fs::File,
    io::Read,
    sync::atomic::{Ordering, compiler_fence},
};

use bitcoin::secp256k1::{
    All, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
    ellswift::{ElligatorSwift, ElligatorSwiftParty},
    schnorr,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use sha2::{Digest, Sha256};

use super::codec::Reader;

/// The official Noise protocol name, 45 bytes and therefore hashed rather
/// than zero-padded.
///
/// The length matters: Noise zero-pads a name of 32 bytes or fewer and
/// hashes anything longer, so a name one byte either side of the boundary
/// would be mixed in differently. It is a long way past it.
const PROTOCOL_NAME: &[u8] = b"Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256";

/// The second handshake message: 64 plaintext + 80 encrypted + 90 encrypted.
pub const PART_2_LEN: usize = 234;

/// `SIGNATURE_NOISE_MESSAGE`: version, valid_from, not_valid_after, signature.
const CERTIFICATE_LEN: usize = 2 + 4 + 4 + 64;

/// The only certificate format this client understands. §4.5.3: an initiator
/// MUST reject a certificate whose version it does not support.
const CERTIFICATE_VERSION: u16 = 0;

/// The `[1, 0]` little-endian `u16` that prefixes a base58check authority key.
///
/// §4.7 is explicit that this "versions the key encoding only and is
/// unrelated to the certificate `version` field", which is worth repeating
/// because the two are both called a version and are both currently the
/// number this constant starts with.
const AUTHORITY_KEY_PREFIX: [u8; 2] = [1, 0];

/// Overwrite a buffer so the key does not outlive its use.
///
/// `write_volatile` and a compiler fence rather than a loop the optimiser is
/// entitled to delete, hand-rolled because nothing else in this repository
/// needs it. This is best-effort and is stated as such: a value may already
/// have been copied into a register or spilled to a stack slot this cannot
/// reach. It is worth doing anyway, and it is worth not overstating.
fn zeroize(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // Safety: a valid mutable reference to one byte, written once.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// SHA-256 over a sequence of pieces, so a caller never builds the
/// concatenation itself.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// HMAC-SHA-256 with a 32-byte key, which is the only size this protocol uses.
///
/// Spelled out rather than taken from a crate because §4.4.2 spells it out:
/// the key is padded to the 64-byte block, XORed with `ipad` and `opad`, and
/// hashed twice. Fifteen lines against a published definition, and the HKDF
/// built on it is checked against an independent implementation below.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for part in parts {
        inner.update(part);
    }
    let temp: [u8; 32] = inner.finalize().into();

    let out = sha256(&[&outer_pad, &temp]);
    zeroize(&mut inner_pad);
    zeroize(&mut outer_pad);
    out
}

/// `HKDF(chaining_key, input_key_material)` with a zero-length info and two
/// outputs, per §4.4.2.
fn hkdf2(chaining_key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut temp = hmac_sha256(chaining_key, &[input]);
    let first = hmac_sha256(&temp, &[&[0x01]]);
    let second = hmac_sha256(&temp, &[&first, &[0x02]]);
    zeroize(&mut temp);
    (first, second)
}

/// Read `N` bytes from the operating system's entropy source.
///
/// `/dev/urandom` directly, for the reason `rpc.rs` speaks HTTP directly: a
/// crate for six lines is a crate to justify forever, and this repository
/// already targets the platforms that have it. **It fails rather than falling
/// back.** There is no second-best source for a Noise ephemeral key — a
/// timestamp-derived one would produce a handshake that completes and a
/// session an observer can decrypt, which is precisely the failure this whole
/// file exists to avoid.
fn os_random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|error| {
            format!(
                "could not read {N} bytes of entropy from /dev/urandom: {error}. \
                 There is no fallback: a Noise session keyed from anything predictable \
                 completes the handshake and protects nothing"
            )
        })?;
    Ok(bytes)
}

/// One direction's transport state: a 32-byte key and a 64-bit counter.
///
/// Two of these come out of a handshake and they are not interchangeable —
/// one encrypts what this client sends and the other decrypts what the pool
/// sends, each with its own counter.
pub struct CipherState {
    key: [u8; 32],
    nonce: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    /// The 12-byte IETF nonce this protocol's counter maps to.
    ///
    /// **Four zero bytes, then the counter little-endian.** The spec
    /// flags this itself — "this follows the Noise Protocol convention,
    /// rather than our normal endian" — and it is worth reading twice,
    /// because the sentence is a warning about the *other* fields rather than
    /// about this one. The layout is not the IETF ChaCha20-Poly1305
    /// convention of a 32-bit sender prefix followed by a 64-bit big-endian
    /// counter, and the two agree only while the counter is zero: the very
    /// first frame of a session encrypts identically either way, and every
    /// frame after it does not.
    fn nonce_bytes(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.nonce.to_le_bytes());
        nonce
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(&Key::from(self.key))
    }

    /// `ENCRYPT(k, n++, ad, pt)`.
    ///
    /// Infallible in practice — ChaCha20-Poly1305 refuses only a plaintext
    /// past 256GB — and the error is returned rather than unwrapped because a
    /// panic inside a mining session is a stopped miner.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let out = self
            .cipher()
            .encrypt(
                &Nonce::from(self.nonce_bytes()),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|error| {
                format!(
                    "could not encrypt a {}-byte message: {error}",
                    plaintext.len()
                )
            })?;
        // **Incremented only on success**, which costs nothing here and is
        // the same rule the decrypt side depends on.
        self.nonce += 1;
        Ok(out)
    }

    /// `DECRYPT(k, n++, ad, ct)`.
    ///
    /// **The counter does not advance on an authentication failure**, per
    /// §4.4.1. That is not tidiness: a transient failure that advanced it
    /// would desynchronise the two ends permanently, turning one bad frame
    /// into a session where nothing decrypts again.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let out = self
            .cipher()
            .decrypt(
                &Nonce::from(self.nonce_bytes()),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| {
                format!(
                    "the pool sent {} bytes that did not authenticate at nonce {}; \
                     the session is over, because a Noise stream cannot be resynchronised",
                    ciphertext.len(),
                    self.nonce
                )
            })?;
        self.nonce += 1;
        Ok(out)
    }
}

impl Drop for CipherState {
    fn drop(&mut self) {
        zeroize(&mut self.key);
    }
}

impl std::fmt::Debug for CipherState {
    /// The counter, never the key.
    ///
    /// A `derive(Debug)` here would put a live session key into any log line
    /// or panic message that formatted the struct holding it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CipherState {{ nonce: {} }}", self.nonce)
    }
}

/// The initiator half of the handshake, between its two messages.
///
/// Consumed by [`Self::finish`], so a handshake cannot be completed twice and
/// an ephemeral key cannot be reused.
pub struct Handshake {
    /// The handshake hash: everything sent and received so far.
    h: [u8; 32],
    /// The chaining key: everything the ECDHs have produced so far.
    ck: [u8; 32],
    /// The current handshake encryption key, empty until the first `MixKey`.
    k: Option<[u8; 32]>,
    ephemeral_secret: SecretKey,
    ephemeral_public: ElligatorSwift,
    secp: Secp256k1<All>,
}

impl Handshake {
    /// Start a handshake, returning the 64 bytes to put on the socket.
    ///
    /// Fallible because of the entropy read: there is no ephemeral key to
    /// fall back to.
    pub fn start() -> Result<(Self, [u8; 64]), String> {
        // Step 1 of §4.5.1, and **the third line is the trap**: `h` is hashed
        // a second time after `ck` has taken its value. Skipping it produces
        // a handshake that is internally consistent and agrees with nobody.
        let protocol_hash = sha256(&[PROTOCOL_NAME]);
        let ck = protocol_hash;
        let mut h = sha256(&[&protocol_hash]);

        let secp = Secp256k1::new();
        let (ephemeral_secret, ephemeral_public) = ephemeral_keypair(&secp)?;
        let serialized = ephemeral_public.to_array();

        // `MixHash(e.public_key)`, over the 64-byte ElligatorSwift encoding —
        // the same bytes that go on the wire, not the 32-byte x-coordinate.
        h = sha256(&[&h, &serialized]);
        // `EncryptAndHash()` with an empty payload. `k` is empty at this
        // point, so this is `MixHash` over nothing, which is still a hash.
        h = sha256(&[&h]);

        Ok((
            Self {
                h,
                ck,
                k: None,
                ephemeral_secret,
                ephemeral_public,
                secp,
            },
            serialized,
        ))
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = sha256(&[&self.h, data]);
    }

    fn mix_key(&mut self, input: &[u8; 32]) {
        let (ck, k) = hkdf2(&self.ck, input);
        zeroize(&mut self.ck);
        self.ck = ck;
        if let Some(old) = self.k.as_mut() {
            zeroize(old);
        }
        self.k = Some(k);
    }

    /// `DecryptAndHash`: decrypt under `h` as associated data, then mix the
    /// **ciphertext** into `h`.
    ///
    /// The ciphertext and not the plaintext, which is the easy half of this
    /// to get backwards and which both ends would have to get backwards the
    /// same way to still agree.
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self
            .k
            .ok_or("a handshake message was to be decrypted before any key existed")?;
        // A fresh state per call: each handshake decryption is nonce 0 under
        // a key that a `MixKey` has just replaced.
        let plaintext = CipherState::new(key).decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// `ECDH(e.private_key, rk)`, always as the initiator.
    ///
    /// **This is not commutative with respect to roles.** §4.3.1.1
    /// defines `v2_ecdh` as a tagged hash over the two ElligatorSwift
    /// encodings *in initiator-then-responder order* followed by the shared
    /// x-coordinate, so the same two keys produce a different secret
    /// depending on who is asking. `ElligatorSwiftParty::A` is the initiator,
    /// which this client always is; getting it backwards fails at the first
    /// decrypt with no diagnostic beyond "did not authenticate".
    ///
    /// `ElligatorSwift::shared_secret` is BIP324's own tagged-hash ECDH, tag
    /// and all, which is byte-for-byte what the spec defines — so this is one
    /// of the places a second opinion comes from `rust-bitcoin` for free.
    fn ecdh(&self, theirs: ElligatorSwift) -> [u8; 32] {
        *ElligatorSwift::shared_secret(
            self.ephemeral_public,
            theirs,
            self.ephemeral_secret,
            ElligatorSwiftParty::A,
            None,
        )
        .as_secret_bytes()
    }

    /// Consume the 234-byte second message and produce the transport states.
    ///
    /// Returns `(outgoing, incoming)`: the first encrypts what this client
    /// sends, the second decrypts what the pool sends. §4.5.2.2 names them
    /// `c1` and `c2` in that order, and swapping them is a session where the
    /// first frame in each direction is a MAC failure.
    ///
    /// `now` is a unix timestamp, passed in rather than read here so the
    /// validity window is testable without waiting for one.
    pub fn finish(
        mut self,
        message: &[u8; PART_2_LEN],
        authority: Option<XOnlyPublicKey>,
        now: u32,
    ) -> Result<(CipherState, CipherState), String> {
        // 1. The responder's ephemeral key, in the clear.
        let their_ephemeral: [u8; 64] = message[..64].try_into().expect("sixty-four bytes");
        self.mix_hash(&their_ephemeral);
        let ecdh = self.ecdh(ElligatorSwift::from_array(their_ephemeral));
        self.mix_key(&ecdh);

        // 2. The responder's static key, encrypted under what that produced.
        let their_static = self.decrypt_and_hash(&message[64..144]).map_err(|why| {
            format!(
                "the pool's static key did not decrypt: {why}. \
                     This is what a handshake looks like when the two ends disagree about \
                     the key schedule rather than about the keys"
            )
        })?;
        let their_static: [u8; 64] = their_static.as_slice().try_into().map_err(|_| {
            format!(
                "the pool's static key is {} bytes, not 64",
                their_static.len()
            )
        })?;
        let their_static = ElligatorSwift::from_array(their_static);
        let ecdh = self.ecdh(their_static);
        self.mix_key(&ecdh);

        // 3. The certificate, encrypted under what *that* produced.
        let certificate = self
            .decrypt_and_hash(&message[144..PART_2_LEN])
            .map_err(|why| format!("the pool's certificate did not decrypt: {why}"))?;

        // The server's static key as the certificate signs it: the 32-byte
        // x-coordinate, decoded out of the 64-byte ElligatorSwift form.
        let server_key = PublicKey::from_ellswift(their_static).x_only_public_key().0;
        verify_certificate(&self.secp, &certificate, server_key, authority, now)?;

        // 4. The transport keys, from the chaining key alone.
        let (outgoing, incoming) = hkdf2(&self.ck, &[]);
        Ok((CipherState::new(outgoing), CipherState::new(incoming)))
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        zeroize(&mut self.h);
        zeroize(&mut self.ck);
        if let Some(k) = self.k.as_mut() {
            zeroize(k);
        }
        self.ephemeral_secret.non_secure_erase();
    }
}

/// A fresh secp256k1 keypair with its public half ElligatorSwift-encoded.
///
/// **`ElligatorSwift::from_seckey` and never `ElligatorSwift::new`.** The
/// latter passes `secp256k1_context_no_precomp` to
/// `secp256k1_ellswift_create`, which needs the `ecmult_gen` table — and
/// libsecp256k1 answers that by firing its illegal-argument callback, which
/// **aborts the process**. It does not return an error and there is nothing
/// to catch: the miner dies with `thread caused non-unwinding panic` and no
/// stack. Found by running it. The context here is a real
/// `Secp256k1::new()`, which carries both tables.
fn ephemeral_keypair(secp: &Secp256k1<All>) -> Result<(SecretKey, ElligatorSwift), String> {
    // A random 32-byte string is a valid secret key unless it is zero or past
    // the group order, which is about a 1-in-2^128 event. Retried rather than
    // failed, and bounded rather than looped forever.
    for _ in 0..8 {
        let seed: [u8; 32] = os_random()?;
        let Ok(secret) = SecretKey::from_slice(&seed) else {
            continue;
        };
        // Extra entropy for the encoding itself, so the 64 bytes that go out
        // in the clear are indistinguishable from random rather than a
        // deterministic function of the key behind them.
        let aux: [u8; 32] = os_random()?;
        let public = ElligatorSwift::from_seckey(secp, secret, Some(aux));
        return Ok((secret, public));
    }
    Err(
        "eight consecutive 32-byte reads from /dev/urandom were not valid secret keys, \
         which is not something that happens to a working entropy source"
            .into(),
    )
}

/// Check the certificate, rather than merely parsing it.
///
/// Four things, each refused by name, because "the handshake failed" is not a
/// diagnosis: an unsupported version, a window that has not opened, a window
/// that has closed, and a signature that does not verify under the **pinned**
/// authority key.
///
/// **`authority` of `None` skips the fourth and only the fourth**, and is
/// reachable only on the loopback — the gate in [`run`](super::run) refuses an
/// unpinned key against anything else before a socket is opened. The version
/// and the validity window are still checked, because they are structural
/// facts about the certificate rather than claims about who signed it. What is
/// given up is the identity of the far end, which on the loopback is the
/// machine the client is already running on.
fn verify_certificate(
    secp: &Secp256k1<All>,
    certificate: &[u8],
    server_key: XOnlyPublicKey,
    authority: Option<XOnlyPublicKey>,
    now: u32,
) -> Result<(), String> {
    if certificate.len() != CERTIFICATE_LEN {
        return Err(format!(
            "the pool's certificate is {} bytes and a SIGNATURE_NOISE_MESSAGE is {CERTIFICATE_LEN}",
            certificate.len()
        ));
    }

    let mut reader = Reader::new(certificate);
    let version = reader.u16()?;
    let valid_from = reader.u32()?;
    let not_valid_after = reader.u32()?;
    let signature = reader.u256()?;
    let signature_tail = reader.u256()?;
    reader.finish()?;

    if version != CERTIFICATE_VERSION {
        return Err(format!(
            "the pool's certificate is version {version} and this client understands \
             version {CERTIFICATE_VERSION} only"
        ));
    }
    if now < valid_from {
        return Err(format!(
            "the pool's certificate is not valid until {valid_from} and it is now {now}. \
             A clock that is wrong by more than the certificate's window looks exactly \
             like a pool with a bad certificate"
        ));
    }
    if now > not_valid_after {
        return Err(format!(
            "the pool's certificate expired at {not_valid_after} and it is now {now}"
        ));
    }

    // §4.5.3.1: `m = SHA-256(version || valid_from || not_valid_after ||
    // server_public_key)`, with each field serialized as its SV2 type and the
    // server key as its 32-byte x-coordinate.
    let message = sha256(&[
        &version.to_le_bytes(),
        &valid_from.to_le_bytes(),
        &not_valid_after.to_le_bytes(),
        &server_key.serialize(),
    ]);

    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&signature);
    raw[32..].copy_from_slice(&signature_tail);
    let signature = schnorr::Signature::from_slice(&raw)
        .map_err(|error| format!("the pool's certificate signature is malformed: {error}"))?;

    let Some(authority) = authority else {
        // Loopback only. The certificate is well formed and in date, and
        // nothing says whose it is.
        return Ok(());
    };

    secp.verify_schnorr(&signature, &Message::from_digest(message), &authority)
        .map_err(|_| {
            format!(
                "the pool's certificate is not signed by the authority key this run pinned \
                 ({authority}). Either the key is wrong or this is not the pool it claims \
                 to be, and there is no way to tell which from here"
            )
        })
}

/// A configured authority key: base58check as §4.7 defines it, or bare hex.
///
/// Both spellings because a pool publishes both — a connect panel may
/// print the hex beside the base58check, and the URL form in
/// `MINER_POOL` carries the base58check one. Neither is a credential: the
/// whole point of an authority *public* key is that miners pin it.
pub fn authority_key(text: &str) -> Result<XOnlyPublicKey, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("an authority key is needed and none was configured".into());
    }

    // 64 hex characters is unambiguous — no base58check string of a 32-byte
    // key is that length — so the two forms are told apart by shape rather
    // than by a prefix the user has to type.
    let raw = if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        super::super::wire::bytes_from_hex(text)
            .map_err(|why| format!("the authority key {why}"))?
    } else {
        let decoded = bitcoin::base58::decode_check(text).map_err(|error| {
            format!(
                "the authority key {text:?} is neither 64 hex characters nor \
                 valid base58check: {error}"
            )
        })?;
        let (prefix, key) = decoded.split_at_checked(2).ok_or_else(|| {
            format!(
                "the authority key {text:?} decodes to {} bytes, which is not a \
                 two-byte prefix and a 32-byte key",
                decoded.len()
            )
        })?;
        if prefix != AUTHORITY_KEY_PREFIX {
            return Err(format!(
                "the authority key {text:?} has the version prefix {prefix:?} and \
                 this client understands {AUTHORITY_KEY_PREFIX:?} only"
            ));
        }
        key.to_vec()
    };

    XOnlyPublicKey::from_slice(&raw).map_err(|error| {
        format!("the authority key {text:?} is not a secp256k1 x-coordinate: {error}")
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The spec's §4.7.1 vector, as a published constant worth pinning for
    /// the same reason `MINER_MODE=probe` pins the genesis header's hash.
    const SPEC_KEY_RAW: [u8; 32] = [
        118, 99, 112, 0, 151, 156, 28, 17, 175, 12, 48, 11, 205, 140, 127, 228, 134, 16, 252, 233,
        185, 193, 30, 61, 174, 227, 90, 224, 176, 138, 116, 85,
    ];
    const SPEC_KEY_B58: &str = "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh";

    /// A key generated for these tests, in both spellings.
    const TEST_KEY_HEX: &str = "24b1551ef29e71a667310c33e8b46f9745628d3b9bdeecf86f2a18b9f20c5635";
    const TEST_KEY_B58: &str = "9aujRnQPBLwXLioR47tVsXLWawgZDRGtBF4JBLYpBc7qgnFXKXw";

    #[test]
    fn the_protocol_name_hashes_to_what_an_independent_implementation_expects() {
        // The protocol-name hash, and the cheapest cross-check in the file:
        // `noise_sv2` ships the same hash as a literal constant it computed
        // separately. A protocol name that is one character out produces a
        // handshake that is perfectly self-consistent and agrees with nobody.
        assert_eq!(PROTOCOL_NAME.len(), 45, "longer than 32, so it is hashed");
        assert_eq!(
            sha256(&[PROTOCOL_NAME]),
            noise_sv2::NOISE_HASHED_PROTOCOL_NAME_CHACHA,
        );
    }

    #[test]
    fn the_nonce_is_four_zero_bytes_and_then_a_little_endian_counter() {
        // The reason a test is needed rather than a reading: the
        // IETF layout and this one agree exactly while the counter is zero,
        // so the first frame of a session proves nothing.
        let mut state = CipherState::new([0x42; 32]);
        assert_eq!(state.nonce_bytes(), [0u8; 12], "counter zero is all zeros");

        state.nonce = 1;
        assert_eq!(
            state.nonce_bytes(),
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
            "little-endian, starting at byte 4"
        );

        state.nonce = 0x0102_0304_0506_0708;
        assert_eq!(
            state.nonce_bytes(),
            [0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        );

        // The big-endian reading, named so it is refused rather than merely
        // not written.
        let big_endian = {
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
            nonce
        };
        assert_ne!(state.nonce_bytes(), big_endian);
    }

    #[test]
    fn a_cipher_state_round_trips_and_a_tampered_frame_does_not() {
        let mut out = CipherState::new([7u8; 32]);
        let mut back = CipherState::new([7u8; 32]);

        // A six-byte frame header becomes exactly 22 bytes, which is the
        // number `frame::ENCRYPTED_HEADER_LEN` asserts from the other side.
        let header = [0x00, 0x80, 0x1f, 0x10, 0x00, 0x00];
        let sealed = out.encrypt_with_ad(&[], &header).unwrap();
        assert_eq!(sealed.len(), 22);
        assert_eq!(back.decrypt_with_ad(&[], &sealed).unwrap(), header);

        // And the counters have to stay in step frame after frame, which is
        // the property a wrong nonce layout breaks on the *second* one.
        for length in [0usize, 1, 100, 5000] {
            let plaintext = vec![0xabu8; length];
            let sealed = out.encrypt_with_ad(&[], &plaintext).unwrap();
            assert_eq!(sealed.len(), length + 16);
            assert_eq!(back.decrypt_with_ad(&[], &sealed).unwrap(), plaintext);
        }
        assert_eq!(out.nonce, 5);
        assert_eq!(back.nonce, 5);

        // One flipped bit is a dead session, and the counter must not move.
        let mut tampered = out.encrypt_with_ad(&[], b"a share").unwrap();
        tampered[0] ^= 1;
        let before = back.nonce;
        assert!(back.decrypt_with_ad(&[], &tampered).is_err());
        assert_eq!(
            back.nonce, before,
            "a failed decrypt must not advance the counter, or the stream can never resynchronise"
        );
    }

    #[test]
    fn the_associated_data_is_authenticated_even_though_it_is_not_encrypted() {
        // The handshake decryptions pass `h` as associated data, so this is
        // the property that binds each step to everything before it.
        let mut out = CipherState::new([9u8; 32]);
        let sealed = out
            .encrypt_with_ad(b"the handshake hash", b"the static key")
            .unwrap();

        assert!(
            CipherState::new([9u8; 32])
                .decrypt_with_ad(b"a different hash", &sealed)
                .is_err()
        );
        assert_eq!(
            CipherState::new([9u8; 32])
                .decrypt_with_ad(b"the handshake hash", &sealed)
                .unwrap(),
            b"the static key"
        );
    }

    #[test]
    fn the_authority_key_parses_the_specs_own_vector_in_both_spellings() {
        let from_b58 = authority_key(SPEC_KEY_B58).expect("the §4.7.1 vector");
        assert_eq!(from_b58.serialize(), SPEC_KEY_RAW);

        let hex: String = SPEC_KEY_RAW.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            authority_key(&hex).expect("the same key as hex"),
            from_b58,
            "the two spellings are one key"
        );

        // And a second key, generated independently, so the check is a second
        // vector from a second source rather than a restatement of the first.
        assert_eq!(
            authority_key(TEST_KEY_HEX).expect("the test key as hex"),
            authority_key(TEST_KEY_B58).expect("and as base58check"),
        );

        // Whitespace from a copied-and-pasted URL is not a different key.
        assert_eq!(
            authority_key(&format!("  {SPEC_KEY_B58}  ")).unwrap(),
            from_b58
        );
    }

    #[test]
    fn an_authority_key_that_is_not_one_is_refused_by_name() {
        // A corrupted checksum, which is what a mistyped character produces.
        let mut corrupted: Vec<char> = SPEC_KEY_B58.chars().collect();
        corrupted[10] = if corrupted[10] == 'a' { 'b' } else { 'a' };
        let corrupted: String = corrupted.into_iter().collect();
        let why = authority_key(&corrupted).expect_err("a bad checksum is refused");
        assert!(why.contains("base58check"), "{why}");

        // A `[0, 0]` version prefix: the right shape, the wrong encoding
        // version, and silently accepting it would be pinning a key under
        // rules this client does not know.
        let mut wrong_prefix = vec![0u8, 0];
        wrong_prefix.extend_from_slice(&SPEC_KEY_RAW);
        let why = authority_key(&bitcoin::base58::encode_check(&wrong_prefix))
            .expect_err("a [0, 0] prefix is refused");
        assert!(why.contains("prefix"), "{why}");

        // And the shapes that are not a key at all.
        assert!(authority_key("").is_err());
        assert!(authority_key("   ").is_err());
        assert!(authority_key(&"ff".repeat(32)).is_err(), "not on the curve");
        assert!(authority_key(&"aa".repeat(31)).is_err(), "too short");
    }

    /// One certificate as a responder would send it, signed by `authority`.
    fn certificate(
        secp: &Secp256k1<All>,
        authority: &bitcoin::secp256k1::Keypair,
        server: XOnlyPublicKey,
        version: u16,
        valid_from: u32,
        not_valid_after: u32,
    ) -> Vec<u8> {
        let message = sha256(&[
            &version.to_le_bytes(),
            &valid_from.to_le_bytes(),
            &not_valid_after.to_le_bytes(),
            &server.serialize(),
        ]);
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(message), authority);

        let mut out = Vec::with_capacity(CERTIFICATE_LEN);
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&valid_from.to_le_bytes());
        out.extend_from_slice(&not_valid_after.to_le_bytes());
        out.extend_from_slice(signature.as_ref());
        out
    }

    #[test]
    fn a_certificate_is_checked_rather_than_merely_parsed() {
        let secp = Secp256k1::new();
        let authority = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[3u8; 32]).unwrap(),
        );
        let other = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[4u8; 32]).unwrap(),
        );
        let server = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[5u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        let pinned = authority.x_only_public_key().0;

        // The one that must pass, so that the four that must fail are failing
        // for their own reason rather than because nothing works.
        let good = certificate(&secp, &authority, server, 0, 1000, 2000);
        verify_certificate(&secp, &good, server, Some(pinned), 1500).expect("a valid certificate");
        verify_certificate(&secp, &good, server, Some(pinned), 1000)
            .expect("the window is inclusive");
        verify_certificate(&secp, &good, server, Some(pinned), 2000).expect("at both ends");

        for (certificate, now, expected, why) in [
            (
                certificate(&secp, &authority, server, 1, 1000, 2000),
                1500,
                "version",
                "a version this client does not understand",
            ),
            (good.clone(), 999, "not valid until", "not yet valid"),
            (good.clone(), 2001, "expired", "expired"),
            (
                certificate(&secp, &other, server, 0, 1000, 2000),
                1500,
                "pinned",
                "signed by the wrong authority",
            ),
        ] {
            let message =
                verify_certificate(&secp, &certificate, server, Some(pinned), now).expect_err(why);
            assert!(
                message.contains(expected),
                "{why} should name {expected:?}, got {message}"
            );
        }

        // And a certificate for a *different* server key, which is the
        // interesting attack: a genuine, in-date, correctly signed
        // certificate replayed in front of somebody else's static key.
        let impostor = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[6u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        assert!(
            verify_certificate(&secp, &good, impostor, Some(pinned), 1500).is_err(),
            "the signature covers the server key, so a replay in front of another one fails"
        );

        // A truncated one is a length error rather than a panic.
        assert!(verify_certificate(&secp, &good[..40], server, Some(pinned), 1500).is_err());
    }

    #[test]
    fn an_unpinned_check_gives_up_the_signature_and_keeps_everything_else() {
        // The loopback case, and the point is how *little* it gives up: the
        // version and the validity window are facts about the certificate
        // rather than claims about who signed it, so they still hold. Only
        // the identity of the far end is unknown, and on the loopback that is
        // the machine the client is already running on.
        let secp = Secp256k1::new();
        let authority = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[3u8; 32]).unwrap(),
        );
        let server = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[5u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;

        let good = certificate(&secp, &authority, server, 0, 1000, 2000);
        verify_certificate(&secp, &good, server, None, 1500).expect("in date and well formed");

        // A certificate signed by *nobody in particular* still passes, which
        // is exactly what "unverified" means and is why the gate that keeps
        // this on the loopback is the load-bearing part.
        let stranger = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[4u8; 32]).unwrap(),
        );
        let someone_elses = certificate(&secp, &stranger, server, 0, 1000, 2000);
        verify_certificate(&secp, &someone_elses, server, None, 1500)
            .expect("unpinned checks no signature, and that is the whole cost");

        // Everything that is not a signature is still refused.
        assert!(
            verify_certificate(&secp, &good, server, None, 999).is_err(),
            "the window has not opened"
        );
        assert!(
            verify_certificate(&secp, &good, server, None, 2001).is_err(),
            "the window has closed"
        );
        let wrong_version = certificate(&secp, &authority, server, 1, 1000, 2000);
        assert!(
            verify_certificate(&secp, &wrong_version, server, None, 1500).is_err(),
            "a version this client does not understand"
        );
        assert!(verify_certificate(&secp, &good[..40], server, None, 1500).is_err());
    }

    /// The oracle: this initiator against `noise_sv2`'s responder.
    ///
    /// `noise_sv2` is a dev-dependency for the reason `sha2` is a runtime
    /// one — to be a second opinion rather than to be used — and this is the
    /// test that spends it. Completing a handshake against a separately
    /// written implementation means agreeing about the protocol name hash,
    /// both `MixKey` inputs, the ECDH role order, the associated-data
    /// discipline and the final HKDF **at once**, and nothing written against
    /// this file alone can check any of them.
    ///
    /// The reverse direction, their initiator
    /// against a responder built from these primitives. That is not here, and
    /// the reason is that it would mean writing a responder this client never
    /// ships — a hundred test-only lines whose bugs would be test bugs. The
    /// direction that runs is the direction that runs in production, and it
    /// is exercised in both *transport* directions below, which is where the
    /// two cipher states could still be swapped.
    #[test]
    fn the_handshake_completes_against_an_independent_implementation() {
        let secp = Secp256k1::new();
        let authority_secret = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let authority = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &authority_secret);
        let pinned = authority.x_only_public_key().0;

        let mut responder = noise_sv2::Responder::from_authority_kp(
            &pinned.serialize(),
            &authority_secret.secret_bytes(),
            Duration::from_secs(3600),
        )
        .expect("the responder takes its own authority keypair");

        let (handshake, first) = Handshake::start().expect("entropy is available");
        let (second, mut engine) = responder
            .step_1(first)
            .expect("an independent responder answers this client's first message");
        assert_eq!(second.len(), PART_2_LEN);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("a clock after 1970")
            .as_secs() as u32;
        let (mut outgoing, mut incoming) = handshake
            .finish(&second, Some(pinned), now)
            .expect("the certificate verifies and the key schedule agrees");

        // Agreement on the *keys* is what the handshake is for, and traffic
        // is how that is demonstrated without either side exposing them.
        // Several frames each way, because one frame each way would pass with
        // the nonce counter stuck at zero.
        for round in 0u8..4 {
            let sent = vec![round; 32];
            let mut sealed = outgoing.encrypt_with_ad(&[], &sent).unwrap();
            engine
                .decrypt(&mut sealed)
                .expect("the pool decrypts what this client encrypted");
            assert_eq!(sealed, sent);

            let mut replied = vec![round ^ 0xff; 48];
            engine.encrypt(&mut replied).expect("the pool encrypts");
            let opened = incoming
                .decrypt_with_ad(&[], &replied)
                .expect("this client decrypts what the pool encrypted");
            assert_eq!(opened, vec![round ^ 0xff; 48]);
        }

        // The two states are not interchangeable, which is the mistake the
        // traffic above would hide if it only ever ran one way.
        assert!(
            incoming
                .decrypt_with_ad(&[], &outgoing.encrypt_with_ad(&[], b"x").unwrap())
                .is_err(),
            "the outgoing state's ciphertext must not open under the incoming one"
        );
    }

    #[test]
    fn a_handshake_against_a_pool_pinned_to_the_wrong_key_dies_at_the_certificate() {
        // The whole authentication story in one test. The handshake itself
        // succeeds — the ECDHs agree, the static key decrypts — and the
        // session is still refused, because the certificate is signed by an
        // authority this run did not pin. A client that connected anyway has
        // the security of plaintext V1 with extra steps.
        let secp = Secp256k1::new();
        let authority_secret = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let authority = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &authority_secret);

        let mut responder = noise_sv2::Responder::from_authority_kp(
            &authority.x_only_public_key().0.serialize(),
            &authority_secret.secret_bytes(),
            Duration::from_secs(3600),
        )
        .expect("the responder takes its own authority keypair");

        let (handshake, first) = Handshake::start().unwrap();
        let (second, _engine) = responder.step_1(first).unwrap();

        let somebody_else = bitcoin::secp256k1::Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[12u8; 32]).unwrap(),
        )
        .x_only_public_key()
        .0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let why = handshake
            .finish(&second, Some(somebody_else), now)
            .expect_err("the certificate is signed by an authority this run did not pin");
        assert!(why.contains("pinned"), "{why}");
    }

    #[test]
    fn two_handshakes_never_share_an_ephemeral_key() {
        // The one property of the entropy read worth asserting: a
        // time-derived or otherwise degenerate source would produce the same
        // 64 bytes twice within a millisecond, and the handshake would still
        // complete.
        let (_, first) = Handshake::start().unwrap();
        let (_, second) = Handshake::start().unwrap();
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 64]);
    }
}
