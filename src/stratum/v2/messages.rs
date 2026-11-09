//! The messages this client exchanges, typed both ways.
//!
//! `Value` in, typed struct out was V1's shape; here it is [`Reader`] in,
//! typed struct out, and [`Reader::finish`] is the check that the shape was
//! right — see [`codec`](super::codec) for why that matters more than it did
//! with JSON.
//!
//! **Twelve messages in and four out.** That asymmetry is the protocol's: a
//! mining client is told almost everything and asks for almost nothing. The
//! four it sends are `SetupConnection`, `OpenExtendedMiningChannel`,
//! `SubmitSharesExtended` and `UpdateChannel`, and only the third is sent
//! more than once per session.
//!
//! Everything here is **extended channels on a pooled connection**. Standard
//! channels, group channels, custom jobs and both of the other subprotocols
//! are out of scope, and a message from one of them arrives as
//! [`Incoming::Unknown`] with its two numbers rather than as an error — §3.4.1
//! requires an unrecognised message to be discarded, and logging the numbers
//! is how that gets noticed rather than silently obeyed.

use bitcoin::{BlockHash, CompactTarget, hashes::Hash};

use super::{
    codec::{Prefix, Reader, Writer},
    frame::{CHANNEL_MSG, Header, msg},
};

/// `SetupConnection.protocol`: 0 is the Mining Protocol.
const PROTOCOL_MINING: u8 = 0;

/// The only protocol version currently defined, sent as both the minimum and
/// the maximum this client supports.
const VERSION: u16 = 2;

/// `SetupConnection` flags, which are per-protocol and per-direction.
///
/// Two namespaces with overlapping bit numbers, which is why they are two
/// modules: bit 0 means `REQUIRES_STANDARD_JOBS` going out and
/// `REQUIRES_FIXED_VERSION` coming back.
pub mod flags {
    /// What a client may require of a server, §5.3.1.
    pub mod client {
        pub const REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
        pub const REQUIRES_WORK_SELECTION: u32 = 1 << 1;
        pub const REQUIRES_VERSION_ROLLING: u32 = 1 << 2;
    }

    /// What a server tells a client in `SetupConnection.Success`, §5.3.1.
    pub mod server {
        pub const REQUIRES_FIXED_VERSION: u32 = 1 << 0;
        pub const REQUIRES_EXTENDED_CHANNELS: u32 = 1 << 1;
    }
}

/// A channel as the pool opened it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedChannel {
    pub request_id: u32,
    pub channel_id: u32,
    /// The initial share target, as 32 little-endian bytes.
    pub target: [u8; 32],
    /// How many extranonce bytes belong to this client.
    pub extranonce_size: usize,
    /// The pool's own bytes, which sit in front of this client's.
    pub extranonce_prefix: Vec<u8>,
    pub group_channel_id: u32,
}

/// A `NewExtendedMiningJob`: everything about a block but its parent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedJob {
    pub channel_id: u32,
    pub job_id: u32,
    /// `None` is a **future job**: it cannot be mined until a
    /// `SetNewPrevHash` names its `job_id`. See [`job`](super::job).
    pub min_ntime: Option<u32>,
    pub version: u32,
    pub version_rolling_allowed: bool,
    /// Merkle path hashes, deepest first, in internal byte order.
    pub merkle_path: Vec<[u8; 32]>,
    /// The coinbase either side of the extranonce, stripped of BIP141 fields
    /// so that its double SHA-256 is the txid directly.
    pub coinbase_tx_prefix: Vec<u8>,
    pub coinbase_tx_suffix: Vec<u8>,
}

/// A `SetNewPrevHash`: the half of a job that only the chain can supply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewPrevHash {
    pub channel_id: u32,
    /// The one job this activates. Every other queued job dies with it.
    pub job_id: u32,
    pub prev_hash: BlockHash,
    pub min_ntime: u32,
    pub bits: CompactTarget,
}

/// Everything the pool can say to this client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
    SetupConnectionSuccess {
        used_version: u16,
        flags: u32,
    },
    SetupConnectionError {
        flags: u32,
        error_code: String,
    },
    OpenExtendedChannelSuccess(OpenedChannel),
    OpenMiningChannelError {
        request_id: u32,
        error_code: String,
    },
    NewExtendedMiningJob(ExtendedJob),
    SetNewPrevHash(NewPrevHash),
    SetTarget {
        channel_id: u32,
        maximum_target: [u8; 32],
    },
    SetExtranoncePrefix {
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    },
    /// **A batch acknowledgement, not a verdict on one share.** See
    /// [`run`](super::run)'s share ledger, which is where that difference
    /// from V1 is handled.
    SubmitSharesSuccess {
        channel_id: u32,
        last_sequence_number: u32,
        new_submits_accepted_count: u32,
        new_shares_sum: u64,
    },
    SubmitSharesError {
        channel_id: u32,
        sequence_number: u32,
        error_code: String,
    },
    Reconnect {
        new_host: String,
        new_port: u16,
    },
    UpdateChannelError {
        channel_id: u32,
        error_code: String,
    },
    /// Named rather than fatal, with both numbers, exactly as V1's is.
    Unknown {
        extension_type: u16,
        msg_type: u8,
    },
}

impl Incoming {
    /// Parse one frame's payload against the type its header names.
    ///
    /// **The `channel_msg` bit needs no special handling and that is worth
    /// saying once.** §3.2 defines the first four bytes of a channel
    /// message's payload as a `channel_id`, and every message definition in
    /// §5.3 then lists `channel_id` as its first field anyway — so the bit
    /// describes the payload rather than adding to it, and a parser that
    /// stripped four bytes on the strength of it would be one field out on
    /// every channel message.
    pub fn parse(header: Header, payload: &[u8]) -> Result<Self, String> {
        // §3.4.1: a message from an extension this client does not implement
        // is discarded, and the `channel_msg` bit is ignored in the lookup.
        // Checked first, because otherwise an extension that happened to use
        // one of the numbers below would be parsed as a core message.
        if header.extension() != 0 {
            return Ok(Self::Unknown {
                extension_type: header.extension_type,
                msg_type: header.msg_type,
            });
        }

        let mut reader = Reader::new(payload);
        let parsed = match header.msg_type {
            msg::SETUP_CONNECTION_SUCCESS => Self::SetupConnectionSuccess {
                used_version: reader.u16()?,
                flags: reader.u32()?,
            },

            msg::SETUP_CONNECTION_ERROR => Self::SetupConnectionError {
                flags: reader.u32()?,
                error_code: reader.str0_255()?.to_string(),
            },

            msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS => {
                Self::OpenExtendedChannelSuccess(OpenedChannel {
                    request_id: reader.u32()?,
                    channel_id: reader.u32()?,
                    target: reader.u256()?,
                    extranonce_size: usize::from(reader.u16()?),
                    extranonce_prefix: reader.bytes(Prefix::Bytes32)?.to_vec(),
                    group_channel_id: reader.u32()?,
                })
            }

            msg::OPEN_MINING_CHANNEL_ERROR => Self::OpenMiningChannelError {
                request_id: reader.u32()?,
                error_code: reader.str0_255()?.to_string(),
            },

            msg::NEW_EXTENDED_MINING_JOB => Self::NewExtendedMiningJob(ExtendedJob {
                channel_id: reader.u32()?,
                job_id: reader.u32()?,
                min_ntime: reader.option_u32()?,
                version: reader.u32()?,
                version_rolling_allowed: reader.bool()?,
                merkle_path: reader.seq_u256()?,
                coinbase_tx_prefix: reader.bytes(Prefix::Bytes64K)?.to_vec(),
                coinbase_tx_suffix: reader.bytes(Prefix::Bytes64K)?.to_vec(),
            }),

            msg::SET_NEW_PREV_HASH => Self::SetNewPrevHash(NewPrevHash {
                channel_id: reader.u32()?,
                job_id: reader.u32()?,
                // **No reversal.** A V1 `mining.notify`
                // prevhash needs `wire::prevhash_from_notify`; a `U256` here
                // is already the hash's internal byte order, which is what
                // `BlockHash` holds. Getting it wrong looks exactly like a
                // bad nonce.
                prev_hash: BlockHash::from_byte_array(reader.u256()?),
                min_ntime: reader.u32()?,
                bits: CompactTarget::from_consensus(reader.u32()?),
            }),

            msg::SET_TARGET => Self::SetTarget {
                channel_id: reader.u32()?,
                maximum_target: reader.u256()?,
            },

            msg::SET_EXTRANONCE_PREFIX => Self::SetExtranoncePrefix {
                channel_id: reader.u32()?,
                extranonce_prefix: reader.bytes(Prefix::Bytes32)?.to_vec(),
            },

            msg::SUBMIT_SHARES_SUCCESS => Self::SubmitSharesSuccess {
                channel_id: reader.u32()?,
                last_sequence_number: reader.u32()?,
                new_submits_accepted_count: reader.u32()?,
                new_shares_sum: reader.u64()?,
            },

            msg::SUBMIT_SHARES_ERROR => Self::SubmitSharesError {
                channel_id: reader.u32()?,
                sequence_number: reader.u32()?,
                error_code: reader.str0_255()?.to_string(),
            },

            msg::RECONNECT => Self::Reconnect {
                new_host: reader.str0_255()?.to_string(),
                new_port: reader.u16()?,
            },

            msg::UPDATE_CHANNEL_ERROR => Self::UpdateChannelError {
                channel_id: reader.u32()?,
                error_code: reader.str0_255()?.to_string(),
            },

            _ => {
                return Ok(Self::Unknown {
                    extension_type: header.extension_type,
                    msg_type: header.msg_type,
                });
            }
        };

        // The structural check. A message that parsed and left bytes behind
        // is a message this client understood as a shape it is not, and on a
        // protocol with no field names there is no other symptom.
        reader
            .finish()
            .map_err(|why| format!("message type {:#04x}: {why}", header.msg_type))?;
        Ok(parsed)
    }
}

/// One frame ready to go out: its header and its payload.
///
/// The header's `length` is filled in from the payload, so the two can never
/// disagree — which on a protocol whose framing is a length prefix is the
/// difference between a frame and a desynchronised socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Outgoing {
    fn new(extension_type: u16, msg_type: u8, payload: Vec<u8>) -> Result<Self, String> {
        let length = u32::try_from(payload.len())
            .map_err(|_| format!("a {}-byte payload does not fit a U24", payload.len()))?;
        if length > 0x00ff_ffff {
            return Err(format!(
                "a {length}-byte payload does not fit the U24 length field"
            ));
        }
        Ok(Self {
            header: Header::new(extension_type, msg_type, length),
            payload,
        })
    }
}

/// How this client describes itself, per §3.6.1.
///
/// The spec wants a vendor, a hardware version, a firmware version and a
/// device id. This is software on a general-purpose machine, so two of those
/// have no honest answer:
///
/// - **`vendor`** is the name before the slash in `MINER_POOL_AGENT`, e.g.
///   `PuntoMiner`. The spec says a client MUST set it.
/// - **`firmware`** is the part *after* the slash, e.g. `0.1`, and not the
///   whole agent string — which is what it was until Pool A's dashboard
///   printed `PuntoMiner/PuntoMiner/0.1`. A pool displays these two fields
///   joined, so repeating the vendor inside the firmware stutters. An agent
///   with no slash therefore has no firmware to report, and sends none.
/// - **`hardware_version` and `device_id` are empty.** §3.6.1 says a client
///   not configured to provide telemetry SHOULD send a zero-length
///   `device_id`, and the same reasoning covers the hardware: naming this
///   machine's CPU to a pool is telemetry nobody asked for, and the V1 client
///   does not do it either.
///
/// Honest rather than an imitation of a miner this is not, which is the same
/// rule `MINER_POOL_AGENT`'s own doc comment states for V1.
fn describe(agent: &str) -> (String, String) {
    match agent.split_once('/') {
        Some((vendor, version)) => (vendor.to_string(), version.to_string()),
        None => (agent.to_string(), String::new()),
    }
}

/// `SetupConnection`, §3.6.1.
///
/// **`REQUIRES_VERSION_ROLLING` is deliberately not set.** It means
/// *requires*, and a server that cannot offer it would then have to refuse
/// the connection — or answer `REQUIRES_FIXED_VERSION`, which would become an
/// error rather than a session that simply does not roll. This client honours
/// the per-job `version_rolling_allowed` instead and asks for nothing, which
/// is strictly more compatible and costs exactly nothing: the pool volunteers
/// the flag on every job either way.
///
/// The other two are likewise unset and for firmer reasons:
/// `REQUIRES_STANDARD_JOBS` is the opposite of what this client wants, and
/// `REQUIRES_WORK_SELECTION` would promise a `SetCustomMiningJob` it never
/// sends.
pub fn setup_connection(host: &str, port: u16, agent: &str) -> Result<Outgoing, String> {
    let (vendor, firmware) = describe(agent);
    let mut writer = Writer::new();
    writer.u8(PROTOCOL_MINING).u16(VERSION).u16(VERSION).u32(0);
    writer.str0_255(host)?;
    writer.u16(port);
    writer.str0_255(&vendor)?;
    writer.str0_255("")?;
    writer.str0_255(&firmware)?;
    writer.str0_255("")?;
    Outgoing::new(0, msg::SETUP_CONNECTION, writer.finish())
}

/// `OpenExtendedMiningChannel`, §5.3.4.
///
/// **`max_target` is a ceiling on the target, which makes it a floor under
/// the difficulty**, and that is the opposite of what V1's two difficulty
/// levers do. `d=` and `mining.suggest_difficulty` both ask a pool to come
/// *down*; this one says no more than "nothing easier than that", which
/// every harder target already satisfies. The server MUST accept it or
/// refuse the channel by name, and accepting is cheap: Pool A honours a
/// request for difficulty 1 by serving 512.
///
/// So the lever that actually lowers a difficulty is `nominal_hash_rate`.
/// §5.3.7 says a server "can use" it to set a reasonable target for the
/// channel, and it is the only input the server has for doing so. Zero
/// claims nothing and leaves the pool nothing to go on but its own default —
/// which is `MINER_POOL_HASHRATE`'s reason for existing.
pub fn open_extended_mining_channel(
    request_id: u32,
    user_identity: &str,
    nominal_hash_rate: f32,
    max_target: &[u8; 32],
    min_extranonce_size: u16,
) -> Result<Outgoing, String> {
    let mut writer = Writer::new();
    writer.u32(request_id);
    writer.str0_255(user_identity)?;
    writer.f32(nominal_hash_rate).u256(max_target);
    writer.u16(min_extranonce_size);
    Outgoing::new(0, msg::OPEN_EXTENDED_MINING_CHANNEL, writer.finish())
}

/// `SubmitSharesExtended`, §5.3.12.
///
/// Two fields are the opposite of their V1 counterparts and both are traps:
///
/// - **`version` is the full nVersion field**, not the rolled bits. V1's
///   sixth `mining.submit` parameter is the masked bits only, and the whole
///   `(announced & !mask) | submitted` versus `announced ^ submitted`
///   ambiguity that made every regtest share fail comes from that. Here the
///   pool is told the header outright and there is nothing to reconstruct.
/// - **`extranonce` is exactly the client's own bytes**, not the prefix and
///   not prefix-plus-extranonce. The pool reassembles
///   `prefix ‖ extranonce_prefix ‖ extranonce ‖ suffix` itself, so sending
///   the prefix back would give it a coinbase with the prefix in twice.
pub fn submit_shares_extended(
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    nonce: u32,
    ntime: u32,
    version: u32,
    extranonce: &[u8],
) -> Result<Outgoing, String> {
    let mut writer = Writer::new();
    writer
        .u32(channel_id)
        .u32(sequence_number)
        .u32(job_id)
        .u32(nonce)
        .u32(ntime)
        .u32(version);
    writer.bytes(Prefix::Bytes32, extranonce)?;
    Outgoing::new(CHANNEL_MSG, msg::SUBMIT_SHARES_EXTENDED, writer.finish())
}

/// `UpdateChannel`, §5.3.7: this client's hash rate and the target it wants.
///
/// Sent when the measured rate has moved enough to be worth telling the pool
/// about. A server that finds it invalid answers `UpdateChannel.Error`; one
/// that accepts it either says nothing or answers `SetTarget`, so nothing
/// waits for a reply.
///
/// **`maximum_target` must be the ceiling this client wants and never the
/// target the pool is currently serving.** The spec is explicit that a
/// value smaller than the channel's current one is a request the server
/// "must reflect" — it can only ever ask for *harder* — so echoing the
/// pool's own target back turns a hash-rate report into a promise never to
/// accept anything easier again. The caller passes the same value the
/// channel was opened with, which is the only one that means what it says.
pub fn update_channel(
    channel_id: u32,
    nominal_hash_rate: f32,
    maximum_target: &[u8; 32],
) -> Result<Outgoing, String> {
    let mut writer = Writer::new();
    writer
        .u32(channel_id)
        .f32(nominal_hash_rate)
        .u256(maximum_target);
    Outgoing::new(CHANNEL_MSG, msg::UPDATE_CHANNEL, writer.finish())
}

#[cfg(test)]
mod tests {
    use binary_sv2::{B032, B064K, Seq0255, Str0255, Sv2Option, U256, from_bytes, to_bytes};

    use super::*;

    /// Serialize one of SRI's own structs into the bytes it thinks the
    /// message is.
    ///
    /// **This is the second opinion on every message encoding.** `mining_sv2`
    /// and
    /// `common_messages_sv2` are independently written definitions of the
    /// same spec tables, so a field in the wrong order, of the wrong width,
    /// or missing entirely fails here — which is the entire risk of this
    /// file and is invisible to any test that round-trips this module
    /// against itself.
    ///
    /// It is not a substitute for a capture and the difference is worth
    /// stating: this checks the *encoding*, and a capture from a running pool
    /// also checks that a real server sends what the spec says. The committed
    /// capture in `tests/fixtures/` is that other check.
    fn sri_bytes<T>(message: T) -> Vec<u8>
    where
        T: binary_sv2::Serialize + binary_sv2::GetSize,
    {
        to_bytes(message).expect("SRI serializes its own struct")
    }

    fn str0255(text: &str) -> Str0255<'_> {
        Str0255::try_from(text.as_bytes()).expect("a string under 256 bytes")
    }

    #[test]
    fn a_new_extended_mining_job_parses_what_an_independent_encoder_produced() {
        // A future job — `min_ntime` empty — because that is the shape with
        // the most that can go wrong: an `OPTION` read as a `U32` would
        // desynchronise every field after it and still parse.
        let mut first = [0x11u8; 32];
        let mut second = [0x22u8; 32];
        let mut prefix = vec![0xaau8; 40];
        let mut suffix = vec![0xccu8; 17];

        let bytes = sri_bytes(mining_sv2::NewExtendedMiningJob {
            channel_id: 7,
            job_id: 9,
            ntime_start: Sv2Option::new(None),
            version: 0x2000_0000,
            version_rolling_allowed: true,
            merkle_path: Seq0255::new(vec![U256::from(&mut first), U256::from(&mut second)])
                .unwrap(),
            coinbase_tx_prefix: B064K::try_from(prefix.as_mut_slice()).unwrap(),
            coinbase_tx_suffix: B064K::try_from(suffix.as_mut_slice()).unwrap(),
        });

        let header = Header::new(
            CHANNEL_MSG,
            msg::NEW_EXTENDED_MINING_JOB,
            bytes.len() as u32,
        );
        let Incoming::NewExtendedMiningJob(job) = Incoming::parse(header, &bytes).unwrap() else {
            panic!("the header names an extended job");
        };

        assert_eq!(job.channel_id, 7);
        assert_eq!(job.job_id, 9);
        assert_eq!(job.min_ntime, None, "an empty min_ntime is a future job");
        assert_eq!(job.version, 0x2000_0000);
        assert!(job.version_rolling_allowed);
        assert_eq!(job.merkle_path, vec![[0x11u8; 32], [0x22u8; 32]]);
        assert_eq!(job.coinbase_tx_prefix, vec![0xaau8; 40]);
        assert_eq!(job.coinbase_tx_suffix, vec![0xccu8; 17]);

        // And the activated form, whose `min_ntime` is present. The two
        // differ by five bytes in the middle of the message.
        let activated = sri_bytes(mining_sv2::NewExtendedMiningJob {
            channel_id: 7,
            job_id: 10,
            ntime_start: Sv2Option::new(Some(1_700_000_000)),
            version: 0x2000_0000,
            version_rolling_allowed: false,
            merkle_path: Seq0255::new(vec![]).unwrap(),
            coinbase_tx_prefix: B064K::try_from(prefix.as_mut_slice()).unwrap(),
            coinbase_tx_suffix: B064K::try_from(suffix.as_mut_slice()).unwrap(),
        });
        assert_eq!(activated.len(), bytes.len() + 4 - 64);

        let header = Header::new(
            CHANNEL_MSG,
            msg::NEW_EXTENDED_MINING_JOB,
            activated.len() as u32,
        );
        let Incoming::NewExtendedMiningJob(job) = Incoming::parse(header, &activated).unwrap()
        else {
            panic!("the header names an extended job");
        };
        assert_eq!(job.min_ntime, Some(1_700_000_000));
        assert!(!job.version_rolling_allowed);
        assert!(job.merkle_path.is_empty(), "a coinbase-only block");
    }

    #[test]
    fn a_prev_hash_arrives_in_internal_order_and_is_not_reversed() {
        // The one place a V1 habit would be silently wrong. The
        // bytes below are a real mainnet block hash in the internal order a
        // `U256` carries it, and `BlockHash`'s own `Display` is the reversed
        // form — so if this ever started reversing, the assertion on the
        // string would be the thing that noticed.
        let tip = "0000000000000000000228527f93c9c265b6d5135a692b4a90d927b998ccd6c1";
        let expected: BlockHash = tip.parse().expect("a block hash");
        let mut internal = expected.to_byte_array();

        let bytes = sri_bytes(mining_sv2::SetNewPrevHash {
            channel_id: 3,
            job_id: 9,
            prev_hash: U256::from(&mut internal),
            ntime_start: 1_700_000_000,
            nbits: 0x1702_355e,
        });

        let header = Header::new(CHANNEL_MSG, msg::SET_NEW_PREV_HASH, bytes.len() as u32);
        let Incoming::SetNewPrevHash(prev) = Incoming::parse(header, &bytes).unwrap() else {
            panic!("the header names a prevhash");
        };
        assert_eq!(prev.channel_id, 3);
        assert_eq!(prev.job_id, 9);
        assert_eq!(prev.prev_hash, expected);
        assert_eq!(prev.prev_hash.to_string(), tip);
        assert_eq!(prev.min_ntime, 1_700_000_000);
        assert_eq!(prev.bits, CompactTarget::from_consensus(0x1702_355e));
    }

    #[test]
    fn every_message_the_pool_sends_parses_from_an_independent_encoding() {
        let mut target = [0u8; 32];
        target[28] = 0xff;
        target[29] = 0xff;
        let mut prefix = vec![0xdeu8, 0xad, 0xbe, 0xef];

        let cases: Vec<(u8, Vec<u8>, Incoming)> = vec![
            (
                msg::SETUP_CONNECTION_SUCCESS,
                sri_bytes(common_messages_sv2::SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0b10,
                }),
                Incoming::SetupConnectionSuccess {
                    used_version: 2,
                    flags: 0b10,
                },
            ),
            (
                msg::SETUP_CONNECTION_ERROR,
                sri_bytes(common_messages_sv2::SetupConnectionError {
                    flags: 0b100,
                    error_code: str0255("unsupported-feature-flags"),
                }),
                Incoming::SetupConnectionError {
                    flags: 0b100,
                    error_code: "unsupported-feature-flags".into(),
                },
            ),
            (
                msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                sri_bytes(mining_sv2::OpenExtendedMiningChannelSuccess {
                    request_id: 1,
                    channel_id: 42,
                    target: U256::from(&mut target),
                    extranonce_size: 8,
                    extranonce_prefix: B032::try_from(prefix.as_mut_slice()).unwrap(),
                    group_channel_id: 0,
                }),
                Incoming::OpenExtendedChannelSuccess(OpenedChannel {
                    request_id: 1,
                    channel_id: 42,
                    target,
                    extranonce_size: 8,
                    extranonce_prefix: vec![0xde, 0xad, 0xbe, 0xef],
                    group_channel_id: 0,
                }),
            ),
            (
                msg::OPEN_MINING_CHANNEL_ERROR,
                sri_bytes(mining_sv2::OpenMiningChannelError {
                    request_id: 1,
                    error_code: str0255("max-target-out-of-range"),
                }),
                Incoming::OpenMiningChannelError {
                    request_id: 1,
                    error_code: "max-target-out-of-range".into(),
                },
            ),
            (
                msg::SET_TARGET,
                sri_bytes(mining_sv2::SetTarget {
                    channel_id: 42,
                    target: U256::from(&mut target),
                }),
                Incoming::SetTarget {
                    channel_id: 42,
                    maximum_target: target,
                },
            ),
            (
                msg::SET_EXTRANONCE_PREFIX,
                sri_bytes(mining_sv2::SetExtranoncePrefix {
                    channel_id: 42,
                    extranonce_prefix: B032::try_from(prefix.as_mut_slice()).unwrap(),
                }),
                Incoming::SetExtranoncePrefix {
                    channel_id: 42,
                    extranonce_prefix: vec![0xde, 0xad, 0xbe, 0xef],
                },
            ),
            (
                msg::SUBMIT_SHARES_SUCCESS,
                sri_bytes(mining_sv2::SubmitSharesSuccess {
                    channel_id: 42,
                    last_sequence_number: 100,
                    new_submits_accepted_count: 10,
                    new_shares_sum: 5_120,
                }),
                Incoming::SubmitSharesSuccess {
                    channel_id: 42,
                    last_sequence_number: 100,
                    new_submits_accepted_count: 10,
                    new_shares_sum: 5_120,
                },
            ),
            (
                msg::SUBMIT_SHARES_ERROR,
                sri_bytes(mining_sv2::SubmitSharesError {
                    channel_id: 42,
                    sequence_number: 101,
                    error_code: str0255("difficulty-too-low"),
                }),
                Incoming::SubmitSharesError {
                    channel_id: 42,
                    sequence_number: 101,
                    error_code: "difficulty-too-low".into(),
                },
            ),
            (
                msg::UPDATE_CHANNEL_ERROR,
                sri_bytes(mining_sv2::UpdateChannelError {
                    channel_id: 42,
                    error_code: str0255("max-target-out-of-range"),
                }),
                Incoming::UpdateChannelError {
                    channel_id: 42,
                    error_code: "max-target-out-of-range".into(),
                },
            ),
        ];

        for (msg_type, bytes, expected) in cases {
            let header = Header::new(CHANNEL_MSG, msg_type, bytes.len() as u32);
            let parsed = Incoming::parse(header, &bytes)
                .unwrap_or_else(|why| panic!("message {msg_type:#04x}: {why}"));
            assert_eq!(parsed, expected, "message {msg_type:#04x}");
        }
    }

    #[test]
    fn a_reconnect_parses_and_its_two_empty_forms_mean_the_present_endpoint() {
        // §3.6.5: an empty host is the present host, a port of 0 the present
        // port. Both together is a pool asking for the handshake to be run
        // again against itself, which is a legitimate thing to be told.
        for (host, port) in [
            ("", 0u16),
            ("", 3350),
            ("pool.example", 0),
            ("pool.example", 3350),
        ] {
            let bytes = sri_bytes(common_messages_sv2::Reconnect {
                new_host: str0255(host),
                new_port: port,
            });
            let header = Header::new(0, msg::RECONNECT, bytes.len() as u32);
            assert_eq!(
                Incoming::parse(header, &bytes).unwrap(),
                Incoming::Reconnect {
                    new_host: host.into(),
                    new_port: port,
                },
            );
        }
    }

    #[test]
    fn what_this_client_sends_is_byte_identical_to_an_independent_encoder() {
        // The other direction, and the more valuable one: these bytes go to a
        // stranger's server, and a field of the wrong width here is a session
        // that fails at the pool with no diagnosis available from this end.
        let mut target = [0x7fu8; 32];

        let mine = setup_connection("pool.example.com", 3350, "PuntoMiner/0.1").unwrap();
        let theirs = sri_bytes(common_messages_sv2::SetupConnection {
            protocol: common_messages_sv2::Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host: str0255("pool.example.com"),
            endpoint_port: 3350,
            vendor: str0255("PuntoMiner"),
            hardware_version: str0255(""),
            firmware: str0255("0.1"),
            device_id: str0255(""),
        });
        assert_eq!(mine.payload, theirs, "SetupConnection");
        assert_eq!(mine.header.msg_type, msg::SETUP_CONNECTION);
        assert!(
            !mine.header.is_channel_msg(),
            "a connection is not a channel"
        );

        let mine =
            open_extended_mining_channel(1, "bc1qexample.puntominer", 430e6, &target, 8).unwrap();
        let theirs = sri_bytes(mining_sv2::OpenExtendedMiningChannel {
            request_id: 1,
            user_identity: str0255("bc1qexample.puntominer"),
            nominal_hash_rate: 430e6,
            max_target: U256::from(&mut target),
            min_extranonce_size: 8,
        });
        assert_eq!(mine.payload, theirs, "OpenExtendedMiningChannel");

        let mut extranonce = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mine = submit_shares_extended(
            42,
            7,
            9,
            0x0122_0aa8,
            1_700_000_000,
            0x2000_0004,
            &extranonce,
        )
        .unwrap();
        let theirs = sri_bytes(mining_sv2::SubmitSharesExtended {
            channel_id: 42,
            sequence_number: 7,
            job_id: 9,
            nonce: 0x0122_0aa8,
            ntime: 1_700_000_000,
            version: 0x2000_0004,
            extranonce: B032::try_from(extranonce.as_mut_slice()).unwrap(),
        });
        assert_eq!(mine.payload, theirs, "SubmitSharesExtended");
        assert!(
            mine.header.is_channel_msg(),
            "a share belongs to a channel, so the header says so"
        );

        let mine = update_channel(42, 430e6, &target).unwrap();
        let theirs = sri_bytes(mining_sv2::UpdateChannel {
            channel_id: 42,
            nominal_hash_rate: 430e6,
            max_target: U256::from(&mut target),
        });
        assert_eq!(mine.payload, theirs, "UpdateChannel");
    }

    #[test]
    fn a_share_this_client_builds_decodes_back_into_the_fields_it_meant() {
        // The same check from the far end: an independent *decoder* reading
        // this client's bytes, which is what the pool will do.
        let mine = submit_shares_extended(
            42,
            7,
            9,
            0x0122_0aa8,
            1_700_000_000,
            0x2000_0004,
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap();

        let mut bytes = mine.payload.clone();
        let theirs: mining_sv2::SubmitSharesExtended =
            from_bytes(bytes.as_mut_slice()).expect("SRI decodes this client's share");

        assert_eq!(theirs.channel_id, 42);
        assert_eq!(theirs.sequence_number, 7);
        assert_eq!(theirs.job_id, 9);
        assert_eq!(theirs.nonce, 0x0122_0aa8);
        assert_eq!(theirs.ntime, 1_700_000_000);
        assert_eq!(
            theirs.version, 0x2000_0004,
            "the full nVersion, not the rolled bits"
        );
        assert_eq!(theirs.extranonce.as_ref(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_message_from_an_extension_this_client_does_not_know_is_discarded() {
        // §3.4.1, and the reason the check comes before the type match: an
        // extension is free to use `0x1f` for something that is not an
        // extended job, and parsing it as one would be obeying a message
        // meant for somebody else.
        let header = Header::new(0x0abc, msg::NEW_EXTENDED_MINING_JOB, 0);
        assert_eq!(
            Incoming::parse(header, &[]).unwrap(),
            Incoming::Unknown {
                extension_type: 0x0abc,
                msg_type: msg::NEW_EXTENDED_MINING_JOB,
            },
        );

        // The `channel_msg` bit does not make it a different extension.
        let header = Header::new(0x8abc, msg::NEW_EXTENDED_MINING_JOB, 0);
        assert!(matches!(
            Incoming::parse(header, &[]).unwrap(),
            Incoming::Unknown { .. }
        ));

        // And a core message type this client does not implement is the same
        // answer rather than an error — `0x1e` is Reserved, `0x11` is the
        // standard-channel success this client never asked for.
        for msg_type in [
            msg::RESERVED,
            msg::OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            0x99,
        ] {
            assert!(matches!(
                Incoming::parse(Header::new(CHANNEL_MSG, msg_type, 0), &[]).unwrap(),
                Incoming::Unknown { .. }
            ));
        }
    }

    #[test]
    fn a_message_with_bytes_left_over_is_refused_rather_than_half_understood() {
        // `finish`, doing the job field names did in V1. Ten trailing bytes
        // on a `SetTarget` is a pool speaking a shape this client does not
        // know, and taking the first 36 bytes as a `SetTarget` anyway is how
        // a client ends up mining to a target nobody sent.
        let mut bytes = sri_bytes(mining_sv2::SetTarget {
            channel_id: 42,
            target: U256::from(&mut [0x7fu8; 32]),
        });
        assert_eq!(bytes.len(), 36);
        bytes.extend_from_slice(&[0u8; 10]);

        let header = Header::new(CHANNEL_MSG, msg::SET_TARGET, bytes.len() as u32);
        let why = Incoming::parse(header, &bytes).expect_err("ten bytes are unaccounted for");
        assert!(why.contains("left over"), "{why}");
        assert!(why.contains("0x21"), "the message type is named: {why}");

        // And truncation is refused for the same reason from the other side.
        assert!(Incoming::parse(header, &bytes[..20]).is_err());
    }

    #[test]
    fn the_agent_string_is_split_into_the_two_fields_that_have_an_honest_answer() {
        // **The vendor must not appear in the firmware too.** A pool
        // displays the two joined, so returning the whole agent string here
        // is what made Pool A's dashboard read
        // `PuntoMiner/PuntoMiner/0.1`.
        assert_eq!(
            describe("PuntoMiner/0.1"),
            ("PuntoMiner".into(), "0.1".into())
        );
        // A name with no version has no firmware to report. Empty is what
        // §3.6.1 asks of a field with no honest answer, and an empty vendor
        // — the one the spec says MUST be set — is never the half dropped.
        assert_eq!(describe("puntominer"), ("puntominer".into(), String::new()));
        // Only the first slash splits, so a version that contains one
        // survives intact.
        assert_eq!(
            describe("PuntoMiner/0.1/rc2"),
            ("PuntoMiner".into(), "0.1/rc2".into())
        );
        assert_eq!(describe(""), (String::new(), String::new()));
    }

    #[test]
    fn the_setup_flags_are_the_bits_the_spec_numbers_and_none_are_set() {
        // Two namespaces, overlapping bit numbers, which is the whole reason
        // they are separate modules.
        assert_eq!(flags::client::REQUIRES_STANDARD_JOBS, 1);
        assert_eq!(flags::client::REQUIRES_WORK_SELECTION, 2);
        assert_eq!(flags::client::REQUIRES_VERSION_ROLLING, 4);
        assert_eq!(flags::server::REQUIRES_FIXED_VERSION, 1);
        assert_eq!(flags::server::REQUIRES_EXTENDED_CHANNELS, 2);

        // And the frame this client actually sends asks for none of them —
        // `REQUIRES_VERSION_ROLLING` especially, which would turn a pool that
        // cannot roll into an error instead of a session that does not.
        let setup = setup_connection("host", 1, "a/1").unwrap();
        let mut reader = Reader::new(&setup.payload);
        assert_eq!(reader.u8().unwrap(), PROTOCOL_MINING);
        assert_eq!(reader.u16().unwrap(), 2, "min_version");
        assert_eq!(reader.u16().unwrap(), 2, "max_version");
        assert_eq!(reader.u32().unwrap(), 0, "no flags, and that is deliberate");
    }
}
