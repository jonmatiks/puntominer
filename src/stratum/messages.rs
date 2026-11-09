//! The JSON shapes a pool sends, and the one reply worth a type of its own.
//!
//! Parsed by hand out of `serde_json::Value`, the way `template.rs` parses
//! `getblocktemplate`: field names checked rather than assumed, and a frame
//! that does not have what it claims named as such rather than defaulted past.
//! Nothing here derives `Deserialize`, and that is a decision — Stratum V1 has
//! no schema, three pools measured in development disagree about
//! the shape of the *same* reply, and a derive would have to be written against
//! one of them.
//!
//! The three disagreements that this file exists to survive, each with a test
//! below:
//!
//! 1. **The subscription list at `result[0]` is not read.** Pool A sends two
//!    entries and Pool B sends one. A client that walks that list works
//!    against one pool in three; [`Subscribed`] reads positions 1 and 2 and
//!    never position 0.
//! 2. **The subscription id is not the `extranonce1`.** Both captures happen to
//!    reuse one as the other, which is exactly why neither can be the test.
//! 3. **A refusal is `result: false` as often as it is a populated `error`.** A
//!    failed `mining.authorize` on Pool A is
//!    `{"id":2,"result":false,"error":null}`. Reading only `error` reads that
//!    as success and then mines for a pool that is not crediting anything.

use bitcoin::{BlockHash, CompactTarget};
use serde_json::Value;

use super::wire;

/// The widest `extranonce2` this client will accept from a pool.
///
/// Not a protocol limit — there isn't one — but a sanity bound. The field is
/// spliced into the coinbase, whose scriptSig consensus caps at 100 bytes, so
/// anything near this is a pool that has lost track of what it is asking for.
/// All three measured pools negotiate 8.
const EXTRANONCE2_MAX: usize = 32;

/// What `mining.subscribe` answered, reduced to the two fields that matter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subscribed {
    /// The pool's half of the extranonce, spliced into every coinbase between
    /// `coinb1` and this client's own `extranonce2`.
    pub extranonce1: Vec<u8>,
    /// How many bytes of `extranonce2` the pool left room for. The width is the
    /// protocol's; the interpretation is this client's.
    pub extranonce2_size: usize,
}

impl Subscribed {
    /// Read a subscribe reply's `result`.
    ///
    /// **Positions 1 and 2 only.** Position 0 is the subscription list, whose
    /// length varies by pool and whose contents this client has no use for: it
    /// subscribes to whatever the pool sends and reads the `method` of each
    /// frame as it arrives. Treating the id inside it as the `extranonce1`
    /// happens to work against both captured pools and is wrong.
    pub fn parse(result: &Value) -> Result<Self, String> {
        let result = result
            .as_array()
            .ok_or("a mining.subscribe reply's result is an array")?;
        if result.len() < 3 {
            return Err(format!(
                "a mining.subscribe reply has three entries; this one has {}",
                result.len()
            ));
        }

        let extranonce1 = result[1]
            .as_str()
            .ok_or("a mining.subscribe reply's extranonce1 is a hex string")?;
        let extranonce1 = wire::bytes_from_hex(extranonce1)
            .map_err(|why| format!("a mining.subscribe extranonce1 {why}"))?;

        let extranonce2_size = result[2]
            .as_u64()
            .ok_or("a mining.subscribe reply's extranonce2_size is a number")?
            as usize;
        if extranonce2_size == 0 || extranonce2_size > EXTRANONCE2_MAX {
            return Err(format!(
                "a mining.subscribe reply left {extranonce2_size} bytes of extranonce2, \
                 which is not between 1 and {EXTRANONCE2_MAX}"
            ));
        }

        Ok(Self {
            extranonce1,
            extranonce2_size,
        })
    }
}

/// One `mining.notify`: everything needed to build a header except the parts
/// this client supplies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notify {
    /// The pool's handle for this work, echoed back in every `mining.submit`.
    /// Pool-global rather than per-connection — two Pool A sessions saw the
    /// same id — so it identifies work, not a conversation.
    pub job_id: String,
    pub prevhash: BlockHash,
    /// The coinbase up to the extranonce.
    pub coinb1: Vec<u8>,
    /// The coinbase after it.
    pub coinb2: Vec<u8>,
    /// The path from the coinbase leaf to the merkle root, in internal byte
    /// order. Everything else in the tree is the pool's and never moves.
    pub branch: Vec<[u8; 32]>,
    pub version: u32,
    pub bits: CompactTarget,
    pub ntime: u32,
    /// Whether every job before this one is dead. `false` means the previous
    /// jobs are still worth shares; `true` means the chain moved.
    pub clean_jobs: bool,
}

impl Notify {
    /// Read a `mining.notify`'s nine positional parameters.
    ///
    /// Positional because that is what the protocol is — there are no names on
    /// the wire — so the only defence against reading `ntime` as `nbits` is
    /// that both go through [`wire::be_u32_from_hex`] and a header built from
    /// the pair swapped would be rejected by the pool. Which is to say: the
    /// defence is the Pool A capture, asserted in `job.rs`.
    pub fn parse(params: &[Value]) -> Result<Self, String> {
        if params.len() < 9 {
            return Err(format!(
                "a mining.notify has nine parameters; this one has {}",
                params.len()
            ));
        }

        let text = |index: usize, name: &str| -> Result<&str, String> {
            params[index]
                .as_str()
                .ok_or_else(|| format!("a mining.notify's {name} is a string"))
        };

        let branch = params[4]
            .as_array()
            .ok_or("a mining.notify's merkle_branch is an array")?
            .iter()
            .map(|entry| {
                let entry = entry
                    .as_str()
                    .ok_or("a mining.notify's merkle_branch holds hex strings")?;
                wire::branch_entry(entry)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            job_id: text(0, "job_id")?.to_string(),
            prevhash: wire::prevhash_from_notify(text(1, "prevhash")?)?,
            coinb1: wire::bytes_from_hex(text(2, "coinb1")?)
                .map_err(|why| format!("a mining.notify's coinb1 {why}"))?,
            coinb2: wire::bytes_from_hex(text(3, "coinb2")?)
                .map_err(|why| format!("a mining.notify's coinb2 {why}"))?,
            branch,
            version: wire::be_u32_from_hex(text(5, "version")?)
                .map_err(|why| format!("a mining.notify's version: {why}"))?,
            bits: CompactTarget::from_consensus(
                wire::be_u32_from_hex(text(6, "nbits")?)
                    .map_err(|why| format!("a mining.notify's nbits: {why}"))?,
            ),
            ntime: wire::be_u32_from_hex(text(7, "ntime")?)
                .map_err(|why| format!("a mining.notify's ntime: {why}"))?,
            clean_jobs: params[8]
                .as_bool()
                .ok_or("a mining.notify's clean_jobs is a boolean")?,
        })
    }
}

/// A frame arriving from the pool.
///
/// `Unknown` is not a failure. Pools send frames this client has no use for —
/// `client.show_message`, a vendor extension — and a session that died on the
/// first of them would be a fragile client rather than a strict one. It carries
/// the method name so the run can say what it ignored.
#[derive(Clone, Debug)]
pub enum Incoming {
    Notify(Notify),
    /// The share difficulty, as a scalar. Not a target: the conversion is the
    /// job's, in `job.rs`, so that a `set_difficulty` between a notify and its
    /// share cannot retroactively change what that share was worth.
    SetDifficulty(f64),
    /// A new `extranonce1` mid-session, which invalidates every job in flight.
    SetExtranonce {
        extranonce1: Vec<u8>,
        /// Sent by some pools and omitted by others, in which case the
        /// negotiated width stands.
        extranonce2_size: Option<usize>,
    },
    /// BIP310's `mining.set_version_mask`: the bits the pool will let this
    /// client roll from now on, as the pool sent them. The clamp to BIP320 is
    /// [`conn::clamp_mask`](super::conn::clamp_mask)'s, the same one the
    /// `mining.configure` answer goes through.
    SetVersionMask(u32),
    /// `mining.ping`, which expects a `pong` under the same id.
    ///
    /// The id is kept as it arrived, because it is the pool's and goes back
    /// unchanged. A null one is a notification and is not answered.
    Ping(Value),
    /// `client.get_version`, which expects this client's name under the same
    /// id.
    GetVersion(Value),
    /// `client.reconnect`. The parameters — conventionally a host, a port and
    /// a wait — are kept for the log and **never followed**: V1 has no
    /// authentication, and a redirect would move the run to a server nobody
    /// named.
    Reconnect(Vec<Value>),
    /// An answer to something this client asked. Both halves are kept raw: a
    /// refusal is `result: false` as often as it is a populated `error`, and
    /// which one a pool uses is not knowable here.
    ///
    /// **The id is optional, because a reply's id can be `null`.** Pool B
    /// answers a frame sent with a null id by echoing that null back, measured
    /// on 18 September 2026 against a local instance; Pool A coerces the
    /// same null to `0` and answers under that. A client that required a number
    /// here works against one of those pools and dies on the first frame from
    /// the other — which is exactly what happened, and is why the client is
    /// tested against a second, local pool.
    Reply {
        id: Option<u64>,
        result: Value,
        error: Value,
    },
    /// A method this client does not implement, named rather than acted on.
    Unknown(String),
}

impl Incoming {
    /// Parse one line off the wire.
    ///
    /// A frame with a `method` is the pool calling this client; anything else
    /// is a reply. The `id` does not decide it — a notification carries
    /// `"id":null` on some pools and no `id` at all on others, while
    /// `mining.notify` carries both an id and a method.
    pub fn parse(line: &str) -> Result<Self, String> {
        let frame: Value =
            serde_json::from_str(line).map_err(|why| format!("a pool frame is not JSON: {why}"))?;

        let params = frame
            .get("params")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        match frame.get("method").and_then(Value::as_str) {
            Some("mining.notify") => Ok(Self::Notify(Notify::parse(params)?)),

            Some("mining.set_difficulty") => {
                let difficulty = params
                    .first()
                    .and_then(Value::as_f64)
                    .ok_or("a mining.set_difficulty carries one number")?;
                if !difficulty.is_finite() || difficulty <= 0.0 {
                    return Err(format!(
                        "a share difficulty of {difficulty} is not a difficulty"
                    ));
                }
                Ok(Self::SetDifficulty(difficulty))
            }

            Some("mining.set_extranonce") => {
                let extranonce1 = params
                    .first()
                    .and_then(Value::as_str)
                    .ok_or("a mining.set_extranonce carries a hex extranonce1")?;
                let extranonce2_size = params.get(1).and_then(Value::as_u64).map(|n| n as usize);
                // The subscribe reply's bound, because the new width replaces
                // the one that reply was held to.
                if let Some(size) =
                    extranonce2_size.filter(|&size| size == 0 || size > EXTRANONCE2_MAX)
                {
                    return Err(format!(
                        "a mining.set_extranonce left {size} bytes of extranonce2, which is \
                         not between 1 and {EXTRANONCE2_MAX}"
                    ));
                }
                Ok(Self::SetExtranonce {
                    extranonce1: wire::bytes_from_hex(extranonce1)
                        .map_err(|why| format!("a mining.set_extranonce extranonce1 {why}"))?,
                    extranonce2_size,
                })
            }

            Some("mining.set_version_mask") => {
                let mask = params
                    .first()
                    .and_then(Value::as_str)
                    .ok_or("a mining.set_version_mask carries one hex mask")?;
                Ok(Self::SetVersionMask(wire::be_u32_from_hex(mask).map_err(
                    |why| format!("a mining.set_version_mask's mask: {why}"),
                )?))
            }

            Some("mining.ping") => Ok(Self::Ping(id(&frame))),
            Some("client.get_version") => Ok(Self::GetVersion(id(&frame))),
            Some("client.reconnect") => Ok(Self::Reconnect(params.to_vec())),

            Some(other) => Ok(Self::Unknown(other.to_string())),

            None => {
                // The `id` key must be there; its *value* may be null. A
                // frame with neither a method nor an id is not a JSON-RPC frame
                // at all, and calling it a reply to nothing would hide a pool
                // sending something this client has no model for.
                let id = frame
                    .get("id")
                    .ok_or("a pool frame is either a method call or a reply with an id")?;
                if !id.is_null() && id.as_u64().is_none() {
                    return Err(format!("a pool reply's id is a number or null, not {id}"));
                }
                Ok(Self::Reply {
                    id: id.as_u64(),
                    result: frame.get("result").cloned().unwrap_or(Value::Null),
                    error: frame.get("error").cloned().unwrap_or(Value::Null),
                })
            }
        }
    }
}

/// A frame's `id`, or null when it has none.
fn id(frame: &Value) -> Value {
    frame.get("id").cloned().unwrap_or(Value::Null)
}

/// Whether a reply says no, in either of the two ways a pool says it.
///
/// Returns the reason, so a caller can put the pool's own words in the log
/// rather than "the pool refused". The `error` member is a JSON-RPC triple
/// `[code, message, data]` on the pools that populate it and `null` on the
/// pools that do not, and `result: false` is the other half of the same answer.
///
/// Both are checked because neither is reliable alone. Reading only `error`
/// treats a refused `mining.authorize` on Pool A as success, which is the
/// worst available outcome: a client that mines happily for a pool crediting
/// nothing.
///
/// This answers "did the pool say no", not "did the pool say yes". A `null`
/// result is deliberately not a failure — it is how a pool acknowledges a
/// request it has no answer for, and `mining.suggest_difficulty` is exactly
/// that. A caller that needs an affirmative checks for `result: true` itself,
/// which is what the handshake does for `mining.authorize`.
pub fn failure(result: &Value, error: &Value) -> Option<String> {
    if !error.is_null() {
        // `[code, message, data]` by convention, a bare string or object by
        // nobody's, so the message is pulled out when it is there and the whole
        // thing is quoted when it is not.
        let message = error
            .get(1)
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| error.to_string());
        return Some(message);
    }
    if result == &Value::Bool(false) {
        return Some("the pool answered false with no error".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{super::fixture, *};

    fn subscribe_reply(capture: &str) -> Subscribed {
        let frames = fixture::load(capture);
        let reply = frames
            .iter()
            .find(|frame| !frame.is_send() && frame.json["id"] == 1)
            .expect("each capture opens with a subscribe reply");
        let Incoming::Reply { result, error, .. } =
            Incoming::parse(&reply.line).expect("a subscribe reply parses")
        else {
            panic!("a frame with no method is a reply");
        };
        assert_eq!(failure(&result, &error), None, "both pools subscribed us");
        Subscribed::parse(&result).expect("a subscribe reply is readable")
    }

    #[test]
    fn both_captured_pools_subscribe_to_the_same_two_fields() {
        // Two pools whose subscription lists are different lengths, read the
        // same way and giving the same shape of answer.
        assert_eq!(
            subscribe_reply(fixture::POOL_A),
            Subscribed {
                extranonce1: vec![0x10, 0x08, 0x6b, 0xd1],
                extranonce2_size: 8,
            }
        );
        assert_eq!(
            subscribe_reply(fixture::POOL_B),
            Subscribed {
                extranonce1: vec![0x19, 0xae, 0xec, 0xb4],
                extranonce2_size: 8,
            }
        );
    }

    #[test]
    fn the_subscription_list_is_never_read() {
        // The rule stated as something that can fail. Position 0 is replaced
        // with each of the things a pool might plausibly put there — including
        // nothing at all — and the answer must not move. A client that walked
        // that list fails every one of these.
        let expected = Subscribed {
            extranonce1: vec![0xde, 0xad, 0xbe, 0xef],
            extranonce2_size: 4,
        };

        for list in [
            json!([["mining.notify", "deadbeef"]]),
            json!([["mining.set_difficulty", "x"], ["mining.notify", "y"]]),
            json!([]),
            Value::Null,
            json!("a string where a list was expected"),
        ] {
            let result = json!([list, "deadbeef", 4]);
            assert_eq!(
                Subscribed::parse(&result).expect("positions 1 and 2 are all that is read"),
                expected
            );
        }
    }

    #[test]
    fn the_subscription_id_is_not_the_extranonce1() {
        // Neither capture can be this test: both pools happen to reuse one as
        // the other, so a client that conflated them would pass against both.
        // This is a third pool's shape of reply, where they differ — the shape a
        // cross-pool comparison found and the reason the rule is written down
        // at all.
        let result = json!([
            [
                ["mining.set_difficulty", "6d1a0f"],
                ["mining.notify", "6d1a0f"]
            ],
            "0a1b2c3d",
            8
        ]);
        let subscribed = Subscribed::parse(&result).expect("a reply whose ids differ");
        assert_eq!(subscribed.extranonce1, vec![0x0a, 0x1b, 0x2c, 0x3d]);
        assert_ne!(
            subscribed.extranonce1,
            wire::bytes_from_hex("6d1a0f").unwrap(),
            "the subscription id is not the extranonce1"
        );
    }

    #[test]
    fn a_subscribe_reply_that_leaves_no_room_to_roll_is_refused() {
        // wire::extranonce2_bytes is documented to leave this check here: a
        // zero-width extranonce2 yields no bytes, which means every header
        // under one merkle root and a client that silently stops rolling.
        for size in [json!(0), json!(33), json!("8"), Value::Null] {
            let result = json!([[], "deadbeef", size]);
            assert!(
                Subscribed::parse(&result).is_err(),
                "an extranonce2_size of {size} is not usable"
            );
        }
        // And a reply too short to hold the fields at all.
        assert!(Subscribed::parse(&json!([[], "deadbeef"])).is_err());
        assert!(Subscribed::parse(&json!("not an array")).is_err());
    }

    #[test]
    fn a_refusal_with_a_null_error_is_still_a_refusal() {
        // The shape a failed mining.authorize takes on Pool A. Reading only
        // `error` reads this as success and then mines for a pool that is
        // crediting nothing to anyone.
        assert!(failure(&json!(false), &Value::Null).is_some());

        // The other half: a populated error, whose message is handed back so a
        // log line can carry the pool's own words.
        let refused = failure(&Value::Null, &json!([24, "Unauthorized worker", null]));
        assert_eq!(refused.as_deref(), Some("Unauthorized worker"));

        // An error that is not the conventional triple still reports.
        assert!(failure(&json!(true), &json!("go away")).is_some());

        // And the successes, including the acknowledgement shape: a `null`
        // result with no error is how a pool answers a request it has nothing
        // to say about, which mining.suggest_difficulty is.
        assert_eq!(failure(&json!(true), &Value::Null), None);
        assert_eq!(failure(&Value::Null, &Value::Null), None);
    }

    #[test]
    fn a_notify_from_the_capture_reads_field_by_field() {
        let frames = fixture::load(fixture::POOL_A);
        let first = frames
            .iter()
            .find(|frame| frame.method() == Some("mining.notify"))
            .expect("the capture has notifies");

        let Incoming::Notify(notify) = Incoming::parse(&first.line).expect("a notify parses")
        else {
            panic!("a mining.notify parses as one");
        };

        assert_eq!(notify.version, 0x2000_0000);
        assert_eq!(notify.bits.to_consensus(), 0x1702_355e);
        // Twelve, not the thirteen of an earlier prevhash vector: that
        // vector was read off a live probe a few minutes earlier, at ntime
        // 6aac7757 and a different transaction set. Both are real, and the
        // branch length is a property of the template rather than of the pool.
        assert_eq!(notify.branch.len(), 12);
        assert!(!notify.job_id.is_empty());
        // The coinbase splits around the extranonce, so neither half is empty
        // and coinb1 ends where the pool's extranonce1 begins.
        assert!(!notify.coinb1.is_empty() && !notify.coinb2.is_empty());
        // Sanity on the pair most easily read in the wrong order: an ntime is a
        // Unix time in 2026 and an nbits is not.
        assert!(
            notify.ntime > 1_700_000_000,
            "ntime is a clock, not a target"
        );
    }

    #[test]
    fn a_notify_missing_a_field_is_named_rather_than_defaulted() {
        let frames = fixture::load(fixture::POOL_A);
        let good = frames
            .iter()
            .find(|frame| frame.method() == Some("mining.notify"))
            .expect("the capture has notifies");
        let params = good.params().to_vec();

        for missing in 0..params.len() {
            let mut broken = params.clone();
            broken[missing] = Value::Null;
            assert!(
                Notify::parse(&broken).is_err(),
                "a notify with a null at position {missing} is not a notify"
            );
        }
        assert!(Notify::parse(&params[..8]).is_err(), "eight is not nine");
    }

    #[test]
    fn a_set_difficulty_is_a_positive_number_and_nothing_else() {
        let parse = |value| {
            Incoming::parse(&format!(
                r#"{{"id":null,"method":"mining.set_difficulty","params":[{value}]}}"#
            ))
        };

        // The two the captures carry: Pool A's 1, Pool B's floor.
        assert!(matches!(parse("1"), Ok(Incoming::SetDifficulty(d)) if d == 1.0));
        assert!(matches!(parse("100000"), Ok(Incoming::SetDifficulty(d)) if d == 100000.0));
        // And a fractional one, which pools running vardiff below 1 do send.
        assert!(matches!(parse("0.5"), Ok(Incoming::SetDifficulty(d)) if d == 0.5));

        for nonsense in ["0", "-1", r#""1""#] {
            assert!(
                parse(nonsense).is_err(),
                "a difficulty of {nonsense} would make every header a share or none"
            );
        }
    }

    #[test]
    fn a_set_extranonce_may_or_may_not_resize_the_field() {
        let one = Incoming::parse(
            r#"{"id":null,"method":"mining.set_extranonce","params":["0a1b2c3d"]}"#,
        )
        .expect("the one-parameter form");
        assert!(matches!(
            one,
            Incoming::SetExtranonce {
                extranonce2_size: None,
                ..
            }
        ));

        let two = Incoming::parse(
            r#"{"id":null,"method":"mining.set_extranonce","params":["0a1b2c3d",4]}"#,
        )
        .expect("the two-parameter form");
        let Incoming::SetExtranonce {
            extranonce1,
            extranonce2_size,
        } = two
        else {
            panic!("a set_extranonce parses as one");
        };
        assert_eq!(extranonce1, vec![0x0a, 0x1b, 0x2c, 0x3d]);
        assert_eq!(extranonce2_size, Some(4));

        // Held to the subscribe reply's bound, since it replaces that width.
        for size in [0, 33] {
            let frame = format!(
                r#"{{"id":null,"method":"mining.set_extranonce","params":["0a1b2c3d",{size}]}}"#
            );
            assert!(
                Incoming::parse(&frame).is_err(),
                "an extranonce2_size of {size} is not usable"
            );
        }
    }

    #[test]
    fn a_method_this_client_does_not_implement_is_named_rather_than_fatal() {
        // A session that died on the first vendor extension would be a fragile
        // client, not a strict one.
        for method in ["client.show_message", "mining.extranonce.subscribe"] {
            let frame = format!(r#"{{"id":null,"method":"{method}","params":[]}}"#);
            match Incoming::parse(&frame).expect("an unknown method still parses") {
                Incoming::Unknown(named) => assert_eq!(named, method),
                other => panic!("{method} should be Unknown, got {other:?}"),
            }
        }

        // Not JSON at all is a different thing and is an error.
        assert!(Incoming::parse("").is_err());
        // Neither a method nor an id: not a frame this client has a model for.
        assert!(Incoming::parse("{}").is_err(), "no method, no id");
        // An id that is neither a number nor null is a pool whose replies this
        // client cannot match, and guessing would credit the wrong share.
        assert!(Incoming::parse(r#"{"id":"3","result":true}"#).is_err());
    }

    #[test]
    fn a_set_version_mask_is_one_big_endian_hex_string() {
        let parse = |params: &str| {
            Incoming::parse(&format!(
                r#"{{"id":null,"method":"mining.set_version_mask","params":{params}}}"#
            ))
        };
        assert!(matches!(
            parse(r#"["00ffe000"]"#),
            Ok(Incoming::SetVersionMask(0x00ff_e000))
        ));
        // Zero is a pool switching rolling off, and is a mask like any other.
        assert!(matches!(
            parse(r#"["00000000"]"#),
            Ok(Incoming::SetVersionMask(0))
        ));
        for nonsense in ["[]", "[536862720]", r#"["not hex"]"#] {
            assert!(parse(nonsense).is_err(), "{nonsense} is not a mask");
        }
    }

    #[test]
    fn a_ping_and_a_version_request_keep_the_id_they_arrived_with() {
        // The id goes back unchanged, whatever type the pool chose for it.
        let ping = Incoming::parse(r#"{"id":"p7","method":"mining.ping","params":[]}"#);
        assert!(matches!(ping, Ok(Incoming::Ping(id)) if id == json!("p7")));

        let version = Incoming::parse(r#"{"id":12,"method":"client.get_version","params":[]}"#);
        assert!(matches!(version, Ok(Incoming::GetVersion(id)) if id == json!(12)));

        // No id at all is a notification, which is a null here.
        let bare = Incoming::parse(r#"{"method":"mining.ping"}"#);
        assert!(matches!(bare, Ok(Incoming::Ping(Value::Null))));
    }

    #[test]
    fn a_reconnect_keeps_what_it_asked_for_so_the_log_can_say_it() {
        let frame = r#"{"id":null,"method":"client.reconnect","params":["pool.example",3333,0]}"#;
        let Ok(Incoming::Reconnect(params)) = Incoming::parse(frame) else {
            panic!("a client.reconnect parses as one");
        };
        assert_eq!(params, vec![json!("pool.example"), json!(3333), json!(0)]);
    }

    #[test]
    fn a_reply_with_a_null_id_is_a_reply() {
        // The frame that killed a session against a local Pool B while
        // every mainnet run stayed green — measured 18 September 2026, and the
        // first thing a local pool found. Pool B answers a null-id
        // request by echoing the null; Pool A coerces the same null to zero.
        // Both are replies and neither is a method call.
        let pool_b = r#"{"id":null,"result":null,"error":[20,"invalid id",null]}"#;
        let Ok(Incoming::Reply { id, result, error }) = Incoming::parse(pool_b) else {
            panic!("a null-id reply is a reply");
        };
        assert_eq!(
            id, None,
            "it matches nothing this client asked, which is right"
        );
        assert!(result.is_null());
        assert_eq!(failure(&result, &error).as_deref(), Some("invalid id"));

        // Pool A's spelling of the same thing.
        let pool_a = r#"{"id":0,"result":true,"error":null}"#;
        let Ok(Incoming::Reply { id, .. }) = Incoming::parse(pool_a) else {
            panic!("an id-0 reply is a reply");
        };
        assert_eq!(id, Some(0));
    }

    #[test]
    fn every_frame_the_pools_sent_parses_without_an_unknown() {
        // Both captures, every received frame, no
        // `Unknown` — which is the assertion that this client understands
        // everything two real pools actually said to it.
        let mut counts = (0, 0, 0, 0);

        for capture in [fixture::POOL_A, fixture::POOL_B] {
            for frame in fixture::load(capture).iter().filter(|f| !f.is_send()) {
                match Incoming::parse(&frame.line)
                    .unwrap_or_else(|why| panic!("{capture} at {}: {why}", frame.ts))
                {
                    Incoming::Notify(_) => counts.0 += 1,
                    Incoming::SetDifficulty(_) => counts.1 += 1,
                    Incoming::Reply { .. } => counts.2 += 1,
                    Incoming::SetExtranonce { .. } => counts.3 += 1,
                    Incoming::SetVersionMask(_)
                    | Incoming::Ping(_)
                    | Incoming::GetVersion(_)
                    | Incoming::Reconnect(_) => {
                        panic!("{capture} sent a frame neither captured pool is known to send")
                    }
                    Incoming::Unknown(method) => {
                        panic!("{capture} sent {method}, which this client does not understand")
                    }
                }
            }
        }

        // 11 + 2 notifies, 1 + 1 difficulties, 15 + 2 replies, and no pool
        // resized an extranonce in either session.
        assert_eq!(counts, (13, 2, 17, 0));
    }
}
