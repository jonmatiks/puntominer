//! Reading the committed Stratum captures, for tests only.
//!
//! `tests/fixtures/*.jsonl` is a real session with a real pool, distilled from
//! cpuminer's `--protocol-dump` — one record per line, each holding the frame
//! *exactly* as it crossed the wire. See `tests/fixtures/README.md` for how it
//! was taken and why it is safe to commit.
//!
//! This lives beside the code rather than in `tests/` because several modules
//! test against the same files and a shared reader is better than a copy of a
//! `serde_json` loop in each. It is `#[cfg(test)]`, so it is not in
//! the binary.
//!
//! **The `line` is kept as a string on purpose.** A fixture re-encoded through
//! `serde_json` would silently normalise key order and spacing, and the two
//! captures disagree about both — Pool A answers `{"id","result","error"}`
//! and Pool B `{"id","error","result"}`. A parser tested against a
//! normalised copy of its input has not been tested against the wire.

use std::path::PathBuf;

use serde_json::Value;

/// The 42-frame Pool A session: a full handshake, 11 notifies, and 13
/// `mining.submit` frames the pool accepted. The accepted submits are what
/// makes this an oracle rather than a sample.
pub const POOL_A: &str = "stratum-pool-a.jsonl";

/// The 7-frame Pool B session. No submits — its difficulty floor is
/// weeks per share at cpuminer's rate — so it is a *shape*
/// fixture: one subscription entry where Pool A sends two, and a
/// subscription id equal to the `extranonce1` where Pool A's differs.
pub const POOL_B: &str = "stratum-pool-b.jsonl";

/// This client against a local Pool B on regtest, recorded by a logging
/// relay: 35 frames and 8 accepted submits, 5 of them at a
/// rolled version. cpuminer 2.5.1 does not roll, so this and
/// [`POOL_A_ROLLED`] are the only captures with rolled shares in them, and
/// on regtest every one of these was also a block the node kept.
pub const POOL_B_ROLLED: &str = "stratum-pool-b-rolled.jsonl";

/// This client against Pool A on mainnet, recorded the same way: 114
/// frames over 45 minutes and 6 accepted submits, 4 of them at a rolled
/// version.
pub const POOL_A_ROLLED: &str = "stratum-pool-a-rolled.jsonl";

/// This client against a local Pool B on a regtest node started with
/// `-blockversion` to announce `30000000`: 133 frames and 37 accepted submits,
/// none of them rolled and none carrying a sixth parameter. The case
/// `search::rollable` exists for, which current Bitcoin Core no longer
/// produces on its own.
pub const POOL_B_30000000: &str = "stratum-pool-b-30000000.jsonl";

/// This client against PuntoHunter's SV2 solo port on regtest, recorded by
/// `MINER_POOL_CAPTURE` at the client's decrypt boundary: two sessions, a CPU
/// one and a GPU one, with 16 shares the pool accepted, every one also a block.
/// PuntoHunter's frames are encoded by SRI's `stratum-core` crates, so this
/// is `messages.rs` checked against an encoder nobody here wrote.
pub const SV2_PUNTOHUNTER: &str = "sv2-puntohunter.hex";

/// One frame from a capture.
pub struct Frame {
    /// The capture's own timestamp, to the second.
    pub ts: String,
    /// `send` for client → pool, `recv` for pool → client — cpuminer's `>` and
    /// `<`. Which direction a frame went is not always recoverable from its
    /// contents: `mining.submit` and `mining.notify` are both `method` frames.
    pub dir: String,
    /// The frame exactly as it came off the wire.
    pub line: String,
    /// The same frame parsed, for tests that want a field rather than the
    /// bytes.
    pub json: Value,
}

impl Frame {
    /// Whether this frame went client → pool.
    pub fn is_send(&self) -> bool {
        self.dir == "send"
    }

    /// The JSON-RPC `method`, if this is a call rather than a reply.
    pub fn method(&self) -> Option<&str> {
        self.json.get("method").and_then(Value::as_str)
    }

    /// The call's `params`, or nothing at all for a reply.
    pub fn params(&self) -> &[Value] {
        self.json
            .get("params")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Parameter `index` as a string, which is what every field this module
    /// cares about is. Panics rather than returning an `Option`: a fixture that
    /// does not have the field is a broken fixture, and a test that skipped it
    /// quietly would be worse than one that fails.
    pub fn param(&self, index: usize) -> &str {
        self.params()
            .get(index)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("frame at {} has no string param {index}", self.ts))
    }

    /// The reply's `result`, if this is a reply.
    pub fn result(&self) -> Option<&Value> {
        self.json.get("result")
    }
}

/// Load a capture by file name, resolved against the crate root.
///
/// `CARGO_MANIFEST_DIR` rather than a relative path: the miner resolves paths
/// relative to the working directory, but a test should not care which
/// directory it was started from.
pub fn load(name: &str) -> Vec<Frame> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("the fixture {} should be readable: {why}", path.display()));

    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|record| {
            let record: Value = serde_json::from_str(record)
                .unwrap_or_else(|why| panic!("every fixture record should be JSON: {why}"));
            let line = record["line"]
                .as_str()
                .expect("every fixture record has a `line`")
                .to_string();
            let json = serde_json::from_str(&line)
                .unwrap_or_else(|why| panic!("every captured frame should be JSON: {why}"));
            Frame {
                ts: record["ts"].as_str().unwrap_or_default().to_string(),
                dir: record["dir"].as_str().unwrap_or_default().to_string(),
                line,
                json,
            }
        })
        .collect()
}

/// One frame from a Stratum V2 capture, in `MINER_POOL_CAPTURE`'s format.
///
/// See `v2::conn::Capture` for the format. Unlike the V1 records there is no
/// "exactly as it crossed the wire" to keep, because what crossed the wire was
/// ciphertext: this is the plaintext at the client's decrypt boundary, after
/// the AEAD tag verified it.
pub struct Sv2Frame {
    /// Which connection of the capture this frame belongs to, counted from 0
    /// at each `# connected` line. Job ids and sequence numbers start again
    /// with a session.
    pub session: usize,
    /// `send` lines, this client's own; `false` for what the pool sent.
    pub send: bool,
    pub header: super::v2::frame::Header,
    pub payload: Vec<u8>,
}

/// Load an SV2 capture by file name, resolved as [`load`] resolves one.
pub fn load_sv2(name: &str) -> Vec<Sv2Frame> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|why| panic!("the fixture {} should be readable: {why}", path.display()));
    parse_sv2(&text)
}

/// Read an SV2 capture's text.
///
/// Panics on a malformed line rather than skipping it, for [`Frame::param`]'s
/// reason. The comment column is checked against the header it describes, so
/// a hand-edited line that renamed a frame is caught here.
pub fn parse_sv2(text: &str) -> Vec<Sv2Frame> {
    use super::v2::frame::{HEADER_LEN, Header, name};

    let mut frames = Vec::new();
    let mut session = None::<usize>;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if line.starts_with("# connected") {
            session = Some(session.map_or(0, |at| at + 1));
            continue;
        }
        if line.starts_with('#') {
            continue;
        }

        let (body, comment) = line
            .split_once(" # ")
            .unwrap_or_else(|| panic!("an SV2 capture line has a comment column: {line}"));
        let (direction, hex) = body
            .split_once(' ')
            .unwrap_or_else(|| panic!("an SV2 capture line has a direction: {line}"));
        let send = match direction {
            "send" => true,
            "recv" => false,
            _ => panic!("an SV2 capture line is send or recv: {line}"),
        };
        let bytes = super::wire::bytes_from_hex(hex)
            .unwrap_or_else(|why| panic!("an SV2 capture line is hex: {why}: {line}"));
        assert!(bytes.len() >= HEADER_LEN, "a frame has a header: {line}");
        let header = Header::parse(bytes[..HEADER_LEN].try_into().unwrap())
            .unwrap_or_else(|why| panic!("a captured header parses: {why}: {line}"));
        let payload = bytes[HEADER_LEN..].to_vec();
        assert_eq!(
            header.length as usize,
            payload.len(),
            "a captured frame is as long as its header says: {line}"
        );
        assert_eq!(comment, name(header), "the comment names the frame: {line}");

        frames.push(Sv2Frame {
            session: session.expect("a capture opens with a # connected line"),
            send,
            header,
            payload,
        });
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sv2_capture_holds_whole_sessions_with_accepted_shares() {
        // What the V2 capture exists to hold: a whole session from
        // SetupConnection.Success to SubmitShares.Success, a future job a
        // SetNewPrevHash activated, and a SetTarget.
        use super::super::v2::frame::name;

        let frames = load_sv2(SV2_PUNTOHUNTER);
        assert_eq!(frames.len(), 82);
        assert_eq!(frames.last().unwrap().session, 1, "two sessions");

        let count = |wanted: &str, send: bool| {
            frames
                .iter()
                .filter(|frame| frame.send == send && name(frame.header) == wanted)
                .count()
        };
        assert_eq!(count("SetupConnection.Success", false), 2);
        assert_eq!(count("NewExtendedMiningJob", false), 20);
        assert_eq!(count("SetNewPrevHash", false), 18);
        assert_eq!(count("SetTarget", false), 2);
        assert_eq!(count("SubmitSharesExtended", true), 16);
        assert_eq!(count("SubmitShares.Success", false), 16);
        assert_eq!(count("SubmitShares.Error", false), 0);
    }

    #[test]
    fn the_pool_a_capture_is_the_documented_session() {
        // A guard on the fixture rather than on the code: every other test in
        // this module reads these counts as given, and a fixture regenerated
        // against a different session would quietly change what they prove.
        let frames = load(POOL_A);
        assert_eq!(frames.len(), 42, "42 frames");

        let submits = frames
            .iter()
            .filter(|frame| frame.is_send() && frame.method() == Some("mining.submit"))
            .count();
        let notifies = frames
            .iter()
            .filter(|frame| frame.method() == Some("mining.notify"))
            .count();
        assert_eq!(submits, 13, "13 accepted submits");
        assert_eq!(notifies, 11, "11 notifies");
    }

    #[test]
    fn the_rolled_captures_are_the_ones_the_readme_documents() {
        for (capture, frames, submits, rolled) in
            [(POOL_B_ROLLED, 35, 8, 5), (POOL_A_ROLLED, 114, 6, 4)]
        {
            let loaded = load(capture);
            assert_eq!(loaded.len(), frames, "{capture}: {frames} frames");

            let sent: Vec<&Frame> = loaded
                .iter()
                .filter(|frame| frame.is_send() && frame.method() == Some("mining.submit"))
                .collect();
            assert_eq!(sent.len(), submits, "{capture}: {submits} accepted submits");
            assert!(
                sent.iter().all(|submit| submit.params().len() == 6),
                "{capture}: every one carries the version it rolled"
            );
            let at_rolled = sent
                .iter()
                .filter(|submit| submit.param(5) != "00000000")
                .count();
            assert_eq!(at_rolled, rolled, "{capture}: {rolled} at a rolled version");
        }
    }

    #[test]
    fn the_30000000_capture_rolls_nothing_and_says_nothing_about_versions() {
        let loaded = load(POOL_B_30000000);
        assert_eq!(loaded.len(), 133, "133 frames");

        let sent: Vec<&Frame> = loaded
            .iter()
            .filter(|frame| frame.is_send() && frame.method() == Some("mining.submit"))
            .collect();
        assert_eq!(sent.len(), 37, "37 accepted submits");
        assert!(
            sent.iter().all(|submit| submit.params().len() == 5),
            "none carries the sixth parameter"
        );
        assert!(
            loaded
                .iter()
                .filter(|frame| frame.method() == Some("mining.notify"))
                .all(|notify| notify.param(5) == "30000000"),
            "every job announced 30000000"
        );
    }

    #[test]
    fn the_two_captures_disagree_about_the_subscription_list() {
        // The whole reason the second capture is committed. A client that
        // reads the subscription list rather than positions 1 and 2 works
        // against one of these pools and not the other, and no single capture
        // can show that.
        let subscribed = |name| {
            let frames = load(name);
            let reply = frames
                .into_iter()
                .find(|frame| !frame.is_send() && frame.json["id"] == 1)
                .expect("each capture has a subscribe reply");
            let result = reply
                .result()
                .expect("a subscribe reply has a result")
                .clone();
            let entries = result[0].as_array().expect("a subscription list").len();
            let extranonce1 = result[1].as_str().expect("an extranonce1").to_string();
            let size = result[2].as_u64().expect("an extranonce2_size");
            (entries, extranonce1, size)
        };

        let (a_entries, a_en1, a_size) = subscribed(POOL_A);
        let (b_entries, b_en1, b_size) = subscribed(POOL_B);

        assert_eq!(a_entries, 2, "Pool A subscribes to two notifications");
        assert_eq!(b_entries, 1, "Pool B subscribes to one");

        // Both pools happen to reuse the extranonce1 as the subscription id,
        // which is precisely why neither capture can be the test for "the
        // subscription id is not the extranonce1". That rule is enforced by
        // reading positions 1 and 2 and never position 0 — a property of the
        // parser, asserted where the parser is, not here.
        assert_eq!(a_en1, "10086bd1");
        assert_eq!(b_en1, "19aeecb4");
        assert_eq!((a_size, b_size), (8, 8), "both negotiated 8 bytes");
    }

    #[test]
    fn the_two_pools_order_their_reply_keys_differently() {
        // Asserted off the raw line rather than the parsed frame, because this
        // is the one property parsing destroys. Nothing in the client may
        // depend on key order; this is here so that stays a measured fact.
        let first_reply = |name| {
            load(name)
                .into_iter()
                .find(|frame| !frame.is_send() && frame.json["id"] == 1)
                .expect("each capture has a subscribe reply")
                .line
        };

        assert!(first_reply(POOL_A).starts_with("{\"id\":1,\"result\":"));
        assert!(first_reply(POOL_B).starts_with("{\"id\":1,\"error\":"));
    }
}
