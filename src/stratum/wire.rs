//! The byte-order conversions between a Stratum V1 frame and a block header.
//!
//! This file is the smallest in the module and carries the most risk per line.
//! Essentially every bug in a from-scratch V1 client lives here, and all of
//! them share a shape: the wrong answer is a well-formed 32-byte value that
//! hashes without complaint and is rejected by every pool on earth. There is no
//! type that catches it and `rust-bitcoin` cannot help, because all of this
//! happens *before* a `Header` exists.
//!
//! So it is a file of its own, with no socket, no JSON and no state — hex in,
//! bytes out — and it is tested against a real pool's own accepted shares.
//! The byte-order rules, item by item:
//!
//! | Field | On the wire | In the header |
//! | --- | --- | --- |
//! | `prevhash` | internal order with the eight 32-bit words individually reversed | internal order |
//! | `merkle_branch` | internal order, per entry | hashed directly, no reversal |
//! | `version`, `nbits`, `ntime` | big-endian hex | little-endian |
//! | `nonce` (going back out) | big-endian hex | little-endian |
//! | `extranonce2` | exactly `extranonce2_size` raw bytes | inside the coinbase |
//!
//! The one that is genuinely surprising is the first: it is **not**
//! `BlockHash::from_str` and it is **not** a reversal of one.

use bitcoin::{
    BlockHash, TxMerkleNode,
    hashes::{Hash, sha256d::Hash as Sha256d},
};

/// Double SHA-256, in Bitcoin's internal byte order.
///
/// Through `rust-bitcoin` rather than through [`super::super::sha256`]: that
/// module is a header hasher built around a midstate over a fixed 80 bytes, and
/// nothing here hashes a header. A coinbase is any length and a merkle step is
/// exactly 64 bytes, so neither has a midstate to save. The trusted path is
/// also the only sensible one when the whole point of the file is being right.
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    Sha256d::hash(bytes).to_byte_array()
}

/// A `mining.notify` prevhash to the hash it names.
///
/// **Reverses the order of the eight 32-bit words and leaves each word's bytes
/// alone.** Stratum inherited this from a pool server that wrote out the
/// header's prevhash field as eight `u32`s on a big-endian machine, and it has
/// been the protocol ever since.
///
/// The two wrong answers are the two a from-scratch client actually writes — a
/// whole-string reversal, and a per-word byte swap — and both are asserted
/// against in the tests below rather than only described here.
///
/// ```text
/// notify prevhash  98ccd6c190d927b95a692b4a65b6d5137f93c9c2000228520000000000000000
/// as eight words   98ccd6c1 90d927b9 5a692b4a 65b6d513 7f93c9c2 00022852 00000000 00000000
/// block hash       0000000000000000000228527f93c9c265b6d5135a692b4a90d927b998ccd6c1
/// ```
pub fn prevhash_from_notify(hex: &str) -> Result<BlockHash, String> {
    let raw = bytes_from_hex(hex).map_err(|why| format!("a mining.notify prevhash {why}"))?;
    let raw: [u8; 32] = raw.try_into().map_err(|raw: Vec<u8>| {
        format!(
            "a mining.notify prevhash is 32 bytes; this one is {}",
            raw.len()
        )
    })?;

    // Two reversals that partly cancel. Going to a hash's internal order means
    // reversing all 32 bytes of the display order, and the display order is the
    // notify order with the eight words reversed — so the composition is each
    // word left where it is with its own four bytes reversed. Written as the
    // one loop it collapses to, because a pair of reversals that cancel is
    // harder to check against the vector above than the answer is.
    let mut internal = raw;
    for word in internal.as_chunks_mut::<4>().0 {
        word.reverse();
    }
    Ok(BlockHash::from_byte_array(internal))
}

/// Big-endian hex, as `version`, `nbits` and `ntime` arrive, to the `u32` the
/// header holds little-endian.
///
/// Fewer than eight characters is accepted — a pool that trims a leading zero
/// is unusual but not wrong — while more than eight is refused, because a
/// ninth character means the field is not the one it claims to be and
/// truncating it would be a header built from a value the pool never sent.
pub fn be_u32_from_hex(hex: &str) -> Result<u32, String> {
    if hex.is_empty() || hex.len() > 8 {
        return Err(format!(
            "a big-endian u32 field is 1 to 8 hex characters; this one is {}",
            hex.len()
        ));
    }
    let mut value = 0u32;
    for byte in hex.as_bytes() {
        value = (value << 4) | u32::from(hex_digit(*byte)?);
    }
    Ok(value)
}

/// The inverse, for `nonce` and `ntime` going back out in `mining.submit`.
///
/// Always eight characters. The padding is not cosmetic: a pool parsing the
/// field by position — and some do — reads a short `nonce` as a different
/// number, so a share found under a nonce below `0x1000_0000` would be
/// rejected roughly one time in sixteen with no pattern to it.
pub fn be_hex_from_u32(value: u32) -> String {
    format!("{value:08x}")
}

/// A `merkle_branch` entry: internal byte order, hashed without reversal.
///
/// The asymmetry with [`prevhash_from_notify`] is real and is not a mistake in
/// either. A branch entry is never displayed and never parsed as a hash — it is
/// 32 bytes to concatenate — so nothing ever reversed it.
pub fn branch_entry(hex: &str) -> Result<[u8; 32], String> {
    let raw = bytes_from_hex(hex).map_err(|why| format!("a merkle_branch entry {why}"))?;
    raw.try_into().map_err(|raw: Vec<u8>| {
        format!(
            "a merkle_branch entry is 32 bytes; this one is {}",
            raw.len()
        )
    })
}

/// `root = sha256d(root ++ branch[i])`, left to right, over the coinbase txid.
///
/// The pool has already done the rest of the tree, which is what lets a client
/// hold no transactions at all: every other pairing in the tree is fixed once
/// the transaction set is, and only the path from the coinbase leaf to the root
/// moves when the extranonce does. The branch is therefore always the *left*
/// operand's partner — the coinbase is leaf zero, so it and every intermediate
/// node on its path are the left side of their pairing, which is why this never
/// has to decide an order.
pub fn fold_merkle(coinbase_txid: [u8; 32], branch: &[[u8; 32]]) -> TxMerkleNode {
    let mut root = coinbase_txid;
    let mut pair = [0u8; 64];
    for step in branch {
        pair[..32].copy_from_slice(&root);
        pair[32..].copy_from_slice(step);
        root = sha256d(&pair);
    }
    TxMerkleNode::from_byte_array(root)
}

/// Exactly `size` bytes, big-endian, as the pool negotiated.
///
/// The *width* is the protocol's — a coinbase spliced to any other length is a
/// different transaction than the one the pool's `coinb1`/`coinb2` describe, so
/// the pool's merkle branch would not fold to anything. The *interpretation* is
/// the client's, and a big-endian counter is this client's choice. cpuminer
/// happens to count little-endian; both are correct and neither is visible to
/// the pool.
///
/// All three pools measured in development negotiate 8, which is
/// exactly [`Extranonce`](super::super::block::Extranonce)'s width and is the
/// whole reason the existing extranonce walk can be reused. A narrower field
/// keeps the low bytes, so a counter past `2^(8 * size)` repeats — bounding the
/// walk is the caller's business. A `size` of zero yields no bytes at all,
/// which leaves nothing to roll; that is a broken pool and is refused where the
/// subscription is parsed rather than here.
pub fn extranonce2_bytes(counter: u64, size: usize) -> Vec<u8> {
    let raw = counter.to_be_bytes();
    if size <= raw.len() {
        raw[raw.len() - size..].to_vec()
    } else {
        let mut bytes = vec![0u8; size];
        bytes[size - raw.len()..].copy_from_slice(&raw);
        bytes
    }
}

/// Hex to bytes, strictly: an even number of ASCII hex digits and nothing else.
///
/// No `0x`, no whitespace, no odd length. Every field this module decodes has a
/// width the protocol fixes, so anything else is a malformed frame and is worth
/// naming as one rather than silently half-decoding.
///
/// Hand-rolled for the same reason `rpc.rs` hand-rolls HTTP: a dependency for
/// fifteen lines is a dependency that has to be justified forever.
pub fn bytes_from_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!(
            "is not hex: {} characters is not a whole number of bytes",
            hex.len()
        ));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        bytes.push((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?);
    }
    Ok(bytes)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!(
            "is not hex: {:?} is not a hex digit",
            char::from(other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{CompactTarget, Target};

    use super::{super::fixture, *};

    /// A prevhash exactly as Pool A sent
    /// it on 18 September 2026.
    const NOTIFY_PREVHASH: &str =
        "98ccd6c190d927b95a692b4a65b6d5137f93c9c2000228520000000000000000";

    /// Mainnet block 000000000000000000022852…, which was the tip at that
    /// moment. A published fact, in the same spirit as `MINER_MODE=probe`
    /// checking the GPU against the genesis header's known hash.
    const TIP: &str = "0000000000000000000228527f93c9c265b6d5135a692b4a90d927b998ccd6c1";

    /// Difficulty 1 as a compact target: `0x00000000ffff0000…`, the share
    /// target the Pool A capture was taken at.
    const DIFFICULTY_ONE: u32 = 0x1d00_ffff;

    fn difficulty_one() -> Target {
        Target::from_compact(CompactTarget::from_consensus(DIFFICULTY_ONE))
    }

    #[test]
    fn the_notify_prevhash_decodes_to_the_tip_it_named() {
        let decoded = prevhash_from_notify(NOTIFY_PREVHASH).expect("the vector is well formed");
        assert_eq!(decoded, BlockHash::from_str(TIP).expect("the tip parses"));
    }

    #[test]
    fn the_two_wrong_decodings_are_asserted_wrong() {
        // Both are what a from-scratch client actually writes, both are
        // well-formed 32-byte values, and both hash without complaint. Nothing
        // but an assertion tells them apart from the right answer, so here it
        // is.
        let right = prevhash_from_notify(NOTIFY_PREVHASH).expect("the vector is well formed");

        let whole_string_reversal =
            "000000000000000052280200c2c9937f13d5b6654a2b695ab927d990c1d6cc98";
        let per_word_byte_swap = "c1d6cc98b927d9904a2b695a13d5b665c2c9937f522802000000000000000000";

        for wrong in [whole_string_reversal, per_word_byte_swap] {
            let wrong = BlockHash::from_str(wrong).expect("the wrong answers are still hashes");
            assert_ne!(
                right, wrong,
                "{wrong} is one of the two known wrong decodings"
            );
        }

        // And the one that is easiest of all to reach for, named rather than
        // spelled out: the hash parser this is not.
        assert_ne!(
            right,
            BlockHash::from_str(NOTIFY_PREVHASH).expect("it parses as a hash, that is the trap"),
            "prevhash_from_notify is not BlockHash::from_str"
        );
    }

    #[test]
    fn a_prevhash_that_is_not_a_prevhash_is_refused() {
        for (input, why) in [
            ("", "empty"),
            ("98ccd6c1", "too short"),
            (&NOTIFY_PREVHASH[..63], "odd length"),
            (
                "zz000000000000000000000000000000000000000000000000000000000000000",
                "not hex",
            ),
        ] {
            let outcome = prevhash_from_notify(input);
            assert!(outcome.is_err(), "{why} should be refused");
            let message = outcome.unwrap_err();
            assert!(
                message.contains("prevhash"),
                "the error should name the field, got {message:?}"
            );
        }
    }

    #[test]
    fn the_big_endian_fields_round_trip() {
        // The three the capture carries, in the hex the pool sent.
        for hex in ["20000000", "1702355e", "6aac80b6", "00000000", "ffffffff"] {
            let value = be_u32_from_hex(hex).expect("a captured field parses");
            assert_eq!(be_hex_from_u32(value), hex, "{hex} survives the round trip");
        }

        // And the direction that matters for the header: big-endian in, and
        // the number the header then holds little-endian.
        assert_eq!(be_u32_from_hex("20000000").unwrap(), 0x2000_0000);
        assert_eq!(be_u32_from_hex("1702355e").unwrap(), 0x1702_355e);
    }

    #[test]
    fn a_nonce_is_always_eight_characters() {
        // A pool that parses by position reads a short nonce as a different
        // number, so this is a correctness property and not formatting.
        assert_eq!(be_hex_from_u32(1), "00000001");
        assert_eq!(be_hex_from_u32(0), "00000000");
        assert_eq!(be_hex_from_u32(0x0122_0aa8), "01220aa8");
        assert_eq!(be_hex_from_u32(u32::MAX), "ffffffff");
        for value in [0u32, 1, 0xff, 0x1000_0000, u32::MAX] {
            assert_eq!(be_hex_from_u32(value).len(), 8);
        }
    }

    #[test]
    fn a_field_wider_than_a_u32_is_refused_rather_than_truncated() {
        for input in ["", "1702355e0", "170 355e", "1702355g"] {
            assert!(
                be_u32_from_hex(input).is_err(),
                "{input:?} is not a big-endian u32 field"
            );
        }
        // Short is allowed: a pool that trims a leading zero is unusual, not
        // wrong, and the value is unambiguous.
        assert_eq!(be_u32_from_hex("1").unwrap(), 1);
        assert_eq!(be_u32_from_hex("ffff").unwrap(), 0xffff);
    }

    #[test]
    fn a_branch_entry_is_thirty_two_bytes_of_hex_and_nothing_else() {
        let entry =
            branch_entry("e7dcc8475429cc9401bbbbc264fdee0d3f3a52e89dd1e5ea80582f6f233aff4a")
                .expect("a captured branch entry");
        assert_eq!(
            entry[0], 0xe7,
            "no reversal: the first hex pair is the first byte"
        );
        assert_eq!(entry[31], 0x4a);

        for input in ["", "e7dc", "zz"] {
            assert!(
                branch_entry(input).is_err(),
                "{input:?} is not a branch entry"
            );
        }
    }

    #[test]
    fn an_empty_branch_folds_to_the_coinbase_itself() {
        // A block whose only transaction is the coinbase — every regtest block
        // this repository mines. The merkle root is the coinbase txid, and the
        // fold must not hash it one more time on the way past.
        let txid = [0x11u8; 32];
        assert_eq!(fold_merkle(txid, &[]).to_byte_array(), txid);
    }

    #[test]
    fn the_fold_is_left_to_right_and_the_order_is_load_bearing() {
        // Swapping the two steps is a different root, which is the whole
        // reason the branch arrives as an ordered list rather than a set.
        let txid = [0x11u8; 32];
        let (first, second) = ([0x22u8; 32], [0x33u8; 32]);
        assert_ne!(
            fold_merkle(txid, &[first, second]),
            fold_merkle(txid, &[second, first])
        );

        // And the step itself is sha256d over the concatenation, in that
        // order, with neither side reversed.
        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&txid);
        expected[32..].copy_from_slice(&first);
        assert_eq!(
            fold_merkle(txid, &[first]).to_byte_array(),
            sha256d(&expected)
        );
    }

    #[test]
    fn an_extranonce2_is_exactly_the_negotiated_width() {
        // The width all three measured pools negotiate, and the one the
        // existing `Extranonce` already is.
        assert_eq!(
            extranonce2_bytes(1, 8),
            vec![0, 0, 0, 0, 0, 0, 0, 1],
            "big-endian, full width"
        );
        assert_eq!(extranonce2_bytes(0, 8).len(), 8);

        // Narrower keeps the low bytes, so the walk repeats rather than
        // silently writing past the field.
        assert_eq!(
            extranonce2_bytes(0x0102_0304_0506_0708, 4),
            vec![5, 6, 7, 8]
        );
        assert_eq!(extranonce2_bytes(1, 4), vec![0, 0, 0, 1]);
        assert_eq!(extranonce2_bytes(1 << 32, 4), extranonce2_bytes(0, 4));

        // Wider left-pads, and zero yields nothing to roll.
        assert_eq!(extranonce2_bytes(1, 12), {
            let mut wide = vec![0u8; 12];
            wide[11] = 1;
            wide
        });
        assert!(extranonce2_bytes(1, 0).is_empty());

        for size in 0..=16 {
            assert_eq!(extranonce2_bytes(u64::MAX, size).len(), size);
        }
    }

    #[test]
    fn every_prevhash_in_the_capture_meets_the_nbits_beside_it() {
        // A decoded prevhash is the hash of a block that was actually mined, so
        // it must meet the network target the same notify announced. Both wrong
        // decodings above fail this by a wide margin — they have their leading
        // zeros in the wrong place — which makes this a real check on eleven
        // more vectors than the hand-picked one above.
        let frames = fixture::load(fixture::POOL_A);
        let mut checked = 0;

        for frame in frames
            .iter()
            .filter(|f| f.method() == Some("mining.notify"))
        {
            let prevhash = prevhash_from_notify(frame.param(1)).expect("a captured prevhash");
            let nbits = be_u32_from_hex(frame.param(6)).expect("a captured nbits");
            let target = Target::from_compact(CompactTarget::from_consensus(nbits));
            assert!(
                target.is_met_by(prevhash),
                "{prevhash} does not meet the nbits {} it arrived with",
                frame.param(6)
            );
            checked += 1;
        }

        assert_eq!(checked, 11, "every notify in the capture");
    }

    #[test]
    fn every_accepted_submit_in_the_capture_rebuilds_to_a_share() {
        // The oracle. Thirteen shares a real pool accepted, rebuilt out of the
        // notifies that answered them using nothing but this file: splice the
        // coinbase, fold the branch, frame the header. Every one must land
        // under the share target, and it can only do that if all five
        // conversions above are right at once.
        //
        // `job.rs` asserts the same thing through `Job::header` and
        // `rust-bitcoin`'s own `Header`. That is not a duplicate: this checks
        // the conversions, that checks the layer built on them, and the two
        // disagreeing would be worth knowing about. Do not delete either.
        let frames = fixture::load(fixture::POOL_A);

        let subscribe = frames
            .iter()
            .find(|frame| !frame.is_send() && frame.json["id"] == 1)
            .expect("the capture opens with a subscribe reply");
        let result = subscribe.result().expect("a subscribe reply has a result");
        let extranonce1 =
            bytes_from_hex(result[1].as_str().expect("an extranonce1")).expect("it is hex");
        let extranonce2_size = result[2].as_u64().expect("an extranonce2_size") as usize;

        let difficulty = frames
            .iter()
            .find(|frame| frame.method() == Some("mining.set_difficulty"))
            .map(|frame| frame.params()[0].as_f64().expect("a scalar difficulty"))
            .expect("the capture sets a difficulty");
        assert_eq!(
            difficulty, 1.0,
            "the Pool A capture was taken at difficulty 1"
        );
        let target = difficulty_one();

        let jobs: std::collections::HashMap<&str, &fixture::Frame> = frames
            .iter()
            .filter(|frame| frame.method() == Some("mining.notify"))
            .map(|frame| (frame.param(0), frame))
            .collect();

        let mut checked = 0;
        for submit in frames
            .iter()
            .filter(|frame| frame.is_send() && frame.method() == Some("mining.submit"))
        {
            let (job_id, extranonce2, ntime, nonce) = (
                submit.param(1),
                submit.param(2),
                submit.param(3),
                submit.param(4),
            );
            let job = jobs.get(job_id).expect("every submit answers a notify");

            let extranonce2 = bytes_from_hex(extranonce2).expect("a captured extranonce2");
            assert_eq!(
                extranonce2.len(),
                extranonce2_size,
                "the pool negotiated {extranonce2_size} bytes"
            );

            // coinb1 ++ extranonce1 ++ extranonce2 ++ coinb2, hashed as it
            // stands: the notify form is stripped of the witness, so this is
            // the txid directly.
            let mut coinbase = bytes_from_hex(job.param(2)).expect("a captured coinb1");
            coinbase.extend_from_slice(&extranonce1);
            coinbase.extend_from_slice(&extranonce2);
            coinbase.extend_from_slice(&bytes_from_hex(job.param(3)).expect("a captured coinb2"));

            let branch: Vec<[u8; 32]> = job.params()[4]
                .as_array()
                .expect("a merkle branch")
                .iter()
                .map(|entry| branch_entry(entry.as_str().expect("a hex entry")).expect("32 bytes"))
                .collect();
            let root = fold_merkle(sha256d(&coinbase), &branch);

            let mut header = Vec::with_capacity(80);
            header.extend_from_slice(&be_u32_from_hex(job.param(5)).unwrap().to_le_bytes());
            header.extend_from_slice(
                &prevhash_from_notify(job.param(1))
                    .expect("a captured prevhash")
                    .to_byte_array(),
            );
            header.extend_from_slice(&root.to_byte_array());
            header.extend_from_slice(&be_u32_from_hex(ntime).unwrap().to_le_bytes());
            header.extend_from_slice(&be_u32_from_hex(job.param(6)).unwrap().to_le_bytes());
            header.extend_from_slice(&be_u32_from_hex(nonce).unwrap().to_le_bytes());
            assert_eq!(header.len(), 80);

            let hash = BlockHash::from_byte_array(sha256d(&header));
            assert!(
                target.is_met_by(hash),
                "share {checked} on job {job_id} (nonce {nonce}) rebuilt to {hash}, \
                 which does not meet difficulty 1"
            );
            checked += 1;
        }

        assert_eq!(checked, 13, "every accepted submit in the capture");
    }
}
