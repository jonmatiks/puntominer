//! The Stratum V2 binary types: little-endian in, little-endian out.
//!
//! This is [`wire`](super::super::wire)'s opposite number, and the comparison
//! is the fastest way to understand what changed. V1's risk is concentrated in
//! five conversions between three byte orders, because JSON gave the fields
//! names and took the widths away. V2 gives the widths back and takes the
//! names away: **every integer is little-endian** and there is nothing to get
//! backwards, but a message is a bare sequence of bytes with no field names in
//! it at all, so a parser that reads one field wrongly reads every field after
//! it wrongly too and has no way to notice.
//!
//! [`Reader::finish`] is what replaces the names. A message that parses and
//! leaves bytes behind is a message this client has misunderstood, and on a
//! protocol with no self-description that is the only structural check
//! available. Every parse in [`messages`](super::messages) ends with it.
//!
//! The rules, from spec §3.1, all of which are tested below:
//!
//! | Type | Bytes | Note |
//! | --- | --- | --- |
//! | `U8`, `U16`, `U24`, `U32`, `U64` | 1, 2, 3, 4, 8 | little-endian |
//! | `F32` | 4 | IEEE-754, little-endian |
//! | `BOOL` | 1 | the low bit only; the other seven are reserved |
//! | `U256` | 32 | raw bytes, not reordered |
//! | `STR0_255` | 1 + L | UTF-8, not null-terminated |
//! | `B0_32`, `B0_64K` | 1 + L, 2 + L | the length prefix width differs |
//! | `SEQ0_255[U256]` | 1 + 32L | |
//! | `OPTION[u32]` | 1 + (0 or 4) | an alias for `SEQ0_1[u32]` |
//!
//! **A `U256` is never byte-reversed here**, in either direction. The spec
//! calls it a little-endian integer and the fields that carry one — a
//! `prev_hash`, a merkle path entry, a target — are all in Bitcoin's internal
//! order already, which is what `rust-bitcoin` holds. Reversing it would be
//! importing a V1 habit into the one place it does not belong.

/// How wide a byte array's length prefix is.
///
/// Only the two widths the mining protocol's extended-channel messages
/// actually use. `B0_255` and `B0_16M` are in the spec and are not here,
/// because nothing this client parses or sends carries one; each is one arm
/// when something does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// `B0_32`: a one-byte length, and at most 32 bytes.
    ///
    /// The bound is not decoration. `extranonce_prefix` and `extranonce` are
    /// both `B0_32`, and both are spliced into a coinbase — so a length this
    /// client accepted and the server did not would be a coinbase the two
    /// disagree about, which is a rejected share with no diagnostic.
    Bytes32,
    /// `B0_64K`: a two-byte little-endian length, and at most 65,535 bytes.
    Bytes64K,
}

impl Prefix {
    /// The longest array this type may carry.
    fn max(self) -> usize {
        match self {
            Self::Bytes32 => 32,
            Self::Bytes64K => 65_535,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Bytes32 => "B0_32",
            Self::Bytes64K => "B0_64K",
        }
    }
}

/// A message payload being taken apart, field by field, in order.
///
/// Bounds-checked and never panicking: the bytes come from a pool, which is a
/// stranger's server, and a length prefix is the one field in this protocol
/// that a peer can use to ask for memory it never sends.
#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes have not been read yet.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    /// Take `width` bytes, or say what was wanted and what was there.
    ///
    /// The single place a length is checked, so there is one error message
    /// shape rather than a dozen. The offset is in it because a protocol with
    /// no field names cannot say *which* field ran out, and the offset is the
    /// next best thing — it is what a hex dump of the frame is indexed by.
    fn take(&mut self, width: usize, what: &str) -> Result<&'a [u8], String> {
        if self.remaining() < width {
            return Err(format!(
                "{what} at byte {} needs {width} bytes and the message has {} left \
                 (of {} in total)",
                self.at,
                self.remaining(),
                self.bytes.len(),
            ));
        }
        let taken = &self.bytes[self.at..self.at + width];
        self.at += width;
        Ok(taken)
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1, "a U8")?[0])
    }

    pub fn u16(&mut self) -> Result<u16, String> {
        let bytes: [u8; 2] = self.take(2, "a U16")?.try_into().expect("two bytes");
        Ok(u16::from_le_bytes(bytes))
    }

    /// A `U24`, widened to the `u32` it is "commonly deserialized as".
    ///
    /// Three little-endian bytes with an implicit zero above them, per §3.1.
    /// The only one that carries this is `msg_length` in a frame header, and a
    /// 24-bit length is why a frame can be 16MB and a Noise block cannot.
    pub fn u24(&mut self) -> Result<u32, String> {
        let bytes = self.take(3, "a U24")?;
        Ok(u32::from(bytes[0]) | u32::from(bytes[1]) << 8 | u32::from(bytes[2]) << 16)
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        let bytes: [u8; 4] = self.take(4, "a U32")?.try_into().expect("four bytes");
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, String> {
        let bytes: [u8; 8] = self.take(8, "a U64")?.try_into().expect("eight bytes");
        Ok(u64::from_le_bytes(bytes))
    }

    /// An `F32`, which carries a hash rate and nothing else.
    pub fn f32(&mut self) -> Result<f32, String> {
        let bytes: [u8; 4] = self.take(4, "an F32")?.try_into().expect("four bytes");
        Ok(f32::from_le_bytes(bytes))
    }

    /// A `BOOL`: **the low bit, and nothing above it**.
    ///
    /// §3.1 is explicit that a recipient must not interpret the other seven
    /// bits and a sender may set them to anything, so a byte of `0x02` is
    /// `false` and a byte of `0x03` is `true`. Reading this as `byte != 0` is
    /// the obvious implementation and is wrong in exactly the case the spec
    /// reserved the bits for.
    pub fn bool(&mut self) -> Result<bool, String> {
        Ok(self.take(1, "a BOOL")?[0] & 1 == 1)
    }

    /// A `U256`: thirty-two bytes, in the order they arrived.
    pub fn u256(&mut self) -> Result<[u8; 32], String> {
        Ok(self
            .take(32, "a U256")?
            .try_into()
            .expect("thirty-two bytes"))
    }

    /// A length-prefixed byte array, bounded by its own type's maximum.
    pub fn bytes(&mut self, prefix: Prefix) -> Result<&'a [u8], String> {
        let at = self.at;
        let length = match prefix {
            Prefix::Bytes32 => usize::from(self.take(1, "a B0_32 length")?[0]),
            Prefix::Bytes64K => {
                let bytes: [u8; 2] = self
                    .take(2, "a B0_64K length")?
                    .try_into()
                    .expect("two bytes");
                usize::from(u16::from_le_bytes(bytes))
            }
        };

        // **Checked before the bytes are taken, not after.** A `B0_32` whose
        // length byte says 200 would otherwise be refused for running off the
        // end of a short message and accepted in a long one, which is a parser
        // whose strictness depends on what came after the field.
        if length > prefix.max() {
            return Err(format!(
                "a {} at byte {at} claims {length} bytes, and its type allows at most {}",
                prefix.name(),
                prefix.max(),
            ));
        }
        self.take(length, prefix.name())
    }

    /// A `STR0_255`, refused rather than lossily converted when it is not
    /// UTF-8.
    ///
    /// §3.1 calls the field an unconstrained sequence of bytes and only
    /// recommends UTF-8, and the only ones this client reads are error codes
    /// and a hostname — both of which are shown to a person. A
    /// `from_utf8_lossy` would put replacement characters in an error message
    /// and make a malformed frame look like a pool with an unusual error
    /// string.
    pub fn str0_255(&mut self) -> Result<&'a str, String> {
        let at = self.at;
        let length = usize::from(self.take(1, "a STR0_255 length")?[0]);
        let bytes = self.take(length, "a STR0_255")?;
        std::str::from_utf8(bytes)
            .map_err(|error| format!("a STR0_255 at byte {at} is not UTF-8: {error}"))
    }

    /// A `SEQ0_255[U256]`, which is a merkle path and nothing else.
    ///
    /// The count is read first and the entries are taken one at a time, so a
    /// sequence claiming 255 entries with three present fails on the fourth
    /// rather than allocating for 255.
    pub fn seq_u256(&mut self) -> Result<Vec<[u8; 32]>, String> {
        let count = usize::from(self.take(1, "a SEQ0_255 length")?[0]);
        let mut entries = Vec::with_capacity(count.min(self.remaining() / 32));
        for _ in 0..count {
            entries.push(self.u256()?);
        }
        Ok(entries)
    }

    /// An `OPTION[u32]`: a `SEQ0_1[u32]`, so a count byte of 0 or 1.
    ///
    /// **This is the future-job flag.** An empty `min_ntime` is what makes a
    /// `NewExtendedMiningJob` a future job, which cannot be mined until a
    /// `SetNewPrevHash` names it — see [`job`](super::job). A count of 2 is
    /// refused rather than read as one value and some slack, because a pool
    /// that sent it means something this client does not understand.
    pub fn option_u32(&mut self) -> Result<Option<u32>, String> {
        let at = self.at;
        match self.take(1, "an OPTION length")?[0] {
            0 => Ok(None),
            1 => self.u32().map(Some),
            other => Err(format!(
                "an OPTION[u32] at byte {at} has a length of {other}; \
                 it is a SEQ0_1 and may only be 0 or 1"
            )),
        }
    }

    /// Every field consumed and nothing left over, or an error naming both.
    ///
    /// **Not a nicety.** V1 got field names for free from JSON, so a parser
    /// that read the wrong field read a string where it wanted a number and
    /// said so. Here a message is a bare byte sequence, and a parser that is
    /// one field out reads plausible values for everything after it. Trailing
    /// bytes are the symptom, and they are the *only* symptom, so every parse
    /// ends here.
    ///
    /// Consumes the reader, so it cannot be called and then read past.
    pub fn finish(self) -> Result<(), String> {
        if self.remaining() > 0 {
            return Err(format!(
                "the message has {} bytes left over after every field was read \
                 ({} of {} consumed), which means this client read it as a shape it is not",
                self.remaining(),
                self.at,
                self.bytes.len(),
            ));
        }
        Ok(())
    }
}

/// A message payload being built up, field by field, in order.
///
/// The same set as [`Reader`], inverted, and only the types an outgoing
/// message carries: this client sends four messages and none of them holds a
/// `U24`, an `F32` sequence or an `OPTION`.
#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u24(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes()[..3]);
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn f32(&mut self, value: f32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// A `BOOL`, written as the canonical 0 or 1.
    ///
    /// A sender *may* set the other seven bits to anything; this one does not,
    /// because a frame that differs from every other client's for no reason is
    /// a frame a pool may have never parsed before.
    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.bytes.push(u8::from(value));
        self
    }

    pub fn u256(&mut self, value: &[u8; 32]) -> &mut Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// A length-prefixed byte array, refused rather than truncated when it is
    /// too long for its type.
    pub fn bytes(&mut self, prefix: Prefix, value: &[u8]) -> Result<&mut Self, String> {
        if value.len() > prefix.max() {
            return Err(format!(
                "a {} of {} bytes does not fit: its type allows at most {}",
                prefix.name(),
                value.len(),
                prefix.max(),
            ));
        }
        match prefix {
            Prefix::Bytes32 => self.bytes.push(value.len() as u8),
            Prefix::Bytes64K => self
                .bytes
                .extend_from_slice(&(value.len() as u16).to_le_bytes()),
        }
        self.bytes.extend_from_slice(value);
        Ok(self)
    }

    /// A `STR0_255`.
    ///
    /// Refused above 255 bytes rather than truncated, because every string
    /// this client sends is an identity — the worker name, the vendor, the
    /// hostname — and a truncated identity is a different one. **UTF-8 length
    /// in bytes, not characters**: `str::len` is already the byte count, which
    /// is what the prefix counts.
    pub fn str0_255(&mut self, value: &str) -> Result<&mut Self, String> {
        if value.len() > 255 {
            return Err(format!(
                "a STR0_255 of {} bytes does not fit: {value:?}",
                value.len()
            ));
        }
        self.bytes.push(value.len() as u8);
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(self)
    }

    /// The payload, finished.
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// The payload so far, for a test or a length check.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_integer_round_trips_little_endian() {
        let mut writer = Writer::new();
        writer
            .u8(0x12)
            .u16(0x3456)
            .u24(0x9a_bcde)
            .u32(0x1234_5678)
            .u64(0x0123_4567_89ab_cdef);
        let bytes = writer.finish();

        // The byte layout itself, spelled out, because "it round-trips" is
        // also true of a writer and a reader that are wrong the same way. This
        // is the half that says which way round the bytes go.
        assert_eq!(
            bytes,
            vec![
                0x12, // U8
                0x56, 0x34, // U16
                0xde, 0xbc, 0x9a, // U24, three bytes and no fourth
                0x78, 0x56, 0x34, 0x12, // U32
                0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, // U64
            ]
        );

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.u8().unwrap(), 0x12);
        assert_eq!(reader.u16().unwrap(), 0x3456);
        assert_eq!(reader.u24().unwrap(), 0x9a_bcde);
        assert_eq!(reader.u32().unwrap(), 0x1234_5678);
        assert_eq!(reader.u64().unwrap(), 0x0123_4567_89ab_cdef);
        reader.finish().expect("nothing left over");
    }

    #[test]
    fn a_u24_has_no_fourth_byte_in_either_direction() {
        // The one width with no Rust type behind it, so it is the one where a
        // `to_le_bytes` slice could silently be four bytes long.
        let mut writer = Writer::new();
        writer.u24(0xff_ffff);
        assert_eq!(writer.as_slice().len(), 3);
        assert_eq!(writer.as_slice(), &[0xff, 0xff, 0xff]);

        assert_eq!(Reader::new(&[0x00, 0x00, 0x01]).u24().unwrap(), 0x01_0000);
        assert_eq!(Reader::new(&[0x01, 0x00, 0x00]).u24().unwrap(), 1);
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff]).u24().unwrap(), 0xff_ffff);
    }

    #[test]
    fn the_other_seven_bits_of_a_bool_are_not_this_clients_business() {
        // §3.1: a sender may set them to anything and a recipient must not
        // interpret them. `byte != 0` is the obvious reading and is wrong for
        // exactly the values the spec reserved those bits for.
        assert!(!Reader::new(&[0x00]).bool().unwrap());
        assert!(Reader::new(&[0x01]).bool().unwrap());
        assert!(
            !Reader::new(&[0x02]).bool().unwrap(),
            "the low bit is clear, so this is false however the high bits are set"
        );
        assert!(Reader::new(&[0x03]).bool().unwrap());
        assert!(!Reader::new(&[0xfe]).bool().unwrap());
        assert!(Reader::new(&[0xff]).bool().unwrap());

        // And what this client writes is the canonical spelling.
        let mut writer = Writer::new();
        writer.bool(true).bool(false);
        assert_eq!(writer.as_slice(), &[1, 0]);
    }

    #[test]
    fn a_u256_is_not_reversed_in_either_direction() {
        // A V1 prevhash needs `wire::prevhash_from_notify`; a V2 one
        // needs nothing at all, and the difference is invisible until a share
        // is rejected for a header that looks perfectly well formed.
        let mut value = [0u8; 32];
        value[0] = 0xaa;
        value[31] = 0xbb;

        let mut writer = Writer::new();
        writer.u256(&value);
        let bytes = writer.finish();
        assert_eq!(bytes[0], 0xaa, "the first byte stays first");
        assert_eq!(bytes[31], 0xbb, "the last stays last");
        assert_eq!(Reader::new(&bytes).u256().unwrap(), value);
    }

    #[test]
    fn an_f32_round_trips_the_hash_rate_it_carries() {
        for rate in [0.0f32, 1.0, 430e6, f32::MIN_POSITIVE] {
            let mut writer = Writer::new();
            writer.f32(rate);
            assert_eq!(Reader::new(writer.as_slice()).f32().unwrap(), rate);
        }
        // Little-endian IEEE-754, spelled out once so the round trip is not
        // checking a writer against a reader that agree wrongly.
        let mut writer = Writer::new();
        writer.f32(1.0);
        assert_eq!(writer.as_slice(), &[0x00, 0x00, 0x80, 0x3f]);
    }

    #[test]
    fn a_byte_array_round_trips_with_the_length_prefix_its_type_names() {
        let short = [0xdeu8, 0xad, 0xbe, 0xef];
        let long = vec![0x5au8; 1000];

        let mut writer = Writer::new();
        writer.bytes(Prefix::Bytes32, &short).unwrap();
        writer.bytes(Prefix::Bytes64K, &long).unwrap();
        let bytes = writer.finish();

        // One byte of length for B0_32, two little-endian for B0_64K.
        assert_eq!(bytes[0], 4);
        assert_eq!(&bytes[5..7], &[0xe8, 0x03], "1000 as a little-endian u16");

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.bytes(Prefix::Bytes32).unwrap(), &short);
        assert_eq!(reader.bytes(Prefix::Bytes64K).unwrap(), long.as_slice());
        reader.finish().expect("nothing left over");
    }

    #[test]
    fn an_empty_byte_array_is_a_length_and_no_bytes() {
        // `extranonce_prefix` is legitimately empty on a pool that grants the
        // whole extranonce to the client, so this is a real case rather than
        // an edge one.
        let mut writer = Writer::new();
        writer.bytes(Prefix::Bytes32, &[]).unwrap();
        assert_eq!(writer.as_slice(), &[0]);
        assert!(
            Reader::new(&[0]).bytes(Prefix::Bytes32).unwrap().is_empty(),
            "a zero length reads back as no bytes rather than as an error"
        );
    }

    #[test]
    fn a_b0_32_claiming_thirty_three_bytes_is_refused_even_when_they_are_there() {
        // The bound belongs to the type and not to what happens to follow.
        // Thirty-three bytes are present, so a parser that only checked
        // whether the read fits would take them and hand a coinbase splice the
        // server will not reproduce.
        let mut frame = vec![33u8];
        frame.extend_from_slice(&[0x11; 33]);

        let why = Reader::new(&frame)
            .bytes(Prefix::Bytes32)
            .expect_err("33 is past B0_32's maximum");
        assert!(why.contains("B0_32"), "{why}");
        assert!(why.contains("33"), "{why}");
        assert!(why.contains("32"), "the maximum is named: {why}");

        // And 32 exactly is fine, which is what makes the bound a bound.
        let mut exact = vec![32u8];
        exact.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            Reader::new(&exact).bytes(Prefix::Bytes32).unwrap().len(),
            32
        );
    }

    #[test]
    fn a_writer_refuses_an_array_too_long_for_its_type() {
        let mut writer = Writer::new();
        assert!(
            writer.bytes(Prefix::Bytes32, &[0u8; 33]).is_err(),
            "33 bytes is not a B0_32"
        );
        assert!(writer.bytes(Prefix::Bytes32, &[0u8; 32]).is_ok());
        assert!(
            writer.bytes(Prefix::Bytes64K, &vec![0u8; 65_536]).is_err(),
            "65536 bytes is not a B0_64K"
        );
    }

    #[test]
    fn a_sequence_claiming_more_entries_than_it_has_is_refused() {
        // 255 claimed, 3 present. A reader that trusted the
        // count would allocate for 255 and then read past the end of three.
        let mut frame = vec![255u8];
        frame.extend_from_slice(&[0x11; 32]);
        frame.extend_from_slice(&[0x22; 32]);
        frame.extend_from_slice(&[0x33; 32]);

        let why = Reader::new(&frame)
            .seq_u256()
            .expect_err("255 entries are not there");
        assert!(why.contains("U256"), "{why}");

        // The honest version of the same frame.
        let mut honest = vec![3u8];
        honest.extend_from_slice(&frame[1..]);
        let entries = Reader::new(&honest).seq_u256().expect("three entries");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0][0], 0x11);
        assert_eq!(entries[2][31], 0x33);
    }

    #[test]
    fn an_empty_merkle_path_is_a_block_with_only_a_coinbase_in_it() {
        // Every regtest block this repository mines, so this is the common
        // case against a local pool rather than a degenerate one.
        assert!(Reader::new(&[0]).seq_u256().unwrap().is_empty());
    }

    #[test]
    fn an_option_is_a_sequence_of_at_most_one() {
        assert_eq!(Reader::new(&[0]).option_u32().unwrap(), None);
        assert_eq!(
            Reader::new(&[1, 0x78, 0x56, 0x34, 0x12])
                .option_u32()
                .unwrap(),
            Some(0x1234_5678)
        );

        // A count of 2 is a message this client does not understand, and
        // reading it as "one value, plus some slack" would hide that.
        let why = Reader::new(&[2, 0, 0, 0, 0, 0, 0, 0, 0])
            .option_u32()
            .expect_err("an OPTION may hold 0 or 1");
        assert!(why.contains("SEQ0_1"), "{why}");

        // A present option with only three bytes behind it is truncation, not
        // absence.
        assert!(Reader::new(&[1, 0, 0, 0]).option_u32().is_err());
    }

    #[test]
    fn a_truncated_buffer_is_refused_rather_than_read_short() {
        // Per type, because a bounds check written once per method is a bounds
        // check that can be missing from one of them. Every one of these has a
        // value's worth of bytes minus one.
        assert!(Reader::new(&[]).u8().is_err());
        assert!(Reader::new(&[0]).u16().is_err());
        assert!(Reader::new(&[0, 0]).u24().is_err());
        assert!(Reader::new(&[0, 0, 0]).u32().is_err());
        assert!(Reader::new(&[0; 7]).u64().is_err());
        assert!(Reader::new(&[0; 3]).f32().is_err());
        assert!(Reader::new(&[]).bool().is_err());
        assert!(Reader::new(&[0; 31]).u256().is_err());
        assert!(Reader::new(&[4, 1, 2, 3]).bytes(Prefix::Bytes32).is_err());
        assert!(Reader::new(&[1]).bytes(Prefix::Bytes64K).is_err());
        assert!(Reader::new(&[3, b'a']).str0_255().is_err());
        assert!(Reader::new(&[1, 0, 0]).seq_u256().is_err());
        assert!(Reader::new(&[]).option_u32().is_err());
    }

    #[test]
    fn a_failed_read_says_where_it_ran_out() {
        // The offset stands in for the field name this protocol does not
        // carry, and it is what a hex dump of the frame is indexed by.
        let why = Reader::new(&[0u8; 6])
            .u256()
            .expect_err("six bytes is not a U256");
        assert!(why.contains("U256"), "{why}");
        assert!(why.contains("byte 0"), "{why}");
        assert!(why.contains('6'), "the remaining count is in it: {why}");
    }

    #[test]
    fn a_string_round_trips_and_a_non_utf8_one_is_refused() {
        let mut writer = Writer::new();
        writer.str0_255("bc1qexample.puntominer").unwrap();
        writer.str0_255("").unwrap();
        let bytes = writer.finish();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.str0_255().unwrap(), "bc1qexample.puntominer");
        assert_eq!(reader.str0_255().unwrap(), "");
        reader.finish().expect("nothing left over");

        // Lossily converted, this would be an error code with a replacement
        // character in it — a malformed frame wearing a pool's voice.
        let why = Reader::new(&[2, 0xff, 0xfe])
            .str0_255()
            .expect_err("0xfffe is not UTF-8");
        assert!(why.contains("UTF-8"), "{why}");
    }

    #[test]
    fn a_multibyte_string_is_prefixed_by_its_byte_length_and_not_its_characters() {
        // The prefix counts bytes, and `str::len` already does too — but a
        // client that reached for `chars().count()` would write a length two
        // short here and desynchronise every field after it.
        let mut writer = Writer::new();
        writer.str0_255("é€").unwrap();
        assert_eq!(writer.as_slice()[0], 5, "two characters, five bytes");
        assert_eq!(Reader::new(writer.as_slice()).str0_255().unwrap(), "é€");

        assert!(
            Writer::new().str0_255(&"x".repeat(256)).is_err(),
            "256 bytes is not a STR0_255"
        );
        assert!(Writer::new().str0_255(&"x".repeat(255)).is_ok());
    }

    #[test]
    fn finish_is_what_catches_a_message_read_as_the_wrong_shape() {
        // The whole reason this method exists. Both of these are well-formed
        // reads of real numbers; only the leftover bytes say that the second
        // one understood the message as something it is not.
        let frame = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];

        let mut right = Reader::new(&frame);
        right.u32().unwrap();
        right.u32().unwrap();
        right.finish().expect("two U32s is the whole message");

        let mut wrong = Reader::new(&frame);
        wrong.u32().unwrap();
        let why = wrong.finish().expect_err("four bytes are unaccounted for");
        assert!(why.contains('4'), "{why}");
        assert!(why.contains("left over"), "{why}");
    }
}
