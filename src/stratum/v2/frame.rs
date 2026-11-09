//! The six-byte frame header, the message type table, and the one piece of
//! arithmetic the Noise layer cannot do without.
//!
//! Three separate things live here because all three are properties of the
//! *frame* rather than of the cipher or of any message:
//!
//! 1. [`Header`] — `extension_type`, `msg_type`, `msg_length`, and the
//!    `channel_msg` bit that the spec contradicts itself about.
//! 2. The message type numbers from spec §8, pinned as constants so that no
//!    other file spells one inline.
//! 3. [`ct_len`] — plaintext length to ciphertext length. The `msg_length` in
//!    an encrypted frame header is the **plaintext** payload length, so a
//!    reader that took it as a byte count to read off the socket would be
//!    short by one MAC per chunk and then desynchronised forever.
//!
//! No encryption happens here and nothing in this file knows a key exists.
//! That is deliberate: everything below is testable against the spec's own
//! numbers with no handshake, and the layer that *is* hard to test is
//! correspondingly smaller.

/// The `channel_msg` bit: **the most significant bit of `extension_type`**.
///
/// The spec disagrees with itself about this and it is worth recording which
/// reading won, because getting it wrong misframes every channel message.
/// §3.2.1 says "the least significant bit of `extension_type` (i.e., bit 15,
/// 0-indexed, also known as `channel_msg`)", which is self-contradictory —
/// bit 15 of a `u16` is the *most* significant. Two other passages settle it:
///
/// - §3.2, on the payload field: "If the MSB in `extension_type` (the
///   `channel_msg` bit) is set the first four bytes are defined as a U32
///   `channel_id`".
/// - §3.4.1: "an `extension_type` of `0x8ABC` is for the same extension as
///   `0x0ABC`", which is only true if the bit is `0x8000`.
///
/// So `0x8000`, and every mining message this client exchanges carries it
/// except `SetupConnection` and the channel-opening pair.
pub const CHANNEL_MSG: u16 = 0x8000;

/// The frame header on the wire, before any encryption.
pub const HEADER_LEN: usize = 6;

/// And after it: six bytes of plaintext plus a 16-byte MAC, as its own AEAD
/// message.
///
/// **The header is encrypted separately from the payload and consumes its own
/// nonce.** A transport that encrypted header and payload as one
/// AEAD message would produce a frame the same length as this one in the
/// common case, which is exactly why it is worth naming.
pub const ENCRYPTED_HEADER_LEN: usize = HEADER_LEN + MAC_LEN;

/// One Poly1305 tag.
pub const MAC_LEN: usize = 16;

/// The longest Noise transport message, ciphertext included.
pub const MAX_CT_CHUNK: usize = 65_535;

/// And therefore the longest plaintext one chunk may carry.
pub const MAX_PT_CHUNK: usize = MAX_CT_CHUNK - MAC_LEN;

/// The longest payload this client will read from a pool.
///
/// A `U24` allows 16MB and nothing in the mining protocol comes close: a
/// `NewExtendedMiningJob` with two full `B0_64K` coinbase halves and a
/// 255-entry merkle path is about 140KB, and everything else is under a
/// hundred bytes. This exists for the reason V1's `FRAME_MAX` does — a pool
/// is a stranger's server, and a length field is the one thing a peer can use
/// to make a client allocate memory it will never be sent.
pub const PAYLOAD_MAX: usize = 1 << 20;

/// The six bytes every frame starts with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The extension this message belongs to, `channel_msg` bit included.
    ///
    /// Kept as it arrived rather than split into a bit and a number, because
    /// a header that is re-serialised must go back out byte-identical.
    pub extension_type: u16,
    pub msg_type: u8,
    /// The **plaintext** payload length. See [`ct_len`].
    pub length: u32,
}

impl Header {
    pub fn new(extension_type: u16, msg_type: u8, length: u32) -> Self {
        Self {
            extension_type,
            msg_type,
            length,
        }
    }

    /// Parse a header, refusing a payload length this client will not read.
    ///
    /// The length check is here rather than at the socket so that it happens
    /// once, on the one path every frame takes, and before anything has been
    /// allocated on the strength of the number.
    pub fn parse(bytes: [u8; HEADER_LEN]) -> Result<Self, String> {
        let length = u32::from(bytes[3]) | u32::from(bytes[4]) << 8 | u32::from(bytes[5]) << 16;
        if length as usize > PAYLOAD_MAX {
            return Err(format!(
                "the pool announced a {length}-byte payload for message type {:#04x}, \
                 and this client reads at most {PAYLOAD_MAX}",
                bytes[2]
            ));
        }
        Ok(Self {
            extension_type: u16::from_le_bytes([bytes[0], bytes[1]]),
            msg_type: bytes[2],
            length,
        })
    }

    /// The six bytes, little-endian throughout.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let extension = self.extension_type.to_le_bytes();
        let length = self.length.to_le_bytes();
        [
            extension[0],
            extension[1],
            self.msg_type,
            length[0],
            length[1],
            length[2],
        ]
    }

    /// Whether the payload's first four bytes are a `channel_id`.
    pub fn is_channel_msg(self) -> bool {
        self.extension_type & CHANNEL_MSG != 0
    }

    /// The extension number with the `channel_msg` bit taken off.
    ///
    /// §3.4.1: the bit is ignored in the extension lookup, so `0x8ABC` and
    /// `0x0ABC` are the same extension. Everything this client speaks is
    /// extension 0.
    pub fn extension(self) -> u16 {
        self.extension_type & !CHANNEL_MSG
    }
}

/// Plaintext payload length to the number of ciphertext bytes on the wire.
///
/// The spec's own reference implementation (§4.6), transcribed:
///
/// ```c
/// uint pt_len_to_ct_len(uint pt_len) {
///         uint remainder = pt_len % MAX_PT_LEN;
///         if (remainder > 0) remainder += MAC_LEN;
///         return pt_len / MAX_PT_LEN * MAX_CT_LEN + remainder;
/// }
/// ```
///
/// **Why this is a trap:** for every payload a mining
/// session actually sends, this is just `pt_len + 16`, so an implementation
/// that hard-coded that would pass every test anyone thought to write and
/// fail on the first `NewExtendedMiningJob` past 65,519 bytes — which is a
/// large but perfectly ordinary block template. The whole-multiple case is
/// the other edge: a payload of exactly 65,519 bytes is one full chunk with
/// **no** trailing empty one, so it is 65,535 rather than 65,551.
pub fn ct_len(pt_len: usize) -> usize {
    let mut remainder = pt_len % MAX_PT_CHUNK;
    if remainder > 0 {
        remainder += MAC_LEN;
    }
    pt_len / MAX_PT_CHUNK * MAX_CT_CHUNK + remainder
}

/// The message a header names, as spec §8 spells it.
///
/// For the comment column of a `MINER_POOL_CAPTURE` file, which is read by
/// people as well as by tests. A message from an extension, or a number §8
/// does not list, is named by its two numbers rather than guessed at.
pub fn name(header: Header) -> String {
    let known = match (header.extension(), header.msg_type) {
        (0, msg::SETUP_CONNECTION) => "SetupConnection",
        (0, msg::SETUP_CONNECTION_SUCCESS) => "SetupConnection.Success",
        (0, msg::SETUP_CONNECTION_ERROR) => "SetupConnection.Error",
        (0, msg::CHANNEL_ENDPOINT_CHANGED) => "ChannelEndpointChanged",
        (0, msg::RECONNECT) => "Reconnect",
        (0, msg::OPEN_STANDARD_MINING_CHANNEL) => "OpenStandardMiningChannel",
        (0, msg::OPEN_STANDARD_MINING_CHANNEL_SUCCESS) => "OpenStandardMiningChannel.Success",
        (0, msg::OPEN_MINING_CHANNEL_ERROR) => "OpenMiningChannel.Error",
        (0, msg::OPEN_EXTENDED_MINING_CHANNEL) => "OpenExtendedMiningChannel",
        (0, msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS) => "OpenExtendedMiningChannel.Success",
        (0, msg::NEW_MINING_JOB) => "NewMiningJob",
        (0, msg::UPDATE_CHANNEL) => "UpdateChannel",
        (0, msg::UPDATE_CHANNEL_ERROR) => "UpdateChannel.Error",
        (0, msg::CLOSE_CHANNEL) => "CloseChannel",
        (0, msg::SET_EXTRANONCE_PREFIX) => "SetExtranoncePrefix",
        (0, msg::SUBMIT_SHARES_STANDARD) => "SubmitSharesStandard",
        (0, msg::SUBMIT_SHARES_EXTENDED) => "SubmitSharesExtended",
        (0, msg::SUBMIT_SHARES_SUCCESS) => "SubmitShares.Success",
        (0, msg::SUBMIT_SHARES_ERROR) => "SubmitShares.Error",
        (0, msg::NEW_EXTENDED_MINING_JOB) => "NewExtendedMiningJob",
        (0, msg::SET_NEW_PREV_HASH) => "SetNewPrevHash",
        (0, msg::SET_TARGET) => "SetTarget",
        (0, msg::SET_CUSTOM_MINING_JOB) => "SetCustomMiningJob",
        (0, msg::SET_CUSTOM_MINING_JOB_SUCCESS) => "SetCustomMiningJob.Success",
        (0, msg::SET_CUSTOM_MINING_JOB_ERROR) => "SetCustomMiningJob.Error",
        (0, msg::SET_GROUP_CHANNEL) => "SetGroupChannel",
        _ => "",
    };
    if known.is_empty() {
        format!(
            "extension {:#06x} message {:#04x}",
            header.extension(),
            header.msg_type
        )
    } else {
        known.to_string()
    }
}

/// The message type numbers, from spec §8.
///
/// Pinned here so that no other file writes one inline. Two of them are in
/// this table for their own sake rather than because this client sends them:
/// [`msg::NEW_MINING_JOB`] and [`msg::RESERVED`] are where a reader who
/// extrapolates from the numbers around them goes wrong, and the test below
/// is the record that they were looked up rather than guessed.
pub mod msg {
    // Common protocol, §3.6. None of these carry `channel_msg`.
    pub const SETUP_CONNECTION: u8 = 0x00;
    pub const SETUP_CONNECTION_SUCCESS: u8 = 0x01;
    pub const SETUP_CONNECTION_ERROR: u8 = 0x02;
    /// Carries `channel_msg`, unlike the rest of the common protocol.
    pub const CHANNEL_ENDPOINT_CHANGED: u8 = 0x03;
    pub const RECONNECT: u8 = 0x04;

    // Mining protocol, §5.3. Standard-channel messages are listed because
    // receiving one is a pool that misunderstood this client's channel
    // request, which is worth naming rather than logging as a number.
    pub const OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
    pub const OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
    pub const OPEN_MINING_CHANNEL_ERROR: u8 = 0x12;
    pub const OPEN_EXTENDED_MINING_CHANNEL: u8 = 0x13;
    pub const OPEN_EXTENDED_MINING_CHANNEL_SUCCESS: u8 = 0x14;
    /// **`0x15`, not `0x1e`.** The standard-channel job message sits a long
    /// way from its extended counterpart at `0x1f`.
    pub const NEW_MINING_JOB: u8 = 0x15;
    pub const UPDATE_CHANNEL: u8 = 0x16;
    pub const UPDATE_CHANNEL_ERROR: u8 = 0x17;
    pub const CLOSE_CHANNEL: u8 = 0x18;
    pub const SET_EXTRANONCE_PREFIX: u8 = 0x19;
    pub const SUBMIT_SHARES_STANDARD: u8 = 0x1a;
    pub const SUBMIT_SHARES_EXTENDED: u8 = 0x1b;
    pub const SUBMIT_SHARES_SUCCESS: u8 = 0x1c;
    pub const SUBMIT_SHARES_ERROR: u8 = 0x1d;
    /// **Reserved, and therefore not a message.** The one gap in the range,
    /// and the number a reader extrapolating from `SubmitShares.Error` would
    /// put `NewExtendedMiningJob` at.
    pub const RESERVED: u8 = 0x1e;
    pub const NEW_EXTENDED_MINING_JOB: u8 = 0x1f;
    pub const SET_NEW_PREV_HASH: u8 = 0x20;
    pub const SET_TARGET: u8 = 0x21;
    pub const SET_CUSTOM_MINING_JOB: u8 = 0x22;
    pub const SET_CUSTOM_MINING_JOB_SUCCESS: u8 = 0x23;
    pub const SET_CUSTOM_MINING_JOB_ERROR: u8 = 0x24;
    pub const SET_GROUP_CHANNEL: u8 = 0x25;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_channel_msg_bit_is_the_most_significant_one() {
        // The only test in this file that would have caught the
        // spec's own contradictory sentence. Read as the least significant
        // bit, `channel_msg` would be `0x0001` — and `0x8000` and `0x0001`
        // disagree about every frame.
        assert_eq!(CHANNEL_MSG, 0x8000);
        assert_ne!(CHANNEL_MSG, 0x0001, "§3.2.1's literal reading is wrong");

        let channel = Header::new(CHANNEL_MSG, msg::NEW_EXTENDED_MINING_JOB, 100);
        assert!(channel.is_channel_msg());
        assert_eq!(channel.extension(), 0);

        let common = Header::new(0, msg::SETUP_CONNECTION, 50);
        assert!(!common.is_channel_msg());
        assert_eq!(common.extension(), 0);

        // §3.4.1's own example: the bit is ignored in the extension lookup.
        assert_eq!(
            Header::new(0x8abc, 0, 0).extension(),
            Header::new(0x0abc, 0, 0).extension(),
        );
    }

    #[test]
    fn a_header_round_trips_byte_for_byte() {
        // Little-endian throughout, including the U24 length, and spelled out
        // once so the round trip is not two mistakes agreeing.
        let header = Header::new(0x8000, 0x1f, 0x01_2345);
        assert_eq!(header.to_bytes(), [0x00, 0x80, 0x1f, 0x45, 0x23, 0x01]);
        assert_eq!(Header::parse(header.to_bytes()).unwrap(), header);

        for bytes in [
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0xff, 0x7f, 0xff, 0xff, 0xff, 0x00],
            [0x00, 0x80, 0x21, 0x24, 0x00, 0x00],
        ] {
            assert_eq!(Header::parse(bytes).unwrap().to_bytes(), bytes);
        }
    }

    #[test]
    fn a_payload_longer_than_this_client_reads_is_refused_at_the_header() {
        // A `U24` allows 16MB. Refusing it here is refusing it before
        // anything has been allocated on the strength of the number.
        let too_long = ((PAYLOAD_MAX + 1) as u32).to_le_bytes();
        let why = Header::parse([0x00, 0x80, 0x1f, too_long[0], too_long[1], too_long[2]])
            .expect_err("a 1MB+1 payload is refused");
        assert!(why.contains("1048577"), "{why}");

        // And the bound itself is accepted, which is what makes it a bound.
        let exact = (PAYLOAD_MAX as u32).to_le_bytes();
        assert!(Header::parse([0x00, 0x80, 0x1f, exact[0], exact[1], exact[2]]).is_ok());
    }

    #[test]
    fn the_message_types_are_the_ones_the_spec_names() {
        // Looked up rather than extrapolated. The two that matter are
        // `NewMiningJob` and the gap, because the numbers around them make a
        // wrong guess look reasonable.
        assert_eq!(msg::NEW_MINING_JOB, 0x15);
        assert_eq!(msg::RESERVED, 0x1e);
        assert_eq!(msg::NEW_EXTENDED_MINING_JOB, 0x1f);
        assert_ne!(
            msg::NEW_EXTENDED_MINING_JOB,
            msg::RESERVED,
            "0x1e is the hole in the table, not the extended job"
        );

        // The four this client sends and the eight it acts on, so a typo in
        // any of them is a failing test rather than a pool that hangs up.
        assert_eq!(msg::SETUP_CONNECTION, 0x00);
        assert_eq!(msg::SETUP_CONNECTION_SUCCESS, 0x01);
        assert_eq!(msg::SETUP_CONNECTION_ERROR, 0x02);
        assert_eq!(msg::RECONNECT, 0x04);
        assert_eq!(msg::OPEN_MINING_CHANNEL_ERROR, 0x12);
        assert_eq!(msg::OPEN_EXTENDED_MINING_CHANNEL, 0x13);
        assert_eq!(msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, 0x14);
        assert_eq!(msg::UPDATE_CHANNEL, 0x16);
        assert_eq!(msg::UPDATE_CHANNEL_ERROR, 0x17);
        assert_eq!(msg::SET_EXTRANONCE_PREFIX, 0x19);
        assert_eq!(msg::SUBMIT_SHARES_EXTENDED, 0x1b);
        assert_eq!(msg::SUBMIT_SHARES_SUCCESS, 0x1c);
        assert_eq!(msg::SUBMIT_SHARES_ERROR, 0x1d);
        assert_eq!(msg::SET_NEW_PREV_HASH, 0x20);
        assert_eq!(msg::SET_TARGET, 0x21);
    }

    #[test]
    fn the_plaintext_to_ciphertext_length_matches_the_specs_own_c() {
        // The chunking boundaries. The first three are the
        // only cases a mining session reaches, and they are also the three
        // that a hard-coded `pt_len + 16` would get right — which is why the
        // last three are here.
        assert_eq!(ct_len(0), 0, "no payload is no ciphertext, not a bare MAC");
        assert_eq!(ct_len(1), 17);
        assert_eq!(ct_len(100), 116);
        assert_eq!(ct_len(65_518), 65_534);
        assert_eq!(
            ct_len(65_519),
            65_535,
            "one full chunk, with no trailing empty one"
        );
        assert_eq!(
            ct_len(65_520),
            65_552,
            "a full chunk plus one byte and a MAC"
        );
        assert_eq!(ct_len(131_038), 131_070, "exactly two full chunks");
        assert_eq!(ct_len(131_039), 131_087);

        // And the property the constant-per-chunk overhead implies, checked
        // across the first two chunk boundaries rather than at them.
        for pt in [
            0usize, 1, 16, 1000, 65_518, 65_519, 65_520, 131_038, 200_000,
        ] {
            let chunks = pt.div_ceil(MAX_PT_CHUNK);
            assert_eq!(
                ct_len(pt),
                pt + chunks * MAC_LEN,
                "{pt} bytes is {chunks} chunk(s), so {chunks} MAC(s)"
            );
        }
    }

    #[test]
    fn an_encrypted_header_is_twenty_two_bytes() {
        // The header is its own AEAD message, so it carries its own
        // MAC and consumes its own nonce.
        assert_eq!(HEADER_LEN, 6);
        assert_eq!(ENCRYPTED_HEADER_LEN, 22);
        assert_eq!(ct_len(HEADER_LEN), ENCRYPTED_HEADER_LEN);
    }
}
