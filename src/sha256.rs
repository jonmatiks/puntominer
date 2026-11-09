//! SHA-256 for block headers: a portable compression function, an x86 SHA-NI
//! one, and the midstate arrangement both use.
//!
//! The naive baseline — `rust-bitcoin`'s `block_hash()`, re-serializing all 80
//! bytes and running three compressions per nonce — measured at 5.46 MH/s per
//! core, or about 305 cycles per compression. This machine has `sha_ni`, which
//! does one in roughly 65 to 75, so that baseline was leaving most of the CPU
//! on the table and every later comparison against a GPU would have been
//! unfair.
//!
//! Two things are wrong with the naive path and they are separable:
//!
//! - **No midstate.** The first 64 bytes of an 80-byte header do not depend on
//!   the nonce, so their compression can be hoisted out of the loop. That takes
//!   the per-nonce cost from three compressions to two.
//! - **Software SHA-256.** The compression function itself.
//!
//! So there are two backends over one [`HeaderHasher`], and both are measured.
//! Anything else would report the sum of two changes as if it were one.

use bitcoin::{block::Header, hashes::Hash};

/// SHA-256 initial hash values, the first 32 bits of the fractional parts of
/// the square roots of the first eight primes.
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants.
///
/// A `static` rather than a `const` deliberately: the SHA-NI path loads four
/// of these at a time straight out of memory, and a `const` is a value that
/// each use materializes afresh — which put a 256-byte stack copy inside the
/// hot loop sixteen times per compression.
#[rustfmt::skip]
pub(crate) static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Which compression function a hasher uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The portable implementation, which runs anywhere.
    Portable,
    /// x86 SHA extensions. Only ever selected when the CPU reports them.
    ShaNi,
}

impl Backend {
    /// The best backend this CPU can run.
    ///
    /// The check is a runtime one: a binary built on this laptop must still
    /// run on a machine without the extensions, and the M1 in the README has
    /// none of them.
    pub fn detect() -> Self {
        if sha_ni_available() {
            Self::ShaNi
        } else {
            Self::Portable
        }
    }

    /// Parse an explicit choice, rejecting SHA-NI where it cannot run rather
    /// than quietly measuring the portable path under its name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::detect()),
            "portable" => Ok(Self::Portable),
            "sha-ni" | "shani" => {
                if sha_ni_available() {
                    Ok(Self::ShaNi)
                } else {
                    Err("this CPU does not support the x86 SHA extensions".into())
                }
            }
            _ => Err(format!(
                "the hasher must be auto, portable or sha-ni, got {value}"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::ShaNi => "sha-ni",
        }
    }
}

/// Whether this CPU can run the SHA-NI path, including the SSE levels the
/// implementation needs alongside the SHA instructions themselves.
pub fn sha_ni_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("sse2")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse4.1")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Hashes one header's nonce space, reusing everything that does not depend on
/// the nonce.
///
/// The split is fixed by the header's 80-byte length:
///
/// ```text
/// block 0  version | prev_hash | merkle_root[0..28]   compressed once, in `new`
/// block 1  merkle_root[28..32] | time | bits | nonce  compressed per nonce
/// block 2  first digest, padded                       compressed per nonce
/// ```
///
/// Only four bytes of block 1 change between nonces, but SHA-256 has no
/// structure to exploit below a block, so the whole of block 1 is recompressed.
pub struct HeaderHasher {
    backend: Backend,
    /// State after block 0, which no nonce can affect.
    midstate: [u32; 8],
    /// Block 1, already padded, with the nonce at bytes 12 to 16.
    tail: [u8; 64],
    /// Block 1 as schedule words, for [`HeaderHasher::screen`]'s portable path.
    tail_words: [u32; 16],
    /// Rounds 0 to 2 of block 1, which every nonce shares.
    prefix: Prefix,
    /// The SHA-NI form of the same thing, packed: the midstate as `ABEF` and
    /// `CDGH`, and `ABEF` after rounds 0 and 1. Zero on the portable backend.
    packed: [[u32; 4]; 3],
}

/// What every nonce under one header shares of block 1's compression.
///
/// Block 1's schedule words are the merkle root's last four bytes, nTime,
/// nBits, the nonce, then padding. Rounds 0 to 2 read only the first three, so
/// the state after them is the same for every nonce; round 3 is the first to
/// read the nonce, and everything it adds besides that word is fixed too.
#[derive(Clone, Copy, Debug)]
struct Prefix {
    /// The state after round 2.
    state: [u32; 8],
    /// Round 3's `temp1` less its schedule word, the nonce.
    temp1: u32,
    /// Round 3's `temp2`, which reads only the state.
    temp2: u32,
}

impl Prefix {
    fn new(midstate: &[u32; 8], tail: &[u32; 16]) -> Self {
        let mut w = [0u32; 64];
        w[..3].copy_from_slice(&tail[..3]);
        let state = rounds(*midstate, &w, 0..3);

        let [a, b, c, _, e, f, g, h] = state;
        Self {
            state,
            temp1: h
                .wrapping_add(big_sigma1(e))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[3]),
            temp2: big_sigma0(a).wrapping_add((a & b) ^ (a & c) ^ (b & c)),
        }
    }
}

impl HeaderHasher {
    pub fn new(header: &Header, backend: Backend) -> Self {
        let bytes = serialize_header(header);

        let mut midstate = IV;
        let mut block = [0u8; 64];
        block.copy_from_slice(&bytes[..64]);
        compress(backend, &mut midstate, &block);

        // The padding for an 80-byte message: the terminator, then the length
        // in bits, 640, as a big-endian u64 in the last eight bytes.
        let mut tail = [0u8; 64];
        tail[..16].copy_from_slice(&bytes[64..]);
        tail[16] = 0x80;
        tail[62] = 0x02;
        tail[63] = 0x80;

        let tail_words = schedule_words(&tail);
        let prefix = Prefix::new(&midstate, &tail_words);

        #[cfg(target_arch = "x86_64")]
        let packed = if backend == Backend::ShaNi {
            // Safety: `Backend::ShaNi` is only constructed after
            // `sha_ni_available` confirmed every instruction set this uses.
            unsafe { sha_ni_prefix(&midstate, &tail) }
        } else {
            [[0; 4]; 3]
        };
        #[cfg(not(target_arch = "x86_64"))]
        let packed = [[0; 4]; 3];

        Self {
            backend,
            midstate,
            tail,
            tail_words,
            prefix,
            packed,
        }
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    /// The double-SHA256 of the header with this nonce, as the eight state
    /// words in SHA-256 order.
    ///
    /// The words rather than bytes, because [`meets_target`] wants them that
    /// way and converting to a byte array on the hot path would be a copy for
    /// nothing.
    pub fn hash(&self, nonce: u32) -> [u32; 8] {
        let mut tail = self.tail;
        tail[12..16].copy_from_slice(&nonce.to_le_bytes());

        #[cfg(target_arch = "x86_64")]
        if self.backend == Backend::ShaNi {
            // Safety: `Backend::ShaNi` is only constructed after
            // `sha_ni_available` confirmed every instruction set this uses.
            return unsafe { sha256d_header_sha_ni(&self.midstate, &tail) };
        }

        let mut first = self.midstate;
        compress(self.backend, &mut first, &tail);

        // The second hash is over a fixed-length 32-byte message, so its
        // padding block is a constant apart from the digest itself: the
        // terminator at byte 32 and a bit length of 256 at the end.
        let mut block = [0u8; 64];
        for (index, word) in first.iter().enumerate() {
            block[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        block[32] = 0x80;
        block[62] = 0x01;

        let mut second = IV;
        compress(self.backend, &mut second, &block);
        second
    }

    /// The digest as the 32 bytes `rust-bitcoin` would produce, for comparing
    /// against a `BlockHash`.
    pub fn hash_bytes(&self, nonce: u32) -> [u8; 32] {
        digest_bytes(&self.hash(nonce))
    }

    /// Exactly `(meets_target(&self.hash(nonce), target),
    /// best_rank(&self.hash(nonce)))`, computing as little of the digest as
    /// that answer needs.
    ///
    /// **Word seven decides almost every nonce.** It is the value's top 32
    /// bits, and it is final after round 60 of the second pass, three rounds
    /// before the end: `h` after round 63 is `e` after round 60. The target
    /// comparison reads further words only on a tie in that one, and the rank
    /// only when it is zero, so those two cases — about one nonce in 2³² —
    /// go through the full [`HeaderHasher::hash`] instead. That keeps `hash`
    /// the whole digest and this a shortcut beside it, which is what lets the
    /// probe and the tests hold one against the other.
    pub fn screen(&self, nonce: u32, target: &[u32; 8]) -> (bool, u32) {
        let high = self.word7(nonce).swap_bytes();
        if high == 0 || high == target[0] {
            let state = self.hash(nonce);
            return (meets_target(&state, target), best_rank(&state));
        }
        (high < target[0], rank_of_high(high))
    }

    /// Exactly `[self.screen(first, target), self.screen(first + 1, target),
    /// ...]` for `N` consecutive nonces, wrapping at `u32::MAX`.
    ///
    /// On SHA-NI the lanes' word sevens are computed together, which is the
    /// whole point: a single nonce's rounds are a chain of dependent
    /// instructions, and `N` chains fill each other's waits. Each lane is then
    /// decided exactly as [`HeaderHasher::screen`] decides a nonce, the tie
    /// and the zero word going through the full [`HeaderHasher::hash`] of that
    /// lane's own nonce. Every other backend is a loop over `screen`.
    pub fn screen_lanes<const N: usize>(&self, first: u32, target: &[u32; 8]) -> [(bool, u32); N] {
        #[cfg(target_arch = "x86_64")]
        if self.backend == Backend::ShaNi {
            // Safety: `Backend::ShaNi` is only constructed after
            // `sha_ni_available` confirmed every instruction set this uses.
            let words = unsafe { word7_sha_ni_lanes::<N>(&self.packed, &self.tail, first) };
            let mut verdicts = [(false, 0); N];
            for (lane, (verdict, word)) in verdicts.iter_mut().zip(words).enumerate() {
                let high = word.swap_bytes();
                *verdict = if high == 0 || high == target[0] {
                    let state = self.hash(first.wrapping_add(lane as u32));
                    (meets_target(&state, target), best_rank(&state))
                } else {
                    (high < target[0], rank_of_high(high))
                };
            }
            return verdicts;
        }

        std::array::from_fn(|lane| self.screen(first.wrapping_add(lane as u32), target))
    }

    /// State word seven of the double hash, and nothing else of it.
    fn word7(&self, nonce: u32) -> u32 {
        #[cfg(target_arch = "x86_64")]
        if self.backend == Backend::ShaNi {
            let mut tail = self.tail;
            tail[12..16].copy_from_slice(&nonce.to_le_bytes());
            // Safety: `Backend::ShaNi` is only constructed after
            // `sha_ni_available` confirmed every instruction set this uses.
            return unsafe { word7_sha_ni(&self.packed, &tail) };
        }

        word7_portable(&self.midstate, &self.prefix, &self.tail_words, nonce)
    }
}

/// [`HeaderHasher::screen`]'s word seven, the textbook way.
///
/// The reference the SHA-NI path is checked against, as [`compress_portable`]
/// is for [`compress_sha_ni`]: block 1 from round 3, continuing from the
/// shared [`Prefix`], then the second pass to round 60.
fn word7_portable(midstate: &[u32; 8], prefix: &Prefix, tail: &[u32; 16], nonce: u32) -> u32 {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(tail);
    // The nonce is little-endian in the header, so as a big-endian schedule
    // word it is byte-reversed.
    w[3] = nonce.swap_bytes();
    extend_schedule(&mut w, 64);

    // Round 3, where the nonce first enters: everything else was added once.
    let [a, b, c, d, e, f, g, _] = prefix.state;
    let temp1 = prefix.temp1.wrapping_add(w[3]);
    let state = [
        temp1.wrapping_add(prefix.temp2),
        a,
        b,
        c,
        d.wrapping_add(temp1),
        e,
        f,
        g,
    ];

    let state = rounds(state, &w, 4..64);
    let mut first = *midstate;
    for (word, add) in first.iter_mut().zip(state) {
        *word = word.wrapping_add(add);
    }

    // The second pass, to round 60 and no further: its `e` is the final `h`.
    let mut w = [0u32; 64];
    w[..8].copy_from_slice(&first);
    w[8] = 0x8000_0000;
    w[15] = 256;
    extend_schedule(&mut w, 61);
    IV[7].wrapping_add(rounds(IV, &w, 0..61)[4])
}

/// The textbook rounds over `range`, from `state`, on an already extended
/// schedule.
fn rounds(state: [u32; 8], w: &[u32; 64], range: std::ops::Range<usize>) -> [u32; 8] {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for index in range {
        let temp1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(K[index])
            .wrapping_add(w[index]);
        let temp2 = big_sigma0(a).wrapping_add((a & b) ^ (a & c) ^ (b & c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    [a, b, c, d, e, f, g, h]
}

/// Fill schedule words 16 up to `end`, from the sixteen already there.
fn extend_schedule(w: &mut [u32; 64], end: usize) {
    for index in 16..end {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }
}

fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// A 64-byte block as its sixteen big-endian schedule words.
fn schedule_words(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (word, chunk) in words.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*chunk);
    }
    words
}

/// A header prepared for the GPU: everything nonce-independent, already done.
///
/// The same split [`HeaderHasher`] uses, but handed over as words rather than
/// bytes, because the shader's message schedule is defined over big-endian
/// words and converting them on the device would be work repeated per nonce
/// that the host can do once per merkle root.
#[derive(Clone, Copy, Debug)]
pub struct GpuHeader {
    /// State after the header's first 64 bytes.
    pub midstate: [u32; 8],
    /// The header's final block, padded. Word 3 is the nonce and is
    /// overwritten by the shader.
    pub tail: [u32; 16],
}

impl GpuHeader {
    pub fn new(header: &Header) -> Self {
        // Either backend produces the same midstate; this is not on any hot
        // path, being once per merkle root rather than once per nonce.
        let hasher = HeaderHasher::new(header, Backend::detect());

        Self {
            midstate: hasher.midstate,
            tail: hasher.tail_words,
        }
    }
}

/// The same header search, over the `sha2` crate from RustCrypto.
///
/// `sha2` has its own runtime-detected x86 SHA-NI backend, so this measures a
/// maintained library's version of the thing `compress_sha_ni` does by hand.
/// It is the fair question to ask of that hand-written code: whether writing it
/// bought anything a dependency would not have.
///
/// The midstate trick survives the public API. `compress256` exists in the
/// crate but its module is private in 0.11, so instead the engine is fed the
/// header's first 64 bytes once and **cloned** per nonce — which is the same
/// hoist, expressed the way an application would have to express it.
pub struct RustCryptoHasher {
    /// An engine that has already absorbed the nonce-independent 64 bytes.
    base: sha2::Sha256,
    /// The header's last 16 bytes, with the nonce at bytes 12 to 16.
    tail: [u8; 16],
}

impl RustCryptoHasher {
    pub fn new(header: &Header) -> Self {
        use sha2::Digest;

        let bytes = serialize_header(header);
        let mut base = sha2::Sha256::new();
        base.update(&bytes[..64]);

        let mut tail = [0u8; 16];
        tail.copy_from_slice(&bytes[64..]);

        Self { base, tail }
    }

    pub fn hash(&self, nonce: u32) -> [u32; 8] {
        use sha2::Digest;

        let mut tail = self.tail;
        tail[12..16].copy_from_slice(&nonce.to_le_bytes());

        // The clone carries the absorbed state; `finalize` adds the padding
        // this module writes by hand in the midstate path.
        let mut engine = self.base.clone();
        engine.update(tail);
        let first = engine.finalize();

        digest_words(&sha2::Sha256::digest(first))
    }
}

/// The `sha2` crate used the obvious way: hash all 80 bytes, twice, per nonce.
///
/// The direct analogue of the `naive` hasher, and there so that library quality
/// and midstate reuse can be told apart rather than reported as one number.
pub struct RustCryptoPlainHasher {
    header: [u8; 80],
}

impl RustCryptoPlainHasher {
    pub fn new(header: &Header) -> Self {
        Self {
            header: serialize_header(header),
        }
    }

    pub fn hash(&self, nonce: u32) -> [u32; 8] {
        use sha2::Digest;

        let mut header = self.header;
        header[76..80].copy_from_slice(&nonce.to_le_bytes());

        digest_words(&sha2::Sha256::digest(sha2::Sha256::digest(header)))
    }
}

/// A 32-byte digest as the eight state words [`meets_target`] compares.
///
/// Eight byte-swaps against roughly 450 cycles of hashing, so this is under a
/// percent and does not distort the comparison — but it is real, and the
/// hand-written path does not pay it because it never leaves word form.
pub fn digest_words(digest: &[u8]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u32::from_be_bytes([
            digest[index * 4],
            digest[index * 4 + 1],
            digest[index * 4 + 2],
            digest[index * 4 + 3],
        ]);
    }
    words
}

/// How many consecutive nonces a CPU search hands [`NonceHasher::screen_lanes`]
/// at once.
///
/// A power of two, so that it divides both the nonce space and the searches'
/// stop-check interval: a worker still looks up once per 65,536 nonces.
pub const LANES: usize = 2;

/// Every way of hashing a header's nonce space that this project can measure.
pub enum NonceHasher {
    /// This module's midstate hasher, portable or SHA-NI.
    Midstate(HeaderHasher),
    /// `sha2` with the midstate hoisted out by cloning the engine.
    RustCrypto(RustCryptoHasher),
    /// `sha2` with no midstate at all.
    RustCryptoPlain(RustCryptoPlainHasher),
}

impl NonceHasher {
    pub fn hash(&self, nonce: u32) -> [u32; 8] {
        match self {
            Self::Midstate(hasher) => hasher.hash(nonce),
            Self::RustCrypto(hasher) => hasher.hash(nonce),
            Self::RustCryptoPlain(hasher) => hasher.hash(nonce),
        }
    }

    /// Whether the nonce meets the target, and its rank: the two things a
    /// search reads per nonce. Only the midstate hasher shortens the work;
    /// the `sha2` ones hash in full, so they keep measuring what the original
    /// hasher comparison measured.
    pub fn screen(&self, nonce: u32, target: &[u32; 8]) -> (bool, u32) {
        match self {
            Self::Midstate(hasher) => hasher.screen(nonce, target),
            _ => {
                let state = self.hash(nonce);
                (meets_target(&state, target), best_rank(&state))
            }
        }
    }

    /// [`NonceHasher::screen`] for the `N` nonces from `first`, wrapping at
    /// `u32::MAX`: exactly what `screen` returns for each, in order. Only the
    /// midstate hasher on SHA-NI computes them together; every other hasher is
    /// a loop over its own `screen`.
    pub fn screen_lanes<const N: usize>(&self, first: u32, target: &[u32; 8]) -> [(bool, u32); N] {
        match self {
            Self::Midstate(hasher) => hasher.screen_lanes(first, target),
            _ => std::array::from_fn(|lane| self.screen(first.wrapping_add(lane as u32), target)),
        }
    }
}

/// Serialize a header the way consensus does: 80 bytes, little-endian scalars,
/// hashes in internal byte order.
fn serialize_header(header: &Header) -> [u8; 80] {
    let mut bytes = [0u8; 80];
    bytes[0..4].copy_from_slice(&header.version.to_consensus().to_le_bytes());
    bytes[4..36].copy_from_slice(&header.prev_blockhash.to_byte_array());
    bytes[36..68].copy_from_slice(&header.merkle_root.to_byte_array());
    bytes[68..72].copy_from_slice(&header.time.to_le_bytes());
    bytes[72..76].copy_from_slice(&header.bits.to_consensus().to_le_bytes());
    bytes[76..80].copy_from_slice(&header.nonce.to_le_bytes());
    bytes
}

/// The eight state words as the digest's 32 bytes.
pub fn digest_bytes(state: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

/// A target as eight words, most significant first, ready for [`meets_target`].
pub fn target_words(target: bitcoin::Target) -> [u32; 8] {
    let bytes = target.to_be_bytes();
    let mut words = [0u32; 8];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u32::from_be_bytes([
            bytes[index * 4],
            bytes[index * 4 + 1],
            bytes[index * 4 + 2],
            bytes[index * 4 + 3],
        ]);
    }
    words
}

/// Whether a digest is at or below the target.
///
/// Bitcoin reads the 32 digest bytes as a **little-endian** number, so the
/// most significant byte of the value is the last byte of the digest — the low
/// byte of state word seven. That is why this walks the state backwards and
/// byte-swaps: word seven reversed is the top 32 bits of the number.
///
/// The first comparison decides almost every call, since a real target has
/// leading zero words and a random digest does not.
pub fn meets_target(state: &[u32; 8], target: &[u32; 8]) -> bool {
    for (index, target_word) in target.iter().enumerate() {
        let digest_word = state[7 - index].swap_bytes();
        if digest_word < *target_word {
            return true;
        }
        if digest_word > *target_word {
            return false;
        }
    }
    // Exactly equal to the target still meets it.
    true
}

/// A digest's rank as one comparable number, smaller being the better hash.
///
/// The counterpart of [`meets_target`] for the question a target cannot answer:
/// not "is this a block" but "how close did this come". A search that wants the
/// best hash it saw has to look at every digest, so this has to be cheap enough
/// to sit in the hot loop beside the target check — one branch and two shifts,
/// against the 128 rounds that produced the digest.
///
/// **What it encodes.** The top 64 bits of the value, in one `u32`, ordered:
/// the high word when it is non-zero, tagged into the upper half of the range,
/// and the next word when it is zero. So every digest worth less than
/// difficulty 1 sorts above every digest worth more, and within each half the
/// order is the numeric one. The bottom bit of each word is dropped to make
/// room for the tag, which costs a tie every four billion digests and nothing
/// else.
///
/// **It ranks; it does not measure.** The number that gets reported comes from
/// hashing the winning nonce again through `rust-bitcoin` — see
/// [`crate::block::difficulty_of_hash`] — because a rank that is one bit coarse
/// is fine for choosing between two hashes and is not fine as a claim about
/// either. `miner.wgsl` carries the same encoding so that the CPU and the GPU
/// rank a digest identically, which is what lets the probe compare them.
pub fn best_rank(state: &[u32; 8]) -> u32 {
    // The same reading `meets_target` walks: the value's most significant word
    // is the last state word, byte-reversed.
    let high = state[7].swap_bytes();
    if high != 0 {
        return rank_of_high(high);
    }
    state[6].swap_bytes() >> 1
}

/// The rank of a digest whose top word, `high`, is non-zero: everything
/// [`best_rank`] needs in that case, which is why [`HeaderHasher::screen`] can
/// rank from word seven alone.
fn rank_of_high(high: u32) -> u32 {
    0x8000_0000 | (high >> 1)
}

fn compress(backend: Backend, state: &mut [u32; 8], block: &[u8; 64]) {
    match backend {
        Backend::Portable => compress_portable(state, block),
        Backend::ShaNi => {
            #[cfg(target_arch = "x86_64")]
            {
                // Safety: `Backend::ShaNi` is only ever constructed after
                // `sha_ni_available` confirmed every instruction set this uses.
                unsafe { compress_sha_ni(state, block) }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                unreachable!("the SHA-NI backend cannot be selected off x86_64")
            }
        }
    }
}

/// The textbook SHA-256 compression function.
///
/// Kept obvious rather than fast: it is the reference the SHA-NI path is
/// checked against, and the measurement of what the hardware instruction is
/// worth is only meaningful if this is an ordinary implementation.
fn compress_portable(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (index, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[index] = u32::from_be_bytes(*chunk);
    }
    for index in 16..64 {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(choose)
            .wrapping_add(K[index])
            .wrapping_add(w[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// The 64-round SHA-256 core, over message registers that already hold
/// big-endian schedule words.
///
/// Factored into a macro because there are two callers that must run the
/// identical sequence: [`compress_sha_ni`], which loads its message from
/// memory, and [`sha256d_header_sha_ni`], which for the second hash has the
/// message sitting in registers already and must not spill it to memory to
/// get at it.
///
/// `state0` and `state1` must be in ABEF/CDGH form on entry and are left
/// there, with the saved state already added back.
#[cfg(target_arch = "x86_64")]
macro_rules! sha_ni_rounds {
    ($state0:ident, $state1:ident, $msg0:ident, $msg1:ident, $msg2:ident, $msg3:ident) => {{
        let abef_save = $state0;
        let cdgh_save = $state1;
        let mut msg;

        // Rounds 0 to 3.
        msg = _mm_add_epi32($msg0, round_constants(0));
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);

        sha_ni_rounds_4_to_59!($state0, $state1, $msg0, $msg1, $msg2, $msg3);

        // Rounds 60 to 63, with no schedule left to extend.
        msg = _mm_add_epi32($msg3, round_constants(60));
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);

        $state0 = _mm_add_epi32($state0, abef_save);
        $state1 = _mm_add_epi32($state1, cdgh_save);
    }};
}

/// Rounds 4 to 59: every group that extends the message schedule.
///
/// Split out of [`sha_ni_rounds`] so that [`word7_sha_ni`], which starts its
/// first pass at round 2 and ends its second at round 61, expands exactly the
/// same schedule work as the full compression rather than a copy of it.
#[cfg(target_arch = "x86_64")]
macro_rules! sha_ni_rounds_4_to_59 {
    ($state0:ident, $state1:ident, $msg0:ident, $msg1:ident, $msg2:ident, $msg3:ident) => {{
        let mut msg;
        let mut carry;

        // Rounds 4 to 7.
        msg = _mm_add_epi32($msg1, round_constants(4));
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
        $msg0 = _mm_sha256msg1_epu32($msg0, $msg1);

        // Rounds 8 to 11.
        msg = _mm_add_epi32($msg2, round_constants(8));
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
        $msg1 = _mm_sha256msg1_epu32($msg1, $msg2);

        // Rounds 12 to 15, the first group that also finishes a schedule word.
        msg = _mm_add_epi32($msg3, round_constants(12));
        $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
        carry = _mm_alignr_epi8($msg3, $msg2, 4);
        $msg0 = _mm_add_epi32($msg0, carry);
        $msg0 = _mm_sha256msg2_epu32($msg0, $msg3);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
        $msg2 = _mm_sha256msg1_epu32($msg2, $msg3);

        // Rounds 16 to 51: the same four-round step, rotating through the four
        // message registers.
        macro_rules! group {
            ($index:expr, $a:ident, $b:ident, $d:ident) => {
                msg = _mm_add_epi32($a, round_constants($index));
                $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
                carry = _mm_alignr_epi8($a, $d, 4);
                $b = _mm_add_epi32($b, carry);
                $b = _mm_sha256msg2_epu32($b, $a);
                msg = _mm_shuffle_epi32(msg, 0x0e);
                $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
                $d = _mm_sha256msg1_epu32($d, $a);
            };
        }

        group!(16, $msg0, $msg1, $msg3);
        group!(20, $msg1, $msg2, $msg0);
        group!(24, $msg2, $msg3, $msg1);
        group!(28, $msg3, $msg0, $msg2);
        group!(32, $msg0, $msg1, $msg3);
        group!(36, $msg1, $msg2, $msg0);
        group!(40, $msg2, $msg3, $msg1);
        group!(44, $msg3, $msg0, $msg2);
        group!(48, $msg0, $msg1, $msg3);

        // Rounds 52 to 59 need no further `sha256msg1`: a register's `msg1`
        // step runs two groups before the `msg2` that completes it, so the
        // last one the schedule needs is the group 48 line above, which starts
        // the words rounds 60 to 63 consume. Dropping it a group earlier
        // produces a digest correct for 60 rounds and wrong after — which is
        // exactly how the first version of this was found to be broken.
        macro_rules! late_group {
            ($index:expr, $a:ident, $b:ident, $d:ident) => {
                msg = _mm_add_epi32($a, round_constants($index));
                $state1 = _mm_sha256rnds2_epu32($state1, $state0, msg);
                carry = _mm_alignr_epi8($a, $d, 4);
                $b = _mm_add_epi32($b, carry);
                $b = _mm_sha256msg2_epu32($b, $a);
                msg = _mm_shuffle_epi32(msg, 0x0e);
                $state0 = _mm_sha256rnds2_epu32($state0, $state1, msg);
            };
        }

        late_group!(52, $msg1, $msg2, $msg0);
        late_group!(56, $msg2, $msg3, $msg1);
    }};
}

/// [`sha_ni_rounds_4_to_59`] for `$lanes` independent nonces at once: the
/// same groups, in the same order, each run for every lane before the next.
///
/// The state and message arguments are arrays with one register per lane.
/// Nothing crosses lanes: every lane reads and writes only its own index. The
/// point is the gap between dependent `sha256rnds2`s, which is longer than the
/// interval at which the core can issue them, so one lane's rounds fill
/// another's wait.
///
/// Written beside the single-lane macro rather than in place of it, and line
/// for line against it: rounds 12 to 15 are the general group with its first
/// register `$msg3`, which is why only the first two groups are special here.
#[cfg(target_arch = "x86_64")]
macro_rules! sha_ni_lanes_rounds_4_to_59 {
    ($lanes:expr, $state0:ident, $state1:ident, $msg0:ident, $msg1:ident, $msg2:ident, $msg3:ident) => {{
        // Rounds 4 to 11: the two groups that only start schedule words.
        macro_rules! early_group {
            ($index:expr, $a:ident, $d:ident) => {
                for lane in 0..$lanes {
                    let mut msg = _mm_add_epi32($a[lane], round_constants($index));
                    $state1[lane] = _mm_sha256rnds2_epu32($state1[lane], $state0[lane], msg);
                    msg = _mm_shuffle_epi32(msg, 0x0e);
                    $state0[lane] = _mm_sha256rnds2_epu32($state0[lane], $state1[lane], msg);
                    $d[lane] = _mm_sha256msg1_epu32($d[lane], $a[lane]);
                }
            };
        }

        macro_rules! group {
            ($index:expr, $a:ident, $b:ident, $d:ident) => {
                for lane in 0..$lanes {
                    let mut msg = _mm_add_epi32($a[lane], round_constants($index));
                    $state1[lane] = _mm_sha256rnds2_epu32($state1[lane], $state0[lane], msg);
                    let carry = _mm_alignr_epi8($a[lane], $d[lane], 4);
                    $b[lane] = _mm_add_epi32($b[lane], carry);
                    $b[lane] = _mm_sha256msg2_epu32($b[lane], $a[lane]);
                    msg = _mm_shuffle_epi32(msg, 0x0e);
                    $state0[lane] = _mm_sha256rnds2_epu32($state0[lane], $state1[lane], msg);
                    $d[lane] = _mm_sha256msg1_epu32($d[lane], $a[lane]);
                }
            };
        }

        // Rounds 52 to 59: no `sha256msg1`, for the reason the single-lane
        // macro gives.
        macro_rules! late_group {
            ($index:expr, $a:ident, $b:ident, $d:ident) => {
                for lane in 0..$lanes {
                    let mut msg = _mm_add_epi32($a[lane], round_constants($index));
                    $state1[lane] = _mm_sha256rnds2_epu32($state1[lane], $state0[lane], msg);
                    let carry = _mm_alignr_epi8($a[lane], $d[lane], 4);
                    $b[lane] = _mm_add_epi32($b[lane], carry);
                    $b[lane] = _mm_sha256msg2_epu32($b[lane], $a[lane]);
                    msg = _mm_shuffle_epi32(msg, 0x0e);
                    $state0[lane] = _mm_sha256rnds2_epu32($state0[lane], $state1[lane], msg);
                }
            };
        }

        early_group!(4, $msg1, $msg0);
        early_group!(8, $msg2, $msg1);
        group!(12, $msg3, $msg0, $msg2);
        group!(16, $msg0, $msg1, $msg3);
        group!(20, $msg1, $msg2, $msg0);
        group!(24, $msg2, $msg3, $msg1);
        group!(28, $msg3, $msg0, $msg2);
        group!(32, $msg0, $msg1, $msg3);
        group!(36, $msg1, $msg2, $msg0);
        group!(40, $msg2, $msg3, $msg1);
        group!(44, $msg3, $msg0, $msg2);
        group!(48, $msg0, $msg1, $msg3);
        late_group!(52, $msg1, $msg2, $msg0);
        late_group!(56, $msg2, $msg3, $msg1);
    }};
}

/// The byte-shuffle turning little-endian 32-bit loads into the big-endian
/// words SHA-256 is defined over.
///
/// # Safety
///
/// The caller must have confirmed `sse2`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn byte_swap_mask() -> std::arch::x86_64::__m128i {
    use std::arch::x86_64::_mm_set_epi64x;
    _mm_set_epi64x(
        0x0c0d_0e0f_0809_0a0b_u64 as i64,
        0x0405_0607_0001_0203_u64 as i64,
    )
}

/// Pack `ABCD`/`EFGH` state into the `ABEF`/`CDGH` pair the round instruction
/// operates on.
///
/// # Safety
///
/// The caller must have confirmed `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3,sse4.1")]
unsafe fn pack_state(
    abcd: std::arch::x86_64::__m128i,
    efgh: std::arch::x86_64::__m128i,
) -> (std::arch::x86_64::__m128i, std::arch::x86_64::__m128i) {
    use std::arch::x86_64::{_mm_alignr_epi8, _mm_blend_epi16, _mm_shuffle_epi32};
    let tmp = _mm_shuffle_epi32(abcd, 0xb1);
    let efgh = _mm_shuffle_epi32(efgh, 0x1b);
    let state0 = _mm_alignr_epi8(tmp, efgh, 8);
    let state1 = _mm_blend_epi16(efgh, tmp, 0xf0);
    (state0, state1)
}

/// The inverse of [`pack_state`]: `ABEF`/`CDGH` back to `ABCD`/`EFGH`.
///
/// # Safety
///
/// The caller must have confirmed `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2,ssse3,sse4.1")]
unsafe fn unpack_state(
    state0: std::arch::x86_64::__m128i,
    state1: std::arch::x86_64::__m128i,
) -> (std::arch::x86_64::__m128i, std::arch::x86_64::__m128i) {
    use std::arch::x86_64::{_mm_alignr_epi8, _mm_blend_epi16, _mm_shuffle_epi32};
    let tmp = _mm_shuffle_epi32(state0, 0x1b);
    let state1 = _mm_shuffle_epi32(state1, 0xb1);
    let abcd = _mm_blend_epi16(tmp, state1, 0xf0);
    let efgh = _mm_alignr_epi8(state1, tmp, 8);
    (abcd, efgh)
}

/// SHA-256 compression using the x86 SHA extensions.
///
/// `sha256rnds2` performs two rounds at once over a state held as two
/// registers, `ABEF` and `CDGH`, which is why the state is shuffled into that
/// layout on entry and back out on exit. `sha256msg1` and `sha256msg2` compute
/// the message schedule that `compress_portable` builds in `w`.
///
/// This is the standard arrangement for these instructions. It is worth
/// nothing on its own — the value is that it is checked against
/// `compress_portable` and against `rust-bitcoin` in the tests below.
///
/// # Safety
///
/// The caller must have confirmed `sha`, `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress_sha_ni(state: &mut [u32; 8], block: &[u8; 64]) {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_loadu_si128, _mm_sha256msg1_epu32,
        _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8, _mm_shuffle_epi32,
        _mm_storeu_si128,
    };

    unsafe {
        let mask = byte_swap_mask();
        let (mut state0, mut state1) = pack_state(
            _mm_loadu_si128(state.as_ptr() as *const __m128i),
            _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i),
        );

        let data = block.as_ptr() as *const __m128i;
        let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(data), mask);
        let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(1)), mask);
        let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(2)), mask);
        let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(3)), mask);

        sha_ni_rounds!(state0, state1, msg0, msg1, msg2, msg3);

        let (abcd, efgh) = unpack_state(state0, state1);
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, abcd);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, efgh);
    }
}

/// Both SHA-256 passes over a header's final block, without the digest ever
/// reaching memory.
///
/// This is the whole reason the SHA-NI path is worth having. The naive
/// arrangement writes the first digest into a 64-byte buffer, pads it, and
/// loads it straight back for the second compression — a store-to-load round
/// trip per nonce, around as expensive as the rounds themselves once the
/// instruction is doing the hashing in ~130 cycles.
///
/// It is avoidable because the first compression already ends with the digest
/// in registers, and [`unpack_state`] leaves it in exactly the lane order the
/// second block's message wants: `ABCD` is `w[0..4]` and `EFGH` is `w[4..8]`.
/// The rest of that message is the padding for a fixed 32-byte input, which is
/// two constants.
///
/// # Safety
///
/// The caller must have confirmed `sha`, `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn sha256d_header_sha_ni(midstate: &[u32; 8], tail: &[u8; 64]) -> [u32; 8] {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_loadu_si128, _mm_set_epi32,
        _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
        _mm_shuffle_epi32, _mm_storeu_si128,
    };

    unsafe {
        let mask = byte_swap_mask();

        // First pass: the header's last block, continuing from the midstate.
        let (mut state0, mut state1) = pack_state(
            _mm_loadu_si128(midstate.as_ptr() as *const __m128i),
            _mm_loadu_si128(midstate.as_ptr().add(4) as *const __m128i),
        );

        let data = tail.as_ptr() as *const __m128i;
        let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(data), mask);
        let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(1)), mask);
        let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(2)), mask);
        let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(3)), mask);

        sha_ni_rounds!(state0, state1, msg0, msg1, msg2, msg3);

        // The first digest, as schedule words rather than bytes.
        let (digest_abcd, digest_efgh) = unpack_state(state0, state1);

        // Second pass: that digest, padded to one block. The terminator and
        // the 256-bit length are the only other words there are.
        let mut msg0 = digest_abcd;
        let mut msg1 = digest_efgh;
        let mut msg2 = _mm_set_epi32(0, 0, 0, 0x8000_0000u32 as i32);
        let mut msg3 = _mm_set_epi32(256, 0, 0, 0);

        let (mut state0, mut state1) = pack_state(
            _mm_loadu_si128(IV.as_ptr() as *const __m128i),
            _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i),
        );

        sha_ni_rounds!(state0, state1, msg0, msg1, msg2, msg3);

        let (abcd, efgh) = unpack_state(state0, state1);
        let mut digest = [0u32; 8];
        _mm_storeu_si128(digest.as_mut_ptr() as *mut __m128i, abcd);
        _mm_storeu_si128(digest.as_mut_ptr().add(4) as *mut __m128i, efgh);
        digest
    }
}

/// [`Prefix`] for the SHA-NI path: the midstate packed as `ABEF` and `CDGH`,
/// and `ABEF` after the first `sha256rnds2`, rounds 0 and 1.
///
/// Rounds 2 and 3 share an instruction, and round 3 reads the nonce, so on
/// this path the prefix is two rounds rather than three.
///
/// # Safety
///
/// The caller must have confirmed `sha`, `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn sha_ni_prefix(midstate: &[u32; 8], tail: &[u8; 64]) -> [[u32; 4]; 3] {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_loadu_si128, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
        _mm_storeu_si128,
    };

    unsafe {
        let (state0, state1) = pack_state(
            _mm_loadu_si128(midstate.as_ptr() as *const __m128i),
            _mm_loadu_si128(midstate.as_ptr().add(4) as *const __m128i),
        );
        // Only lanes 0 and 1 are read, and they hold no nonce.
        let msg0 = _mm_shuffle_epi8(
            _mm_loadu_si128(tail.as_ptr() as *const __m128i),
            byte_swap_mask(),
        );
        let after = _mm_sha256rnds2_epu32(state1, state0, _mm_add_epi32(msg0, round_constants(0)));

        let mut packed = [[0u32; 4]; 3];
        for (slot, register) in packed.iter_mut().zip([state0, state1, after]) {
            _mm_storeu_si128(slot.as_mut_ptr() as *mut __m128i, register);
        }
        packed
    }
}

/// [`sha256d_header_sha_ni`], shortened at both ends to the one word
/// [`HeaderHasher::screen`] reads.
///
/// The first pass starts from [`sha_ni_prefix`] at rounds 2 and 3. The
/// second stops after the rounds 60–61 instruction: the `ABEF` it returns
/// holds `F` after round 61, which is `e` after round 60, which is the final
/// `h`. Two rounds of 128 are skipped, not three at each end, because
/// `sha256rnds2` runs them in pairs.
///
/// # Safety
///
/// The caller must have confirmed `sha`, `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn word7_sha_ni(packed: &[[u32; 4]; 3], tail: &[u8; 64]) -> u32 {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_cvtsi128_si32, _mm_loadu_si128, _mm_set_epi32,
        _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8,
        _mm_shuffle_epi32,
    };

    unsafe {
        let mask = byte_swap_mask();
        let abef_save = _mm_loadu_si128(packed[0].as_ptr() as *const __m128i);
        let cdgh_save = _mm_loadu_si128(packed[1].as_ptr() as *const __m128i);

        // After rounds 0 and 1, the old `ABEF` is the new `CDGH`.
        let mut state0 = abef_save;
        let mut state1 = _mm_loadu_si128(packed[2].as_ptr() as *const __m128i);

        let data = tail.as_ptr() as *const __m128i;
        let mut msg0 = _mm_shuffle_epi8(_mm_loadu_si128(data), mask);
        let mut msg1 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(1)), mask);
        let mut msg2 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(2)), mask);
        let mut msg3 = _mm_shuffle_epi8(_mm_loadu_si128(data.add(3)), mask);

        // Rounds 2 and 3, the first to read the nonce.
        let mut msg = _mm_add_epi32(msg0, round_constants(0));
        msg = _mm_shuffle_epi32(msg, 0x0e);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        sha_ni_rounds_4_to_59!(state0, state1, msg0, msg1, msg2, msg3);

        msg = _mm_add_epi32(msg3, round_constants(60));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);
        let (digest_abcd, digest_efgh) = unpack_state(state0, state1);

        // The second pass, as in `sha256d_header_sha_ni`, to round 61.
        let mut msg0 = digest_abcd;
        let mut msg1 = digest_efgh;
        let mut msg2 = _mm_set_epi32(0, 0, 0, 0x8000_0000u32 as i32);
        let mut msg3 = _mm_set_epi32(256, 0, 0, 0);

        let (mut state0, mut state1) = pack_state(
            _mm_loadu_si128(IV.as_ptr() as *const __m128i),
            _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i),
        );

        msg = _mm_add_epi32(msg0, round_constants(0));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0e);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        sha_ni_rounds_4_to_59!(state0, state1, msg0, msg1, msg2, msg3);

        // Rounds 60 and 61 only. `ABEF` keeps `F` in lane 0.
        msg = _mm_add_epi32(msg3, round_constants(60));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        IV[7].wrapping_add(_mm_cvtsi128_si32(state1) as u32)
    }
}

/// [`word7_sha_ni`] for the `N` nonces `first`, `first + 1`, ..., hashed
/// together, so that each lane's dependent rounds overlap the others'.
///
/// Every step is [`word7_sha_ni`]'s, done once per lane. The tail is read
/// once: each lane takes its own nonce into message word three after the byte
/// swap, which is where the tail's bytes 12 to 16 land, so the tail's own
/// nonce field is never read. Nonces wrap at `u32::MAX`.
///
/// # Safety
///
/// The caller must have confirmed `sha`, `sse2`, `ssse3` and `sse4.1`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn word7_sha_ni_lanes<const N: usize>(
    packed: &[[u32; 4]; 3],
    tail: &[u8; 64],
    first: u32,
) -> [u32; N] {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_cvtsi128_si32, _mm_insert_epi32,
        _mm_loadu_si128, _mm_set_epi32, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32,
        _mm_sha256rnds2_epu32, _mm_shuffle_epi8, _mm_shuffle_epi32,
    };

    unsafe {
        let mask = byte_swap_mask();
        let abef_save = _mm_loadu_si128(packed[0].as_ptr() as *const __m128i);
        let cdgh_save = _mm_loadu_si128(packed[1].as_ptr() as *const __m128i);
        let after = _mm_loadu_si128(packed[2].as_ptr() as *const __m128i);

        let data = tail.as_ptr() as *const __m128i;
        let words0 = _mm_shuffle_epi8(_mm_loadu_si128(data), mask);
        let mut msg0 = [words0; N];
        let mut msg1 = [_mm_shuffle_epi8(_mm_loadu_si128(data.add(1)), mask); N];
        let mut msg2 = [_mm_shuffle_epi8(_mm_loadu_si128(data.add(2)), mask); N];
        let mut msg3 = [_mm_shuffle_epi8(_mm_loadu_si128(data.add(3)), mask); N];
        for (lane, words) in msg0.iter_mut().enumerate() {
            let nonce = first.wrapping_add(lane as u32);
            *words = _mm_insert_epi32(words0, nonce.swap_bytes() as i32, 3);
        }

        // After rounds 0 and 1, the old `ABEF` is the new `CDGH`.
        let mut state0 = [abef_save; N];
        let mut state1 = [after; N];

        // Rounds 2 and 3, the first to read the nonce.
        for lane in 0..N {
            let msg = _mm_shuffle_epi32(_mm_add_epi32(msg0[lane], round_constants(0)), 0x0e);
            state0[lane] = _mm_sha256rnds2_epu32(state0[lane], state1[lane], msg);
        }

        sha_ni_lanes_rounds_4_to_59!(N, state0, state1, msg0, msg1, msg2, msg3);

        // Rounds 60 to 63, and the first digest becomes the second pass's
        // message.
        for lane in 0..N {
            let mut msg = _mm_add_epi32(msg3[lane], round_constants(60));
            state1[lane] = _mm_sha256rnds2_epu32(state1[lane], state0[lane], msg);
            msg = _mm_shuffle_epi32(msg, 0x0e);
            state0[lane] = _mm_sha256rnds2_epu32(state0[lane], state1[lane], msg);

            let (digest_abcd, digest_efgh) = unpack_state(
                _mm_add_epi32(state0[lane], abef_save),
                _mm_add_epi32(state1[lane], cdgh_save),
            );
            msg0[lane] = digest_abcd;
            msg1[lane] = digest_efgh;
        }

        // The second pass, as in `word7_sha_ni`, to round 61.
        msg2 = [_mm_set_epi32(0, 0, 0, 0x8000_0000u32 as i32); N];
        msg3 = [_mm_set_epi32(256, 0, 0, 0); N];
        let (iv_abef, iv_cdgh) = pack_state(
            _mm_loadu_si128(IV.as_ptr() as *const __m128i),
            _mm_loadu_si128(IV.as_ptr().add(4) as *const __m128i),
        );
        state0 = [iv_abef; N];
        state1 = [iv_cdgh; N];

        for lane in 0..N {
            let mut msg = _mm_add_epi32(msg0[lane], round_constants(0));
            state1[lane] = _mm_sha256rnds2_epu32(state1[lane], state0[lane], msg);
            msg = _mm_shuffle_epi32(msg, 0x0e);
            state0[lane] = _mm_sha256rnds2_epu32(state0[lane], state1[lane], msg);
        }

        sha_ni_lanes_rounds_4_to_59!(N, state0, state1, msg0, msg1, msg2, msg3);

        // Rounds 60 and 61 only. `ABEF` keeps `F` in lane 0.
        let mut words = [0u32; N];
        for (lane, word) in words.iter_mut().enumerate() {
            let msg = _mm_add_epi32(msg3[lane], round_constants(60));
            let last = _mm_sha256rnds2_epu32(state1[lane], state0[lane], msg);
            *word = IV[7].wrapping_add(_mm_cvtsi128_si32(last) as u32);
        }
        words
    }
}

/// Four round constants as one register, for the SHA-NI path.
///
/// A plain load: `K` is contiguous and little-endian in memory, which puts
/// `K[index]` in lane zero, exactly where the round instruction wants it.
///
/// # Safety
///
/// The caller must have confirmed `sse2`, and `index` must leave four
/// constants in range.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn round_constants(index: usize) -> std::arch::x86_64::__m128i {
    use std::arch::x86_64::{__m128i, _mm_loadu_si128};
    debug_assert!(index + 4 <= K.len());
    unsafe { _mm_loadu_si128(K.as_ptr().add(index) as *const __m128i) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        BlockHash, CompactTarget, Target, TxMerkleNode,
        block::{Header, Version},
        hashes::Hash,
    };

    fn backends() -> Vec<Backend> {
        let mut backends = vec![Backend::Portable];
        if sha_ni_available() {
            backends.push(Backend::ShaNi);
        }
        backends
    }

    /// A header with every field distinct, so a byte-order mistake anywhere in
    /// the 80 bytes changes the digest.
    fn header(nonce: u32) -> Header {
        Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0x22; 32]),
            time: 0x3344_5566,
            bits: CompactTarget::from_consensus(0x1702_3ad4),
            nonce,
        }
    }

    #[test]
    fn the_portable_compression_reproduces_the_known_digest() {
        // FIPS 180-4: SHA-256 of "abc".
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[62] = 0x00;
        block[63] = 24; // three bytes, in bits

        let mut state = IV;
        compress_portable(&mut state, &block);

        assert_eq!(
            bitcoin::hex::DisplayHex::to_lower_hex_string(&digest_bytes(&state)[..]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn every_backend_agrees_with_rust_bitcoin_on_a_header() {
        for backend in backends() {
            let header = header(0);
            let hasher = HeaderHasher::new(&header, backend);

            for nonce in [0u32, 1, 2, 4096, 0x7fff_ffff, u32::MAX] {
                let mut expected_header = header;
                expected_header.nonce = nonce;
                let expected = expected_header.block_hash().to_byte_array();

                assert_eq!(
                    hasher.hash_bytes(nonce),
                    expected,
                    "{} disagreed at nonce {nonce}",
                    backend.name()
                );
            }
        }
    }

    #[test]
    fn the_rustcrypto_hashers_agree_with_rust_bitcoin() {
        let header = header(0);
        let midstate = RustCryptoHasher::new(&header);
        let plain = RustCryptoPlainHasher::new(&header);

        for nonce in [0u32, 1, 2, 4096, 0x7fff_ffff, u32::MAX] {
            let mut expected_header = header;
            expected_header.nonce = nonce;
            let expected = expected_header.block_hash().to_byte_array();

            assert_eq!(
                digest_bytes(&midstate.hash(nonce)),
                expected,
                "the rustcrypto midstate hasher disagreed at nonce {nonce}"
            );
            assert_eq!(
                digest_bytes(&plain.hash(nonce)),
                expected,
                "the rustcrypto plain hasher disagreed at nonce {nonce}"
            );
        }
    }

    #[test]
    fn every_hasher_produces_the_same_digest() {
        // The cross-check that matters for a fair benchmark: five ways of
        // computing the same thing, agreeing on a sweep rather than on a
        // handful of values.
        let header = header(7);
        let portable = HeaderHasher::new(&header, Backend::Portable);
        let rustcrypto = RustCryptoHasher::new(&header);
        let plain = RustCryptoPlainHasher::new(&header);
        let sha_ni = sha_ni_available().then(|| HeaderHasher::new(&header, Backend::ShaNi));

        for nonce in (0..50_000).step_by(11) {
            let expected = portable.hash(nonce);
            assert_eq!(rustcrypto.hash(nonce), expected, "rustcrypto at {nonce}");
            assert_eq!(plain.hash(nonce), expected, "rustcrypto-naive at {nonce}");
            if let Some(sha_ni) = &sha_ni {
                assert_eq!(sha_ni.hash(nonce), expected, "sha-ni at {nonce}");
            }
        }
    }

    #[test]
    fn the_backends_agree_on_arbitrary_blocks() {
        #[cfg(target_arch = "x86_64")]
        {
            if !sha_ni_available() {
                return;
            }

            // The header tests only ever present two block shapes. This walks
            // arbitrary data through both compression functions, which is what
            // exercises the message schedule across its whole range — the last
            // schedule word is computed eight rounds before it is used, so a
            // mistake there is invisible until round 60.
            let mut seed = 0x0123_4567_89ab_cdefu64;
            for _ in 0..500 {
                let mut block = [0u8; 64];
                for byte in block.iter_mut() {
                    seed = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    *byte = (seed >> 33) as u8;
                }

                let mut portable = IV;
                compress_portable(&mut portable, &block);
                let mut hardware = IV;
                unsafe { compress_sha_ni(&mut hardware, &block) };

                assert_eq!(portable, hardware, "the backends disagreed on {block:?}");
            }
        }
    }

    #[test]
    fn the_backends_agree_with_each_other_across_many_nonces() {
        if !sha_ni_available() {
            return;
        }

        let header = header(0);
        let portable = HeaderHasher::new(&header, Backend::Portable);
        let sha_ni = HeaderHasher::new(&header, Backend::ShaNi);

        // A wide sweep rather than a handful of values: the message schedule
        // instructions carry state between four-round groups, so a fault could
        // easily depend on the data rather than being uniform.
        for nonce in (0..200_000).step_by(37) {
            assert_eq!(
                portable.hash(nonce),
                sha_ni.hash(nonce),
                "the backends disagreed at nonce {nonce}"
            );
        }
    }

    #[test]
    fn the_midstate_matches_hashing_the_whole_header() {
        // The point of the midstate is that splitting the header at 64 bytes
        // and carrying state across the split is the same computation.
        for backend in backends() {
            let mut header = header(12_345);
            let hasher = HeaderHasher::new(&header, backend);

            header.nonce = 999;
            assert_eq!(hasher.hash_bytes(999), header.block_hash().to_byte_array());
        }
    }

    #[test]
    fn a_rank_orders_digests_the_way_their_difficulty_does() {
        use crate::block::difficulty_of_hash;

        // Real digests rather than constructed ones: what the encoding has to
        // order is the hashes a search actually sees, and `difficulty_of_hash`
        // is the measure it has to agree with.
        let mut header = header(0);
        let hasher = HeaderHasher::new(&header, Backend::detect());
        let mut ranked: Vec<(u32, f64)> = (0..4096u32)
            .map(|nonce| {
                header.nonce = nonce;
                (
                    best_rank(&hasher.hash(nonce)),
                    difficulty_of_hash(&header.block_hash()),
                )
            })
            .collect();

        ranked.sort_by_key(|(rank, _)| *rank);
        for pair in ranked.windows(2) {
            assert!(
                pair[0].1 >= pair[1].1,
                "rank {:#010x} sorts below rank {:#010x} but is worth less difficulty: \
                 {} against {}",
                pair[0].0,
                pair[1].0,
                pair[0].1,
                pair[1].1
            );
        }

        // The two ends, which no sweep of real digests will ever reach: the
        // largest possible value ranks worst and the smallest ranks best, so
        // the starting value a dispatch clears to cannot beat a real hash.
        assert_eq!(best_rank(&[u32::MAX; 8]), u32::MAX);
        assert_eq!(best_rank(&[0; 8]), 0);
    }

    #[test]
    fn the_target_comparison_agrees_with_rust_bitcoin() {
        // Regtest's target is met by roughly one header in two, so a sweep
        // this size lands on both sides of the comparison many times over.
        let target = Target::from_compact(CompactTarget::from_consensus(0x207f_ffff));
        let words = target_words(target);
        let header = header(0);
        let hasher = HeaderHasher::new(&header, Backend::detect());

        let mut met = 0;
        for nonce in 0..2_000 {
            let mut expected_header = header;
            expected_header.nonce = nonce;

            let ours = meets_target(&hasher.hash(nonce), &words);
            let theirs = target.is_met_by(expected_header.block_hash());
            assert_eq!(ours, theirs, "disagreed at nonce {nonce}");
            met += usize::from(ours);
        }

        assert!(met > 0, "some header should have met the regtest target");
        assert!(met < 2_000, "not every header should have met it");
    }

    #[test]
    fn a_harder_target_is_still_compared_correctly() {
        // Difficulty 1: eight leading zero bits' worth of headroom is gone, so
        // this exercises the path where the first word decides every call.
        let target = Target::from_compact(CompactTarget::from_consensus(0x1d00_ffff));
        let words = target_words(target);
        let header = header(0);
        let hasher = HeaderHasher::new(&header, Backend::detect());

        for nonce in 0..2_000 {
            let mut expected_header = header;
            expected_header.nonce = nonce;
            assert_eq!(
                meets_target(&hasher.hash(nonce), &words),
                target.is_met_by(expected_header.block_hash()),
                "disagreed at nonce {nonce}"
            );
        }
    }

    /// `screen` against its contract, on every backend: exactly the verdict
    /// and the rank the full hash gives.
    fn assert_screen_matches(header: &Header, nonce: u32, target: &[u32; 8]) {
        for backend in backends() {
            let hasher = HeaderHasher::new(header, backend);
            let state = hasher.hash(nonce);
            assert_eq!(
                hasher.screen(nonce, target),
                (meets_target(&state, target), best_rank(&state)),
                "{} screened nonce {nonce} against {target:08x?} differently from the full hash",
                backend.name()
            );
        }
    }

    /// The target whose value is exactly this digest's: the inverse of the
    /// reading `meets_target` does.
    fn target_at(state: &[u32; 8]) -> [u32; 8] {
        std::array::from_fn(|index| state[7 - index].swap_bytes())
    }

    /// One less than `target`, as a 256-bit number.
    fn minus_one(mut target: [u32; 8]) -> [u32; 8] {
        for word in target.iter_mut().rev() {
            let borrowed = *word == 0;
            *word = word.wrapping_sub(1);
            if !borrowed {
                break;
            }
        }
        target
    }

    fn lcg(seed: &mut u64) -> u32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 32) as u32
    }

    #[test]
    fn the_screen_matches_the_full_hash_on_random_headers_and_targets() {
        let mut seed = 0x5eed_0000_0000_0001u64;
        for _ in 0..200 {
            let mut root = [0u8; 32];
            for byte in root.iter_mut() {
                *byte = lcg(&mut seed) as u8;
            }
            let header = Header {
                merkle_root: TxMerkleNode::from_byte_array(root),
                time: lcg(&mut seed),
                bits: CompactTarget::from_consensus(lcg(&mut seed)),
                ..header(0)
            };

            for _ in 0..20 {
                // Leading zero words from none to three, so the top word is
                // sometimes zero, as at any real difficulty, and sometimes not.
                let zeros = (lcg(&mut seed) % 4) as usize;
                let target: [u32; 8] =
                    std::array::from_fn(|index| if index < zeros { 0 } else { lcg(&mut seed) });
                assert_screen_matches(&header, lcg(&mut seed), &target);
            }
        }
    }

    #[test]
    fn the_screen_matches_the_full_hash_at_difficulty_1_and_on_regtest() {
        let header = header(0);
        for bits in [0x1d00_ffff, 0x207f_ffff, 0x1f00_ffff] {
            let target = target_words(Target::from_compact(CompactTarget::from_consensus(bits)));
            for nonce in (0..20_000).step_by(7) {
                assert_screen_matches(&header, nonce, &target);
            }
        }
    }

    #[test]
    fn the_screen_decides_a_tie_on_the_top_word_both_ways() {
        // A random digest's own value as the target: the top words tie, and
        // only the words below decide. Equal meets; one less does not.
        let header = header(0);
        let hasher = HeaderHasher::new(&header, Backend::Portable);
        for nonce in [0u32, 1, 77, 0xdead_beef] {
            let state = hasher.hash(nonce);
            assert_ne!(
                state[7], 0,
                "this tie is meant to be on a non-zero top word"
            );

            let at = target_at(&state);
            assert!(meets_target(&state, &at));
            assert_screen_matches(&header, nonce, &at);

            let below = minus_one(at);
            assert_eq!(below[0], at[0], "the tie must survive the decrement");
            assert!(!meets_target(&state, &below));
            assert_screen_matches(&header, nonce, &below);
        }
    }

    #[test]
    fn the_screen_ranks_a_zero_word_7_through_the_full_hash() {
        use bitcoin::{Network, blockdata::constants::genesis_block};

        // No random digest has 32 leading zero bits; a real block does. The
        // genesis hash has 43, so its word seven is zero, the rank has to
        // come from word six, and a tie at difficulty 1 is a tie on zero.
        let header = genesis_block(Network::Bitcoin).header;
        let state = HeaderHasher::new(&header, Backend::Portable).hash(header.nonce);
        assert_eq!(state[7], 0);

        let at = target_at(&state);
        let difficulty_1 = target_words(Target::from_compact(CompactTarget::from_consensus(
            0x1d00_ffff,
        )));
        let regtest = target_words(Target::from_compact(CompactTarget::from_consensus(
            0x207f_ffff,
        )));
        for target in [at, minus_one(at), difficulty_1, regtest, [0; 8]] {
            assert_screen_matches(&header, header.nonce, &target);
        }
    }

    #[test]
    fn the_screens_agree_with_each_other_across_many_nonces() {
        if !sha_ni_available() {
            return;
        }

        // The same sweep `the_backends_agree_with_each_other_across_many_nonces`
        // runs on the full hash, here on the word the screen stops at.
        let header = header(0);
        let portable = HeaderHasher::new(&header, Backend::Portable);
        let sha_ni = HeaderHasher::new(&header, Backend::ShaNi);
        for nonce in (0..200_000).step_by(37) {
            let expected = portable.hash(nonce)[7];
            assert_eq!(portable.word7(nonce), expected, "portable at {nonce}");
            assert_eq!(sha_ni.word7(nonce), expected, "sha-ni at {nonce}");
        }
    }

    /// `screen_lanes` against its contract, on every backend: lane by lane,
    /// exactly what `screen` returns for that lane's nonce.
    fn assert_lanes_match<const N: usize>(header: &Header, first: u32, target: &[u32; 8]) {
        for backend in backends() {
            let hasher = HeaderHasher::new(header, backend);
            let expected: [(bool, u32); N] =
                std::array::from_fn(|lane| hasher.screen(first.wrapping_add(lane as u32), target));
            assert_eq!(
                hasher.screen_lanes::<N>(first, target),
                expected,
                "{} screened {N} lanes from nonce {first} against {target:08x?} differently \
                 from one nonce at a time",
                backend.name()
            );
        }
    }

    /// The same check for every lane count the searches may choose.
    fn assert_every_lane_count_matches(header: &Header, first: u32, target: &[u32; 8]) {
        assert_lanes_match::<1>(header, first, target);
        assert_lanes_match::<2>(header, first, target);
        assert_lanes_match::<3>(header, first, target);
        assert_lanes_match::<4>(header, first, target);
    }

    #[test]
    fn the_lanes_match_the_screen_on_random_headers_and_targets() {
        let mut seed = 0x1a4e_0000_0000_0002u64;
        for _ in 0..100 {
            let mut root = [0u8; 32];
            for byte in root.iter_mut() {
                *byte = lcg(&mut seed) as u8;
            }
            let header = Header {
                merkle_root: TxMerkleNode::from_byte_array(root),
                time: lcg(&mut seed),
                bits: CompactTarget::from_consensus(lcg(&mut seed)),
                ..header(0)
            };

            for _ in 0..10 {
                let zeros = (lcg(&mut seed) % 4) as usize;
                let target: [u32; 8] =
                    std::array::from_fn(|index| if index < zeros { 0 } else { lcg(&mut seed) });
                assert_every_lane_count_matches(&header, lcg(&mut seed), &target);
            }
        }

        // The top of the nonce space, where the lanes wrap.
        let target = [u32::MAX; 8];
        for first in [u32::MAX - 3, u32::MAX - 1, u32::MAX] {
            assert_every_lane_count_matches(&header(0), first, &target);
        }
    }

    #[test]
    fn the_lanes_match_the_screen_at_difficulty_1_and_on_regtest() {
        let header = header(0);
        for bits in [0x1d00_ffff, 0x207f_ffff, 0x1f00_ffff] {
            let target = target_words(Target::from_compact(CompactTarget::from_consensus(bits)));
            for first in (0..4_000).step_by(12) {
                assert_every_lane_count_matches(&header, first, &target);
            }
        }
    }

    /// Every lane count, with `nonce` in each lane position in turn: the rare
    /// branches fire in one lane only, so a lane that read another's state
    /// or hashed another's nonce is caught here and nowhere else.
    fn assert_every_lane_position_matches(header: &Header, nonce: u32, target: &[u32; 8]) {
        fn positions<const N: usize>(header: &Header, nonce: u32, target: &[u32; 8]) {
            for lane in 0..N as u32 {
                assert_lanes_match::<N>(header, nonce.wrapping_sub(lane), target);
            }
        }
        positions::<1>(header, nonce, target);
        positions::<2>(header, nonce, target);
        positions::<3>(header, nonce, target);
        positions::<4>(header, nonce, target);
    }

    #[test]
    fn the_lanes_decide_a_tie_on_the_top_word_in_every_lane() {
        let header = header(0);
        let hasher = HeaderHasher::new(&header, Backend::Portable);
        for nonce in [0u32, 1, 77, 0xdead_beef] {
            let state = hasher.hash(nonce);
            let at = target_at(&state);
            let below = minus_one(at);
            assert_eq!(below[0], at[0], "the tie must survive the decrement");

            // The tie decides differently either side of the digest, so a
            // lane that took its neighbour's full hash would get one wrong.
            assert!(meets_target(&state, &at));
            assert!(!meets_target(&state, &below));
            assert_every_lane_position_matches(&header, nonce, &at);
            assert_every_lane_position_matches(&header, nonce, &below);
        }
    }

    #[test]
    fn the_lanes_rank_a_zero_word_7_through_the_full_hash_in_every_lane() {
        use bitcoin::{Network, blockdata::constants::genesis_block};

        // The genesis header at its real nonce, whose word seven is zero, in
        // lane 0, then lane 1, and so on. Its neighbours' are not.
        let header = genesis_block(Network::Bitcoin).header;
        let state = HeaderHasher::new(&header, Backend::Portable).hash(header.nonce);
        assert_eq!(state[7], 0);

        let at = target_at(&state);
        let difficulty_1 = target_words(Target::from_compact(CompactTarget::from_consensus(
            0x1d00_ffff,
        )));
        for target in [at, minus_one(at), difficulty_1, [0; 8]] {
            assert_every_lane_position_matches(&header, header.nonce, &target);
        }
    }

    #[test]
    fn every_hashers_lanes_match_its_own_screen() {
        let header = header(3);
        let mut hashers = vec![
            NonceHasher::Midstate(HeaderHasher::new(&header, Backend::Portable)),
            NonceHasher::RustCrypto(RustCryptoHasher::new(&header)),
            NonceHasher::RustCryptoPlain(RustCryptoPlainHasher::new(&header)),
        ];
        if sha_ni_available() {
            hashers.push(NonceHasher::Midstate(HeaderHasher::new(
                &header,
                Backend::ShaNi,
            )));
        }
        let target = target_words(Target::from_compact(CompactTarget::from_consensus(
            0x207f_ffff,
        )));
        for hasher in &hashers {
            for first in (0..2_000).step_by(4).chain([u32::MAX - 1]) {
                let expected: [(bool, u32); 4] = std::array::from_fn(|lane| {
                    hasher.screen(first.wrapping_add(lane as u32), &target)
                });
                assert_eq!(
                    hasher.screen_lanes::<4>(first, &target),
                    expected,
                    "from {first}"
                );
            }
        }
    }

    /// The lanes against one nonce at a time, timed in-process. Ignored
    /// because it is a measurement on a shared machine, not an assertion: pin
    /// it with `taskset -c <cpu>` and read the clock beside it.
    ///
    /// ```sh
    /// taskset -c 4 cargo test --release sha256::tests::the_lanes_beat -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn the_lanes_beat_one_nonce_at_a_time() {
        use std::hint::black_box;
        use std::time::Instant;

        if !sha_ni_available() {
            return;
        }
        let hasher = HeaderHasher::new(&header(0), Backend::ShaNi);
        let target = target_words(Target::from_compact(CompactTarget::from_consensus(
            0x1d00_ffff,
        )));
        const NONCES: u32 = 1 << 24;

        fn walk<const N: usize>(hasher: &HeaderHasher, target: &[u32; 8]) -> f64 {
            let started = Instant::now();
            let mut best = u32::MAX;
            for first in (0..NONCES).step_by(N) {
                for (_, rank) in hasher.screen_lanes::<N>(black_box(first), target) {
                    best = best.min(rank);
                }
            }
            black_box(best);
            f64::from(NONCES) / started.elapsed().as_secs_f64() / 1e6
        }
        fn one_at_a_time(hasher: &HeaderHasher, target: &[u32; 8]) -> f64 {
            let started = Instant::now();
            let mut best = u32::MAX;
            for nonce in 0..NONCES {
                best = best.min(hasher.screen(black_box(nonce), target).1);
            }
            black_box(best);
            f64::from(NONCES) / started.elapsed().as_secs_f64() / 1e6
        }

        let mut rates: [Vec<f64>; 5] = Default::default();
        for _ in 0..5 {
            rates[0].push(one_at_a_time(&hasher, &target));
            rates[1].push(walk::<1>(&hasher, &target));
            rates[2].push(walk::<2>(&hasher, &target));
            rates[3].push(walk::<3>(&hasher, &target));
            rates[4].push(walk::<4>(&hasher, &target));
        }
        let names = ["screen", "lanes x1", "lanes x2", "lanes x3", "lanes x4"];
        for (name, mut rate) in names.into_iter().zip(rates) {
            rate.sort_by(f64::total_cmp);
            println!(
                "sha-ni, {name}: {:.2} MH/s median of 5 ({:.2} to {:.2})",
                rate[2], rate[0], rate[4]
            );
        }
    }

    #[test]
    fn a_digest_equal_to_the_target_meets_it() {
        let target = Target::from_compact(CompactTarget::from_consensus(0x207f_ffff));
        let words = target_words(target);

        // Build the state whose digest is exactly the target: word seven holds
        // the most significant bytes, byte-swapped.
        let mut state = [0u32; 8];
        for (index, word) in words.iter().enumerate() {
            state[7 - index] = word.swap_bytes();
        }

        assert!(meets_target(&state, &words));

        // One more than the target does not meet it.
        state[7] = (words[0] + 1).swap_bytes();
        assert!(!meets_target(&state, &words));
    }
}
