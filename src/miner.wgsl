// GPU SHA256d header search.
//
// The CPU side has already done everything that does not depend on the nonce:
// the coinbase, the merkle root, and the compression of the header's first 64
// bytes. What arrives here is a midstate, the header's padded final block, and
// an expanded target. Each invocation walks a slice of the nonce space and
// records the nonces whose double-SHA256 lands at or below that target.
//
// SHA-256 is duplicated from `../gpu/probe.wgsl` rather than shared with it.
// That shader is the most delicate file in the repository and serves a
// different search; a copy that can be changed independently is worth more
// here than the deduplication.

struct Params {
    // State after the header's first 64 bytes.
    midstate: array<vec4<u32>, 2>,
    // The header's final block, padded, as big-endian words. The nonce is
    // word 3 and is overwritten per candidate.
    tail: array<vec4<u32>, 4>,
    // The target, most significant word first. Named `threshold` because
    // `target` is a WGSL reserved keyword.
    threshold: array<vec4<u32>, 2>,
    base_nonce: u32,
    nonces_per_lane: u32,
    lanes: u32,
    capacity: u32,
    // `search_pair`'s second midstate: the same header under the other version
    // of a rolled pair. Appended, so every field above keeps its offset, and
    // zero for every other entry point, which never reads it.
    pair_midstate: array<vec4<u32>, 2>,
}

struct Winners {
    count: atomic<u32>,
    overflow: atomic<u32>,
    // The best hash this dispatch saw: the rank that ordered it, and the nonce
    // that produced it. Two words that were reserved from the start, so this
    // needs no second buffer, no second readback and no change to the bind
    // group layout.
    best: atomic<u32>,
    best_nonce: u32,
    nonces: array<u32>,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> winners: Winners;

const SHA256_IV: array<u32, 8> = array<u32, 8>(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
);

fn small_sigma0(x: u32) -> u32 {
    return ((x >> 7u) | (x << 25u)) ^ ((x >> 18u) | (x << 14u)) ^ (x >> 3u);
}

fn small_sigma1(x: u32) -> u32 {
    return ((x >> 17u) | (x << 15u)) ^ ((x >> 19u) | (x << 13u)) ^ (x >> 10u);
}

fn big_sigma0(x: u32) -> u32 {
    return ((x >> 2u) | (x << 30u)) ^ ((x >> 13u) | (x << 19u)) ^ ((x >> 22u) | (x << 10u));
}

fn big_sigma1(x: u32) -> u32 {
    return ((x >> 6u) | (x << 26u)) ^ ((x >> 11u) | (x << 21u)) ^ ((x >> 25u) | (x << 7u));
}

// **The round functions are not in this file.** `sha256_rounds_F_L(state,
// block)` runs rounds F up to L of one compression from the working variables
// `state` and returns them, not yet added to the chaining value. `gpu.rs`
// writes each one out round by round and appends it to this source before
// compiling it — see `gpu::unrolled_rounds` for why a loop is not used.

fn add_state(chain: array<u32, 8>, worked: array<u32, 8>) -> array<u32, 8> {
    return array<u32, 8>(
        chain[0] + worked[0], chain[1] + worked[1], chain[2] + worked[2], chain[3] + worked[3],
        chain[4] + worked[4], chain[5] + worked[5], chain[6] + worked[6], chain[7] + worked[7],
    );
}

/// One whole SHA-256 compression.
fn sha256_compress(state: array<u32, 8>, block: array<u32, 16>) -> array<u32, 8> {
    return add_state(state, sha256_rounds_0_64(state, block));
}

/// What every nonce under one header shares of the first pass.
///
/// The final block's schedule words are the merkle root's last four bytes,
/// nTime, nBits, the nonce, then padding. Rounds 0 to 2 read only the first
/// three, so the state after them is the same for every nonce. Round 3 is the
/// first to read the nonce, and everything it adds besides that word is fixed
/// too. `sha256::Prefix` on the host is the same split.
struct Prefix {
    // The working variables after round 2.
    state: array<u32, 8>,
    // Round 3's `temp1` less its schedule word, the nonce.
    temp1: u32,
    // Round 3's `temp2`, which reads only the state.
    temp2: u32,
}

fn prefix() -> Prefix {
    return prefix_of(midstate_words());
}

/// [`prefix`] for any midstate: `search_pair` has two.
fn prefix_of(midstate: array<u32, 8>) -> Prefix {
    let s = sha256_rounds_0_3(midstate, tail_block(0u));
    let choose = (s[4] & s[5]) ^ (~s[4] & s[6]);
    let majority = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]);
    return Prefix(
        s,
        // K[3]: the round constants are written into the generated rounds,
        // and this is the one place outside them that needs one.
        s[7] + big_sigma1(s[4]) + choose + 0xe9b5dba5u,
        big_sigma0(s[0]) + majority,
    );
}

/// The first pass for one nonce, from round 3 on.
fn first_pass(p: Prefix, nonce: u32) -> array<u32, 8> {
    return first_pass_of(midstate_words(), p, nonce);
}

/// [`first_pass`] from any midstate and its prefix.
fn first_pass_of(midstate: array<u32, 8>, p: Prefix, nonce: u32) -> array<u32, 8> {
    let block = tail_block(nonce);
    return add_state(midstate, sha256_rounds_4_64(after_round_3(p, block[3]), block));
}

/// Round 3, where the nonce first enters: everything else was added once.
fn after_round_3(p: Prefix, nonce_word: u32) -> array<u32, 8> {
    let s = p.state;
    let temp1 = p.temp1 + nonce_word;
    return array<u32, 8>(temp1 + p.temp2, s[0], s[1], s[2], s[3] + temp1, s[4], s[5], s[6]);
}

/// The second pass is over a fixed 32-byte message, so its whole padding is
/// constant: the terminator, then a bit length of 256.
fn second_block(first: array<u32, 8>) -> array<u32, 16> {
    return array<u32, 16>(
        first[0], first[1], first[2], first[3],
        first[4], first[5], first[6], first[7],
        0x80000000u, 0u, 0u, 0u,
        0u, 0u, 0u, 256u,
    );
}

/// State word seven of the second pass, and nothing else of it: the value's
/// top 32 bits, byte-reversed. `h` after round 63 is `e` after round 60, so
/// rounds 61 to 63 are never run.
fn second_top(first: array<u32, 8>) -> u32 {
    return SHA256_IV[7] + sha256_rounds_0_61(SHA256_IV, second_block(first))[4];
}

fn midstate_words() -> array<u32, 8> {
    let low = params.midstate[0];
    let high = params.midstate[1];
    return array<u32, 8>(low.x, low.y, low.z, low.w, high.x, high.y, high.z, high.w);
}

fn pair_midstate_words() -> array<u32, 8> {
    let low = params.pair_midstate[0];
    let high = params.pair_midstate[1];
    return array<u32, 8>(low.x, low.y, low.z, low.w, high.x, high.y, high.z, high.w);
}

fn threshold_words() -> array<u32, 8> {
    let low = params.threshold[0];
    let high = params.threshold[1];
    return array<u32, 8>(low.x, low.y, low.z, low.w, high.x, high.y, high.z, high.w);
}

/// The header's final block with `nonce` substituted.
///
/// The nonce sits at bytes 12 to 16 of the block and is little-endian in the
/// header, so as a big-endian schedule word it is the byte-reversed nonce.
///
/// Words 4 to 15 are written here as literals rather than read from
/// `params.tail`, which carries the same values: an 80-byte header's padding
/// is always the terminator, zeros, then a bit length of 640. Literals are what
/// let the compiler fold them — `K[i] + W[i]` into one constant in rounds 4 to
/// 15, and every schedule term built only from them.
fn tail_block(nonce: u32) -> array<u32, 16> {
    let a = params.tail[0];
    return array<u32, 16>(
        a.x, a.y, a.z, byte_reverse(nonce),
        0x80000000u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u,
        0u, 0u, 0u, 640u,
    );
}

fn byte_reverse(value: u32) -> u32 {
    return ((value & 0x000000ffu) << 24u)
        | ((value & 0x0000ff00u) << 8u)
        | ((value & 0x00ff0000u) >> 8u)
        | ((value & 0xff000000u) >> 24u);
}

/// The double-SHA256 of the header carrying `nonce`, whole.
///
/// Through the same [`prefix`] and [`first_pass`] the search uses, so the
/// probe's comparison of these digests with `rust-bitcoin` covers that split
/// too. Only the second pass's shortened end, [`second_top`], is the search's
/// alone, and the probe's winner and rank comparisons are what reach it.
fn hash_nonce(nonce: u32) -> array<u32, 8> {
    return hash_nonce_with(midstate_words(), nonce);
}

/// [`hash_nonce`] from any midstate: the rare path of `search_pair`, for
/// whichever version of the pair needs its whole digest.
fn hash_nonce_with(midstate: array<u32, 8>, nonce: u32) -> array<u32, 8> {
    return sha256_compress(SHA256_IV, second_block(first_pass_of(midstate, prefix_of(midstate), nonce)));
}

/// Whether a digest is at or below the target.
///
/// Bitcoin reads the digest's 32 bytes as a little-endian number, so the most
/// significant byte of the value is the digest's last byte — the low byte of
/// state word seven. Hence walking the state backwards and byte-reversing.
///
/// The first comparison decides almost every call, since a real target has
/// leading zero words and a random digest does not.
fn meets_threshold(digest: array<u32, 8>, threshold: array<u32, 8>) -> bool {
    for (var index = 0u; index < 8u; index = index + 1u) {
        let word = byte_reverse(digest[7u - index]);
        if (word < threshold[index]) {
            return true;
        }
        if (word > threshold[index]) {
            return false;
        }
    }
    // Exactly equal to the target still meets it.
    return true;
}

/// A digest's rank, smaller being the better hash. `sha256::best_rank` on the
/// host is the same encoding and must stay that way: the probe compares the two
/// directly, and a rank that disagreed would look exactly like a wrong digest.
fn rank(digest: array<u32, 8>) -> u32 {
    let high = byte_reverse(digest[7]);
    if (high != 0u) {
        return rank_of_high(high);
    }
    return byte_reverse(digest[6]) >> 1u;
}

/// The rank of a digest whose top word, `high`, is non-zero: all `rank` reads
/// in that case, which is why the search can rank from word seven alone.
fn rank_of_high(high: u32) -> u32 {
    return 0x80000000u | (high >> 1u);
}

fn record_winner(nonce: u32) {
    let slot = atomicAdd(&winners.count, 1u);
    if (slot < params.capacity) {
        winners.nonces[slot] = nonce;
    } else {
        // The host treats an overflow as an error rather than a truncated
        // list: past this point a dropped winner and a nonce that never won
        // are indistinguishable.
        atomicAdd(&winners.overflow, 1u);
    }
}

@compute @workgroup_size(64)
fn search(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if (lane >= params.lanes) {
        return;
    }

    let threshold = threshold_words();
    // Rounds 0 to 2 of the first pass, once for the lane's 256-odd nonces.
    let lane_prefix = prefix();
    // Contiguous per lane. Nothing here touches memory per nonce, so there is
    // no coalescing argument for striding instead.
    let first = params.base_nonce + lane * params.nonces_per_lane;

    // **The lane's own best, in registers.** Ranking every digest globally
    // would mean an atomic per nonce — millions of them per dispatch, on one
    // address, which is the one way to make a search that touches no memory
    // start touching memory. Held here instead and merged once below, so the
    // per-nonce cost is a compare against a register.
    var best = 0xffffffffu;
    var best_lead = 0xffu;
    var best_nonce = 0u;

    for (var step = 0u; step < params.nonces_per_lane; step = step + 1u) {
        let nonce = first + step;
        let top = second_top(first_pass(lane_prefix, nonce));
        let high = byte_reverse(top);
        let lead = top & 0xffu;

        // **Word seven decides almost every nonce.** The target comparison
        // reads further words only on a tie in this one, and the rank only
        // when it is zero. Those two cases, about one nonce in 2^32, take the
        // whole digest instead, through the same `hash_nonce` the probe checks
        // against `rust-bitcoin`; `sha256::HeaderHasher::screen` on the host
        // makes the same split.
        if (top == 0u || high == threshold[0]) {
            let digest = hash_nonce(nonce);
            if (meets_threshold(digest, threshold)) {
                record_winner(nonce);
            }
            let candidate = rank(digest);
            if (candidate < best) {
                best = candidate;
                best_lead = lead;
                best_nonce = nonce;
            }
            continue;
        }

        if (high < threshold[0]) {
            record_winner(nonce);
        }

        // **A mask and a compare, and only then the rank.** The value's most
        // significant byte is the low byte of word seven — no reversal needed
        // to read one byte — and a digest whose leading byte is above the best
        // seen cannot beat it. Ranking every digest instead costs a measured
        // 1% of this shader's rate; this leaves the same answer and enters the
        // full comparison about once in every 256 nonces, falling as the
        // lane's best improves.
        if (lead <= best_lead) {
            let candidate = rank_of_high(high);
            if (candidate < best) {
                best = candidate;
                best_lead = lead;
                best_nonce = nonce;
            }
        }
    }

    // One atomic per lane rather than per nonce: 256 hashes' worth of work for
    // a single contended write.
    //
    // **The nonce is not written under the same atomic**, because there is no
    // 64-bit atomic here to write the pair with. The lane holding the dispatch
    // best always reaches its store — nothing smaller can displace it — so the
    // only interleaving that loses is a lane that read its own rank back before
    // a better one landed and stored afterwards. That leaves a real nonce from
    // this dispatch that is not quite the best one, which costs a statistic a
    // little accuracy and costs correctness nothing: the host hashes whatever
    // nonce it is handed and reports what that hash is actually worth.
    atomicMin(&winners.best, best);
    if (atomicLoad(&winners.best) == best) {
        winners.best_nonce = best_nonce;
    }
}

/// A lane's best hash so far: the rank, its leading byte for the pre-filter,
/// and the nonce behind it.
struct Best {
    rank: u32,
    lead: u32,
    nonce: u32,
}

/// One version's word seven through the same screen `search` applies inline:
/// a winner when its top word is below the target's, the whole digest on a tie
/// or a zero word, and the rank behind the leading-byte pre-filter.
fn screen_version(
    top: u32,
    midstate: array<u32, 8>,
    nonce: u32,
    threshold: array<u32, 8>,
    best: ptr<function, Best>,
) {
    let high = byte_reverse(top);
    let lead = top & 0xffu;
    if (top == 0u || high == threshold[0]) {
        let digest = hash_nonce_with(midstate, nonce);
        if (meets_threshold(digest, threshold)) {
            record_winner(nonce);
        }
        let candidate = rank(digest);
        if (candidate < (*best).rank) {
            *best = Best(candidate, lead, nonce);
        }
        return;
    }
    if (high < threshold[0]) {
        record_winner(nonce);
    }
    if (lead <= (*best).lead) {
        let candidate = rank_of_high(high);
        if (candidate < (*best).rank) {
            *best = Best(candidate, lead, nonce);
        }
    }
}

/// [`search`] over two versions of one header at once: AsicBoost.
///
/// The two headers differ only in a rolled version bit, which sits in the
/// first 64 bytes, so they have two midstates and one final block. That
/// block's message schedule is therefore computed once per nonce and its
/// rounds applied to both states — `sha256_rounds_x2_4_64`, generated like the
/// rest. Measured as a prototype at +9.5% per hash against `search`.
///
/// **A winner is recorded as its nonce alone**, once for each version that
/// meets the target. The host re-verifies every nonce against both headers,
/// and the header that verifies is the version the share is reported under:
/// the version comes from `rust-bitcoin`, never from here, and the winner
/// buffer keeps the layout every other caller reads.
@compute @workgroup_size(64)
fn search_pair(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if (lane >= params.lanes) {
        return;
    }

    let threshold = threshold_words();
    let midstate_a = midstate_words();
    let midstate_b = pair_midstate_words();
    let prefix_a = prefix_of(midstate_a);
    let prefix_b = prefix_of(midstate_b);
    let first = params.base_nonce + lane * params.nonces_per_lane;
    var best = Best(0xffffffffu, 0xffu, 0u);

    for (var step = 0u; step < params.nonces_per_lane; step = step + 1u) {
        let nonce = first + step;
        let block = tail_block(nonce);
        let worked = sha256_rounds_x2_4_64(
            after_round_3(prefix_a, block[3]),
            after_round_3(prefix_b, block[3]),
            block,
        );
        let top_a = second_top(add_state(midstate_a, worked[0]));
        let top_b = second_top(add_state(midstate_b, worked[1]));
        screen_version(top_a, midstate_a, nonce, threshold, &best);
        screen_version(top_b, midstate_b, nonce, threshold, &best);
    }

    atomicMin(&winners.best, best.rank);
    if (atomicLoad(&winners.best) == best.rank) {
        winners.best_nonce = best.nonce;
    }
}

/// Write back every digest for a fixed span of nonces, for the correctness
/// probe. Never used by the search: it exists so the host can compare whole
/// digests against `rust-bitcoin` rather than only the target verdict.
@group(0) @binding(2) var<storage, read_write> digests: array<u32>;

@compute @workgroup_size(64)
fn probe(@builtin(global_invocation_id) id: vec3<u32>) {
    let lane = id.x;
    if (lane >= params.lanes) {
        return;
    }

    let digest = hash_nonce(params.base_nonce + lane);
    for (var word = 0u; word < 8u; word = word + 1u) {
        digests[lane * 8u + word] = digest[word];
    }
}
