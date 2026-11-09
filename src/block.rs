//! Building a candidate block from a template: the coinbase, the merkle root,
//! and the 80-byte header the search then grinds.
//!
//! Everything here is consensus-critical and none of it is forgiving. A wrong
//! BIP34 height, a missing witness commitment or a merkle root computed over
//! the wrong hashes all produce a block the node rejects, which is exactly why
//! this is built and debugged against regtest before any of it reaches a
//! shader.

use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Target, Transaction,
    TxIn, TxMerkleNode, TxOut, Witness,
    absolute::LockTime,
    block::{Header, Version},
    consensus::encode::serialize,
    hashes::Hash,
    script::{self, PushBytesBuf},
    transaction,
};

use super::template::Template;
use crate::constants::{MINER_COINBASE_TAG_PREFIX, MINER_COINBASE_TAGS};

/// The witness reserved value a coinbase must carry when the block commits to
/// a witness merkle root: 32 zero bytes, per BIP141.
const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// The byte a tag is wrapped in on its way into the scriptSig, so
/// [`MINER_COINBASE_TAGS`] holds names rather than punctuation.
///
/// A slash on each side is what every pool does — `/Slush/`, `/ViaBTC/` — and it
/// is convention rather than consensus: the bytes are opaque to the node either
/// way. What the convention buys is a readable boundary in a scriptSig that also
/// holds a height, an extranonce and, on a real pool's block, other miners'
/// merged-mining tags.
///
/// One ASCII byte, because the whole point of these bytes is being read as ASCII
/// in a block explorer.
const COINBASE_TAG_DELIMITER: u8 = b'/';

/// The longest tag that still leaves a legal scriptSig, delimiters included.
///
/// Consensus caps the coinbase scriptSig at 100 bytes. The height costs at most
/// five (one opcode, four bytes — enough past any height this chain will see for
/// centuries) and the extranonce costs nine, which leaves 86 for the tag's push.
/// Stopping at 75 is the largest direct push, so the script stays canonical
/// without an `OP_PUSHDATA1`, and 75 characters is more than anyone should want
/// to write into every block.
///
/// This bounds what is pushed, so a [`MINER_COINBASE_TAGS`] entry has two fewer
/// bytes than this to spend — the delimiters are part of the tag by the time the
/// scriptSig sees it.
pub const COINBASE_TAG_MAX: usize = 75;

// Checked here rather than at mining time: a tag too long for the scriptSig is a
// typo in a constant, and it should cost a failed build rather than a template
// fetched, a GPU opened and a search that dies on its first coinbase. Every
// entry is checked, not just the first — the rotation reaches all of them, and
// the one that overruns would otherwise wait for its own height to say so.
const _: () = {
    let mut index = 0;
    while index < MINER_COINBASE_TAGS.len() {
        let name = MINER_COINBASE_TAGS[index].as_bytes();

        // Two for the delimiters `wrap_coinbase_tag` adds.
        assert!(
            name.len() + 2 <= COINBASE_TAG_MAX,
            "a MINER_COINBASE_TAGS entry is longer than the coinbase scriptSig has room for"
        );

        // A leftover `/sheroz/` from before the wrapping moved into the code
        // would be pushed as `//sheroz//` and stay that way in the chain, which
        // is exactly the kind of mistake that is only noticed in an explorer.
        assert!(
            name.is_empty()
                || (name[0] != COINBASE_TAG_DELIMITER
                    && name[name.len() - 1] != COINBASE_TAG_DELIMITER),
            "a MINER_COINBASE_TAGS entry carries its own delimiter: the entries are names, \
             and the slashes are added when the tag is built"
        );

        index += 1;
    }
};

/// A tag name as it goes into the scriptSig: wrapped in
/// `COINBASE_TAG_DELIMITER`.
///
/// An empty name stays empty rather than becoming a bare `//`, so an entry can
/// be blanked out to mine a plain coinbase at that point in the rotation.
pub fn wrap_coinbase_tag(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let delimiter = COINBASE_TAG_DELIMITER as char;
    // format!("{delimiter}{name}{delimiter}")
    format!("{delimiter}{MINER_COINBASE_TAG_PREFIX}{name}{delimiter}")
}

/// The rotation entry a coinbase carries, as a bare name: the height picks
/// where the rotation starts and the attempt — how many templates this run has
/// already ground at that height — moves it that many entries along.
///
/// The height was once the whole key, which made the tag a property of the
/// block rather than of the process: the same height always produced the same
/// tag, so a won block could be explained from the chain alone. At mainnet
/// difficulty a height is not one search but a long run of templates abandoned
/// because the node found better work, and keying on the height alone meant one
/// tag for the whole stretch. The attempt is what breaks that up.
///
/// What it costs is the prediction: the height no longer says on its own which
/// entry a block should have carried, only where its run started counting. A
/// won block's tag is still readable from its own coinbase, which is where
/// anyone reads it anyway. What it keeps is stability where stability matters —
/// [`crate::template::Template::attempt`] is fixed for the life of a
/// template, so every rebuild of one coinbase still agrees.
///
/// An empty list has no tag to give, and `rem_euclid` keeps the index in range
/// for a height of any sign — a negative one cannot come from a template, but it
/// can come from a test, and wrapping is a better answer there than a panic.
pub fn coinbase_tag_name_for(height: i64, attempt: u64) -> &'static str {
    if MINER_COINBASE_TAGS.is_empty() {
        return "";
    }
    let period = MINER_COINBASE_TAGS.len();

    // Each side is reduced before they are added, so no height and no number of
    // abandoned templates can carry the sum out of range.
    let start = height.rem_euclid(period as i64) as usize;
    let step = (attempt % period as u64) as usize;

    MINER_COINBASE_TAGS[(start + step) % period]
}

/// The tag the coinbase built from a template at `height` on its `attempt`
/// carries: [`coinbase_tag_name_for`] put through [`wrap_coinbase_tag`], which
/// is the byte string that reaches the chain.
pub fn coinbase_tag_for(height: i64, attempt: u64) -> String {
    wrap_coinbase_tag(coinbase_tag_name_for(height, attempt))
}

/// The last nonce a header can carry. The field is 32 bits, which is the
/// reason the extranonce exists at all: at 429 MH/s this is ten seconds of work
/// before the coinbase has to change.
///
/// This lives here rather than in whichever module happens to walk it, because
/// it is a property of the header.
pub const NONCE_MAX: u32 = u32::MAX;

/// Where a search's extranonce walk stands.
///
/// A named type rather than a bare `u64`: a search already takes a worker
/// count, and one more unlabelled integer beside it is a bug that compiles. It also gives
/// the wrap-around a single home, below.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Extranonce(pub u64);

impl Extranonce {
    /// The start every search used before the walk could begin anywhere else,
    /// and still the default. A run that starts here is one anybody can repeat.
    pub const ZERO: Self = Self(0);

    /// The extranonce `step` on from this one.
    ///
    /// Wrapping rather than checked, and that is a decision rather than a
    /// shortcut. Reaching 2^64 by walking is not possible — each roll follows a
    /// whole nonce space, ten seconds of this GPU, so the space is 5.9 x 10^12
    /// years wide — which leaves a start already near the end as the only way to
    /// arrive there. Wrapping costs one repeated merkle root; a checked add
    /// would cost the run.
    pub fn advance(self, step: u64) -> Self {
        Self(self.0.wrapping_add(step))
    }
}

impl std::fmt::Display for Extranonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Build the coinbase transaction for a template.
///
/// Three things make this valid rather than merely well-formed:
///
/// - the scriptSig opens with the block height as a minimally-encoded number,
///   which is BIP34 and is checked by the node against its own idea of the
///   height;
/// - the input witness is the 32-byte reserved value, without which the
///   witness commitment cannot be verified;
/// - the last output is the BIP141 commitment, which the node recomputes from
///   the block's witness merkle root.
///
/// The extranonce follows the height in the scriptSig. It exists so the search
/// can change the merkle root — and therefore the whole header prefix — once
/// the 32-bit nonce space is exhausted.
///
/// The tag follows the extranonce, so the extranonce stays immediately after
/// the height where every test and every log line expects it. It is derived
/// from the template's own height and attempt by [`coinbase_tag_for`] rather
/// than passed in alongside it: every caller holding one template gets one
/// tag, and threading it separately would let two of them disagree about a
/// coinbase they are both rebuilding.
pub fn build_coinbase(
    template: &Template,
    payout: &ScriptBuf,
    extranonce: u64,
) -> Result<Transaction, String> {
    let mut builder = script::Builder::new()
        .push_int(template.height)
        .push_slice(extranonce.to_le_bytes());

    let tag = coinbase_tag_for(template.height, template.attempt);

    // An empty tag pushes nothing at all rather than a zero-length push, so
    // turning it off leaves a coinbase byte-identical to one built without it.
    if !tag.is_empty() {
        let pushed = PushBytesBuf::try_from(tag.as_bytes().to_vec()).map_err(|error| {
            format!("the coinbase tag {tag:?} cannot be pushed into a scriptSig: {error}")
        })?;
        builder = builder.push_slice(pushed);
    }

    let script_sig = builder.into_script();

    // Core enforces both bounds on the coinbase scriptSig; hitting either means
    // the height, the extranonce encoding or the tag grew past what the budget
    // behind `COINBASE_TAG_MAX` assumed.
    let length = script_sig.len();
    if !(2..=100).contains(&length) {
        return Err(format!(
            "the coinbase scriptSig must be 2 to 100 bytes, built {length} for height {} \
             with the {}-byte tag {tag:?}",
            template.height,
            tag.len()
        ));
    }

    let mut witness = Witness::new();
    witness.push(WITNESS_RESERVED_VALUE);

    let mut output = vec![TxOut {
        value: Amount::from_sat(template.coinbase_value),
        script_pubkey: payout.clone(),
    }];

    // A template with no commitment is a pre-segwit or non-segwit-rules
    // template; adding an unrequested OP_RETURN would break it, so this
    // follows the node rather than always emitting one.
    if let Some(commitment) = &template.witness_commitment {
        output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: commitment.clone(),
        });
    }

    Ok(Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness,
        }],
        output,
    })
}

/// Assemble the full candidate block: coinbase first, then the template's
/// transactions in the order the node gave them, which is already
/// dependency-ordered.
///
/// The header's merkle root is computed over transaction ids, never witness
/// ids; the witness side is committed to separately by the coinbase output.
pub fn build_block(
    template: &Template,
    payout: &ScriptBuf,
    extranonce: u64,
    time: u32,
) -> Result<Block, String> {
    let coinbase = build_coinbase(template, payout, extranonce)?;

    let mut txdata = Vec::with_capacity(template.transactions.len() + 1);
    txdata.push(coinbase);
    txdata.extend(template.transactions.iter().cloned());

    let mut block = Block {
        header: Header {
            version: Version::from_consensus(template.version),
            prev_blockhash: template.previous_block_hash,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: template.bits,
            nonce: 0,
        },
        txdata,
    };

    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or("the block has no transactions to build a merkle root from")?;

    Ok(block)
}

/// Re-derive the header from a block whose coinbase changed, keeping the rest
/// of the block untouched.
///
/// This is the cheap step the search takes between extranonce values: one
/// merkle root over the same transaction set, rather than a whole rebuild.
pub fn refresh_merkle_root(block: &mut Block) -> Result<(), String> {
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or("the block has no transactions to build a merkle root from")?;
    Ok(())
}

/// The sixteen header bits BIP320 sets aside for miners to roll, and the mask
/// all three pools measured during development answered `mining.configure` with.
///
/// Here rather than in the pool client because it is a property of BIP320 and
/// not of any protocol: the solo search rolls inside it too, through
/// [`Template::rollable_bits`], and must not depend on `stratum/` to do so. A
/// second spelling of a constant is a second thing to keep in step.
pub const BIP320_MASK: u32 = 0x1fff_e000;

/// The top three bits of a BIP9 version, `001`, which a rolled version must
/// keep: a version that opens with anything else is not read as versionbits.
const VERSIONBITS_TOP_MASK: u32 = 0xe000_0000;
const VERSIONBITS_TOP_BITS: u32 = 0x2000_0000;

/// The versions one job or template is searched under, in order.
///
/// **The middle dimension of the walk: nonce, then version, then extranonce.**
/// The order is a cost argument rather than a correctness one. Every dimension
/// finds winners at the same rate, and they differ only in what a roll costs:
/// a nonce is free, a version costs one compression to rebuild the midstate,
/// and an extranonce costs a coinbase hash plus the whole merkle branch before
/// the midstate. So the cheapest roll goes innermost. Rolling the version
/// faster than the nonce would throw away exactly the optimisation `sha256.rs`
/// exists for: the rolled bits sit in the header's first 64 bytes, so a new
/// version invalidates the midstate and a new nonce does not.
///
/// A mask of zero yields exactly one version — the one announced — which is
/// what "version rolling off" is, with no branch anywhere in the hot loop to
/// express it.
///
/// Two callers. The share search rolls the mask a pool agreed to, and the
/// ambiguity rule in [`Self::new`] is about that case. The solo block search
/// rolls [`Template::rollable_bits`], which excludes the template's own bits by
/// construction, so the rule is inert there.
#[derive(Clone, Copy, Debug)]
pub struct VersionRoll {
    base: u32,
    mask: u32,
    counter: u64,
    span: u64,
}

impl VersionRoll {
    pub fn new(base: u32, mask: u32) -> Self {
        // **No rolling at all when the announced version has bits inside the
        // mask.** BIP310 says what goes back in `mining.submit` is the rolled
        // bits and leaves how the pool puts them back unstated, so pools
        // differ. The spec reading rebuilds `(announced & !mask) | submitted`;
        // Pool B computes `announced ^ submitted`, measured 18 September
        // 2026 by reading its source. The two agree exactly when the announced
        // version has no bits set inside the mask, and disagree on *every*
        // share when it does — and no choice of submitted bits satisfies both,
        // because the disagreement is about the pool's own announcement rather
        // than about anything this client sends.
        //
        // So where it is ambiguous, this rolls nothing: a client that guessed
        // would have every share silently rejected against half the pools in
        // the world, for a header the pool cannot reproduce, which looks
        // exactly like a byte-order bug. Both pools measured announce
        // `20000000` and roll the full space; nothing is given up in practice.
        let mask = if base & mask == 0 { mask } else { 0 };
        Self {
            base,
            mask,
            counter: 0,
            span: 1u64 << mask.count_ones(),
        }
    }

    /// How many versions the walk yields: a power of two, and one when nothing
    /// rolls.
    pub fn span(&self) -> u64 {
        self.span
    }
}

impl Iterator for VersionRoll {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        if self.counter >= self.span {
            return None;
        }
        let version = (self.base & !self.mask) | deposit(self.counter as u32, self.mask);
        self.counter += 1;
        Some(version)
    }
}

/// Scatter a counter's low bits into the mask's set bits, lowest to lowest.
///
/// BIP320's mask is sixteen contiguous bits and a shift would do, but a mask is
/// whatever the pool answered — or whatever a template leaves free — and may
/// not be assumed otherwise. Bits outside the mask are never touched, which is
/// the property that matters: a pool rebuilds the header as `(announced &
/// !mask) | (submitted & mask)`, so a bit rolled outside the mask is a header
/// the pool cannot reproduce, and for a solo block it is a bit the template
/// never cleared for rolling.
fn deposit(counter: u32, mask: u32) -> u32 {
    let mut deposited = 0u32;
    let mut source = counter;
    let mut remaining = mask;
    while remaining != 0 && source != 0 {
        let lowest = remaining.isolate_lowest_one();
        if source & 1 == 1 {
            deposited |= lowest;
        }
        source >>= 1;
        remaining ^= lowest;
    }
    deposited
}

/// Whether a header meets the target, using the same comparison the node will.
pub fn meets_target(header: &Header, target: Target) -> bool {
    target.is_met_by(header.block_hash())
}

/// Grind a header until it meets the target, for the experiments rather than
/// for mining: one thread, no extranonce roll, no stop flag.
///
/// Every deliberately invalid block still has to carry **valid proof of work**.
/// Core checks the hash before almost anything else, so a broken block that is
/// also unsolved comes back as `high-hash` and the rule under test is never
/// reached. This is what re-solves one after it has been tampered with, and it
/// is only reasonable at regtest difficulty, where it succeeds in a handful of
/// tries.
pub fn solve(block: &mut Block, target: Target) -> Result<u32, String> {
    for nonce in 0..=u32::MAX {
        block.header.nonce = nonce;
        if meets_target(&block.header, target) {
            return Ok(nonce);
        }
    }
    Err("no nonce in the whole space solved this header".into())
}

/// The block subsidy at a height, halving every `interval` blocks.
///
/// Core computes this rather than being told it, so a template's
/// `coinbasevalue` minus its fees has to agree with this — which is the check
/// that catches a fee total being misread as subsidy or the other way round.
/// After 64 halvings the subsidy is zero and the coinbase is fees only.
pub fn subsidy_at(height: i64, interval: i64) -> u64 {
    let halvings = height / interval;
    if halvings >= 64 {
        return 0;
    }
    (50 * 100_000_000u64) >> halvings
}

/// Serialize a block as the hex string `submitblock` expects.
pub fn serialize_block(block: &Block) -> String {
    bitcoin::hex::DisplayHex::to_lower_hex_string(serialize(block).as_slice())
}

/// The compact target a template carries, expanded, for reporting.
pub fn difficulty_of(bits: CompactTarget) -> f64 {
    Target::from_compact(bits).difficulty_float()
}

/// The difficulty a digest actually achieved: how many times harder than the
/// difficulty-1 target this particular hash turned out to be.
///
/// The inverse reading of the one above — that one asks what a target demands,
/// this one what a hash delivered — and the same scale, which is what makes the
/// two comparable. It is what `lottery` measures its distribution in and what a
/// pool dashboard calls a worker's best difficulty.
pub fn difficulty_of_hash(hash: &BlockHash) -> f64 {
    Target::from_le_bytes(hash.to_byte_array()).difficulty_float()
}

/// A block's own OP_RETURN commitment output, if it has one.
///
/// Used only by the checks below: it makes "the coinbase committed to the
/// witnesses" testable without reaching into output indices elsewhere.
pub fn commitment_output(block: &Block) -> Option<&TxOut> {
    block
        .txdata
        .first()?
        .output
        .iter()
        .find(|output| output.script_pubkey.is_op_return())
}

/// Everything about a candidate block that can be checked without a node.
///
/// The node is the authority, but it answers slowly and only in production;
/// these are the same conditions stated locally so a bug is caught in a test
/// rather than as a `bad-cb-height` from a live daemon.
pub fn check_block(block: &Block, template: &Template) -> Result<(), String> {
    let coinbase = block.txdata.first().ok_or("the block has no coinbase")?;

    if !coinbase.is_coinbase() {
        return Err("the first transaction is not a coinbase".into());
    }

    if block.txdata.len() != template.transactions.len() + 1 {
        return Err(format!(
            "the block has {} transactions, the template had {} plus a coinbase",
            block.txdata.len(),
            template.transactions.len()
        ));
    }

    // BIP34: the height opens the scriptSig, encoded exactly as Core encodes it.
    let expected_height = script::Builder::new()
        .push_int(template.height)
        .into_script();
    if !coinbase
        .input
        .first()
        .ok_or("the coinbase has no input")?
        .script_sig
        .as_bytes()
        .starts_with(expected_height.as_bytes())
    {
        return Err("the coinbase scriptSig does not open with the BIP34 height".into());
    }

    let paid: u64 = coinbase
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .sum();
    if paid > template.coinbase_value {
        return Err(format!(
            "the coinbase pays {paid} against an allowed {}",
            template.coinbase_value
        ));
    }

    if template.witness_commitment.is_some() {
        let commitment = commitment_output(block)
            .ok_or("the template wanted a witness commitment and the coinbase has none")?;
        if Some(&commitment.script_pubkey) != template.witness_commitment.as_ref() {
            return Err("the coinbase commitment does not match the template's".into());
        }

        let witness = &coinbase.input[0].witness;
        if witness.len() != 1 || witness.iter().next() != Some(&WITNESS_RESERVED_VALUE[..]) {
            return Err("the coinbase witness is not the 32-byte reserved value".into());
        }
    }

    if block.header.merkle_root
        != block
            .compute_merkle_root()
            .ok_or("the block has no merkle root")?
    {
        return Err("the header's merkle root does not match the transactions".into());
    }

    if block.header.time < template.mintime {
        return Err(format!(
            "the header time {} is below the template's mintime {}",
            block.header.time, template.mintime
        ));
    }

    check_version(block.header.version.to_consensus() as u32, template)
}

/// The version rule: a block either carries the template's version, or a
/// rolled one that only ever *added* bits the template left free.
///
/// Stated as three checks so a failure names which one broke: a rolled version
/// keeps BIP9's top bits, never clears a bit the template set — that bit is a
/// deployment the node is signalling for — and moves nothing outside
/// [`Template::rollable_bits`].
fn check_version(version: u32, template: &Template) -> Result<(), String> {
    let announced = template.version as u32;
    if version == announced {
        return Ok(());
    }
    if version & VERSIONBITS_TOP_MASK != VERSIONBITS_TOP_BITS {
        return Err(format!(
            "the rolled version {version:08x} does not open with BIP9's top bits 001"
        ));
    }
    let cleared = announced & !version;
    if cleared != 0 {
        return Err(format!(
            "the rolled version {version:08x} clears the template's bits {cleared:08x} \
             (template version {announced:08x})"
        ));
    }
    let outside = (version ^ announced) & !template.rollable_bits();
    if outside != 0 {
        return Err(format!(
            "the rolled version {version:08x} moves bits {outside:08x}, outside the template's \
             rollable bits {:08x} (template version {announced:08x})",
            template.rollable_bits()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::Template;
    use serde_json::json;

    #[test]
    fn a_hash_reports_the_difficulty_it_would_have_satisfied() {
        use bitcoin::{Network, blockdata::constants::genesis_block};

        // Difficulty 1's target is what every other difficulty is measured
        // against, so a hash sitting exactly on it is worth exactly 1.
        let one = difficulty_of_hash(&BlockHash::from_byte_array(Target::MAX.to_le_bytes()));
        assert!(
            (one - 1.0).abs() < 1e-9,
            "a hash at difficulty 1's target is worth 1, not {one}"
        );

        // The mainnet genesis hash is a published constant, and this is the
        // distinction the function exists to make: the chain's difficulty at
        // height 0 was 1, and the hash Satoshi actually found is 2536 times
        // harder than that — 0xffff * 2^208 over
        // 0x19d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f. A target
        // says what was demanded; a hash says what was delivered.
        let genesis = difficulty_of_hash(&genesis_block(Network::Bitcoin).block_hash());
        assert!(
            (genesis - 2_536.426_298_445_310_3).abs() < 1e-6,
            "the mainnet genesis hash is worth 2536.43, not {genesis}"
        );
    }

    #[test]
    fn an_extranonce_wraps_at_the_end_of_its_space_rather_than_panicking() {
        assert_eq!(Extranonce::ZERO.advance(1), Extranonce(1));
        assert_eq!(Extranonce(7).advance(4), Extranonce(11));

        // The end is unreachable by walking — 5.9 x 10^12 years of rolls — but
        // reachable by configuration, and a debug build panics on an overflowing
        // `+`. One repeated merkle root is the right price; a killed run is not.
        assert_eq!(Extranonce(u64::MAX).advance(1), Extranonce::ZERO);
        assert_eq!(Extranonce(u64::MAX).advance(3), Extranonce(2));
        assert_eq!(Extranonce(u64::MAX - 1).advance(1), Extranonce(u64::MAX));
    }

    #[test]
    fn an_extranonce_reaches_the_coinbase_whole() {
        // Eight bytes little-endian after the height push, per `build_coinbase`.
        // Worth pinning: the whole point of a configurable start is that the
        // number gets into the block, and every claim about disjoint headers
        // rests on it doing so exactly.
        let extranonce = Extranonce(0x0123_4567_89ab_cdef);
        let coinbase = build_coinbase(&template(), &payout(), extranonce.0)
            .expect("the sample coinbase should build");
        let script = coinbase.input[0].script_sig.as_bytes();

        assert!(
            script
                .windows(8)
                .any(|window| window == extranonce.0.to_le_bytes()),
            "the extranonce is not in the scriptSig: {}",
            coinbase.input[0].script_sig
        );
        // Fixed width, so the block's size does not shift as the walk rolls.
        let zero = build_coinbase(&template(), &payout(), 0).expect("should build");
        assert_eq!(zero.input[0].script_sig.len(), script.len());
    }

    #[test]
    fn the_coinbase_tag_reaches_the_block_as_readable_bytes() {
        let template = template();
        let coinbase = build_coinbase(&template, &payout(), 0).expect("coinbase should build");
        let script = coinbase.input[0].script_sig.as_bytes();

        // Whatever the tag is set to, it goes in verbatim and it goes in whole:
        // a block this miner wins carries it forever, so a silently truncated or
        // re-encoded tag would be found out far too late to fix.
        let wrapped = coinbase_tag_for(template.height, template.attempt);
        let tag = wrapped.as_bytes();
        if tag.is_empty() {
            // Height push plus the nine-byte extranonce push, nothing else.
            assert_eq!(script.len(), 2 + 9);
        } else {
            assert!(
                script.windows(tag.len()).any(|window| window == tag),
                "the tag is not in the scriptSig: {}",
                coinbase.input[0].script_sig
            );
            // Pushed with its own length byte, so the script stays parseable
            // rather than being raw bytes glued onto the end.
            assert_eq!(script[script.len() - tag.len() - 1], tag.len() as u8);
        }
    }

    #[test]
    fn the_tag_rotates_one_entry_per_height_and_repeats_on_the_same_one() {
        if MINER_COINBASE_TAGS.is_empty() {
            assert_eq!(coinbase_tag_for(101, 0), "");
            assert_eq!(coinbase_tag_for(101, 7), "");
            return;
        }

        // Consecutive heights walk consecutive entries and come back around
        // after a full cycle, on the first template of each.
        let period = MINER_COINBASE_TAGS.len() as i64;
        for height in 0..(period * 2) {
            assert_eq!(
                coinbase_tag_for(height, 0),
                wrap_coinbase_tag(MINER_COINBASE_TAGS[(height % period) as usize])
            );
            assert_eq!(
                coinbase_tag_for(height, 0),
                coinbase_tag_for(height + period, 0)
            );
        }

        // One template is asked for its tag once per extranonce by every
        // caller that rebuilds a coinbase mid-search — the answer has to be the
        // same every time or the merkle root moves under the extranonce walk.
        assert_eq!(coinbase_tag_for(842_000, 0), coinbase_tag_for(842_000, 0));
        assert_eq!(coinbase_tag_for(842_000, 9), coinbase_tag_for(842_000, 9));
    }

    #[test]
    fn the_tag_moves_on_with_every_template_ground_at_one_height() {
        if MINER_COINBASE_TAGS.is_empty() {
            return;
        }

        // The reason the attempt exists: a mainnet height is a long run of
        // templates abandoned for better work, and the rotation has to walk
        // during it rather than waiting for the next block. One attempt is one
        // step, which is the same step a height is.
        let period = MINER_COINBASE_TAGS.len() as u64;
        for attempt in 0..(period * 2) {
            assert_eq!(
                coinbase_tag_for(966_400, attempt),
                coinbase_tag_for(966_400 + attempt as i64, 0),
                "attempt {attempt} did not land where the same offset in height does"
            );
        }

        // A full cycle of abandoned templates comes back to where it started,
        // and every entry is reached on the way.
        let walked: Vec<String> = (0..period)
            .map(|attempt| coinbase_tag_for(966_400, attempt))
            .collect();
        let mut sorted = walked.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            MINER_COINBASE_TAGS
                .iter()
                .map(|name| wrap_coinbase_tag(name))
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        assert_eq!(coinbase_tag_for(966_400, period), walked[0]);

        // And the field is not merely consulted: the bytes the attempt selects
        // have to reach the scriptSig, since that is the only place the tag of
        // a won block can ever be read.
        let mut template = template();
        template.height = 966_400;
        for attempt in 0..period {
            template.attempt = attempt;
            let coinbase =
                build_coinbase(&template, &payout(), 0).expect("every attempt should build");
            let script = coinbase.input[0].script_sig.as_bytes();
            let tag = coinbase_tag_for(template.height, attempt);

            if tag.is_empty() {
                continue;
            }
            assert!(
                script
                    .windows(tag.len())
                    .any(|window| window == tag.as_bytes()),
                "attempt {attempt} did not carry {tag:?}: {}",
                coinbase.input[0].script_sig
            );
        }
    }

    #[test]
    fn the_whole_rotation_reaches_the_block_across_consecutive_heights() {
        // Not just the entry the sample height happens to land on: every entry
        // has to survive being pushed, and one that cannot would otherwise sit
        // in the constant until its own height came up.
        let mut template = template();
        for height in 1..=(MINER_COINBASE_TAGS.len() as i64) {
            template.height = height;
            let coinbase =
                build_coinbase(&template, &payout(), 0).expect("every rotation entry should build");
            let script = coinbase.input[0].script_sig.as_bytes();
            let wrapped = coinbase_tag_for(height, template.attempt);
            let tag = wrapped.as_bytes();

            if !tag.is_empty() {
                assert!(
                    script.windows(tag.len()).any(|window| window == tag),
                    "height {height} did not carry its tag: {}",
                    coinbase.input[0].script_sig
                );
            }
        }
    }

    #[test]
    fn a_name_reaches_the_block_wrapped_in_its_delimiters() {
        // The bytes in the chain are the wrapped form, so the wrapping is the
        // part worth pinning: the constant says `sheroz` and the block has to
        // say `/sheroz/`, with one delimiter on each side and no more.
        assert_eq!(
            wrap_coinbase_tag("ali"),
            format!("/{MINER_COINBASE_TAG_PREFIX}ali/")
        );
        assert_eq!(
            wrap_coinbase_tag("a"),
            format!("/{MINER_COINBASE_TAG_PREFIX}a/")
        );
        // Blanking an entry mines a plain coinbase at that height rather than
        // pushing a bare pair of delimiters.
        assert_eq!(wrap_coinbase_tag(""), "");

        let mut template = template();
        for (offset, name) in MINER_COINBASE_TAGS.iter().enumerate() {
            template.height = offset as i64;
            let coinbase = build_coinbase(&template, &payout(), 0).expect("should build");
            let script = coinbase.input[0].script_sig.as_bytes();

            if name.is_empty() {
                continue;
            }
            let expected = format!("/{MINER_COINBASE_TAG_PREFIX}{name}/");
            assert!(
                script
                    .windows(expected.len())
                    .any(|window| window == expected.as_bytes()),
                "height {} carried {name:?} unwrapped: {}",
                template.height,
                coinbase.input[0].script_sig
            );
        }
    }

    #[test]
    fn a_max_length_tag_still_fits_a_mainnet_height() {
        // The budget behind `COINBASE_TAG_MAX` claims a longest-tag scriptSig
        // clears 100 bytes at any height this chain will reach. Checked against a
        // four-byte height push — height 2^25 is around the year 2400 — because
        // the alternative is discovering it in a rejected block.
        let mut template = template();
        template.height = 1 << 25;

        let coinbase = build_coinbase(&template, &payout(), u64::MAX)
            .expect("a mainnet-scale height should build");
        let overhead = coinbase.input[0].script_sig.len()
            - coinbase_tag_for(template.height, template.attempt).len();

        assert!(
            overhead + COINBASE_TAG_MAX <= 100,
            "a {COINBASE_TAG_MAX}-byte tag plus {overhead} bytes of height and extranonce \
             overruns the 100-byte scriptSig"
        );
    }

    fn template() -> Template {
        Template::parse(&json!({
            "version": 536870912,
            "previousblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            "transactions": [],
            "coinbasevalue": 5000000000u64,
            "mintime": 1296688603u64,
            "curtime": 1785588946u64,
            "bits": "207fffff",
            "height": 101,
            "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
        }))
        .expect("the regtest-shaped template should parse")
    }

    fn payout() -> ScriptBuf {
        ScriptBuf::from_hex("0014329649f03db93aef2cf873e9b8544a446d38316d")
            .expect("the sample payout should be hex")
    }

    #[test]
    fn the_coinbase_opens_with_the_bip34_height() {
        let coinbase = build_coinbase(&template(), &payout(), 0).expect("coinbase should build");
        let script_sig = coinbase.input[0].script_sig.as_bytes();

        // Height 101 encodes as a one-byte push of 0x65.
        assert_eq!(&script_sig[..2], &[0x01, 0x65]);
        assert!(coinbase.is_coinbase());
    }

    #[test]
    fn the_coinbase_carries_the_reserved_witness_and_the_commitment() {
        let template = template();
        let coinbase = build_coinbase(&template, &payout(), 7).expect("coinbase should build");

        assert_eq!(coinbase.input[0].witness.len(), 1);
        assert_eq!(
            coinbase.input[0].witness.iter().next(),
            Some(&[0u8; 32][..])
        );
        assert_eq!(coinbase.output.len(), 2);
        assert_eq!(
            Some(&coinbase.output[1].script_pubkey),
            template.witness_commitment.as_ref()
        );
        assert_eq!(coinbase.output[1].value, Amount::ZERO);
    }

    #[test]
    fn the_extranonce_changes_the_merkle_root_and_nothing_else() {
        let template = template();
        let first = build_block(&template, &payout(), 0, template.curtime).expect("should build");
        let second = build_block(&template, &payout(), 1, template.curtime).expect("should build");

        assert_ne!(first.header.merkle_root, second.header.merkle_root);
        assert_eq!(first.header.prev_blockhash, second.header.prev_blockhash);
        assert_eq!(first.header.bits, second.header.bits);
        assert_eq!(first.txdata.len(), second.txdata.len());
    }

    #[test]
    fn a_freshly_built_block_passes_every_local_check() {
        let template = template();
        let block = build_block(&template, &payout(), 3, template.curtime).expect("should build");
        check_block(&block, &template).expect("a freshly built block should be valid");
    }

    #[test]
    fn a_tampered_merkle_root_is_caught_locally() {
        let template = template();
        let mut block =
            build_block(&template, &payout(), 3, template.curtime).expect("should build");
        block.header.merkle_root = TxMerkleNode::all_zeros();

        assert!(check_block(&block, &template).is_err());
    }

    #[test]
    fn an_overpaying_coinbase_is_caught_locally() {
        let template = template();
        let mut block =
            build_block(&template, &payout(), 3, template.curtime).expect("should build");
        block.txdata[0].output[0].value = Amount::from_sat(template.coinbase_value + 1);
        refresh_merkle_root(&mut block).expect("the root should recompute");

        assert!(check_block(&block, &template).is_err());
    }

    #[test]
    fn regtest_difficulty_one_is_reachable_by_grinding() {
        let template = template();
        let mut block =
            build_block(&template, &payout(), 0, template.curtime).expect("should build");

        // The regtest target is 0x207fffff, so a valid nonce is a handful of
        // hashes away. Finding one here proves the header serialization and
        // the target comparison agree end to end, without a node.
        let mut found = false;
        for nonce in 0..100_000u32 {
            block.header.nonce = nonce;
            if meets_target(&block.header, template.target) {
                found = true;
                break;
            }
        }

        assert!(found, "a regtest-difficulty nonce should exist below 100k");
        check_block(&block, &template).expect("the mined block should still be valid");
    }

    /// [`template`] at `version`, with a `vbavailable` naming `deployments`, so
    /// that [`Template::rollable_bits`] has something to roll.
    fn rolling_template(version: u32, deployments: serde_json::Value) -> Template {
        let mut value = json!({
            "version": version,
            "previousblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            "transactions": [],
            "coinbasevalue": 5000000000u64,
            "mintime": 1296688603u64,
            "curtime": 1785588946u64,
            "bits": "207fffff",
            "height": 101,
            "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
        });
        value["vbavailable"] = deployments;
        Template::parse(&value).expect("the rolling template should parse")
    }

    /// The template's block, built and solved under `version`.
    fn under_version(template: &Template, version: u32) -> Result<(), String> {
        let mut block = build_block(template, &payout(), 0, template.curtime)?;
        block.header.version = Version::from_consensus(version as i32);
        solve(&mut block, template.target)?;
        check_block(&block, template)
    }

    #[test]
    fn a_version_rolled_inside_the_mask_passes() {
        let template = rolling_template(0x2000_0000, json!({}));
        assert_eq!(template.rollable_bits(), BIP320_MASK);
        for version in [0x2000_2000, 0x3fff_e000, 0x2aaa_a000] {
            under_version(&template, version)
                .unwrap_or_else(|error| panic!("{version:08x} should pass: {error}"));
        }
    }

    #[test]
    fn a_rolled_version_that_clears_a_template_bit_is_caught_locally() {
        // Regtest's `testdummy` signalling on bit 28: that bit is the node's to
        // set, and a roll that clears it stops signalling for the deployment.
        let template = rolling_template(0x3000_0000, json!({"testdummy": 28}));
        let error = under_version(&template, 0x2000_2000).expect_err("bit 28 was cleared");
        assert!(
            error.contains("clears the template's bits 10000000"),
            "{error}"
        );
    }

    #[test]
    fn a_rolled_version_outside_the_mask_is_caught_locally() {
        let template = rolling_template(0x2000_0000, json!({}));

        let error = under_version(&template, 0x2000_1000).expect_err("bit 12 moved");
        assert!(error.contains("moves bits 00001000"), "{error}");

        // Bit 29 is one of BIP9's top bits, so moving it is named as that.
        let error = under_version(&template, 0x0000_2000).expect_err("bit 29 moved");
        assert!(error.contains("top bits 001"), "{error}");
    }

    #[test]
    fn a_rolled_version_without_bip9s_top_bits_is_caught_locally() {
        let template = rolling_template(0x2000_0000, json!({}));
        let error = under_version(&template, 0x6000_2000).expect_err("bit 30 set");
        assert!(error.contains("top bits 001"), "{error}");
    }

    #[test]
    fn a_rolled_bit_a_deployment_owns_is_caught_locally() {
        // Listed in `vbavailable` but not set by this template: the node knows
        // the deployment and is not signalling for it, so neither may this.
        let template = rolling_template(0x2000_0000, json!({"somefork": 20}));
        let error = under_version(&template, 0x2010_0000).expect_err("bit 20 is a deployment's");
        assert!(error.contains("moves bits 00100000"), "{error}");
        under_version(&template, 0x2020_0000).expect("bit 21 is free");
    }

    #[test]
    fn a_template_without_vbavailable_allows_only_its_own_version() {
        let template = template();
        assert_eq!(template.rollable_bits(), 0);
        under_version(&template, 0x2000_0000).expect("the template's own version");
        let error = under_version(&template, 0x2000_2000).expect_err("nothing may roll");
        assert!(error.contains("moves bits 00002000"), "{error}");
    }

    #[test]
    fn no_mask_is_one_version_and_therefore_no_rolling_at_all() {
        // "Version rolling off" is expressed as a mask of zero rather than as a
        // branch, so nothing in the hot loop has to know which it is.
        let versions: Vec<u32> = VersionRoll::new(0x2000_0000, 0).collect();
        assert_eq!(versions, vec![0x2000_0000]);
    }

    #[test]
    fn a_rolled_version_never_touches_a_bit_outside_the_mask() {
        // The property the pool depends on. It rebuilds the header as
        // `(announced & !mask) | (submitted & mask)`, so a bit rolled outside
        // the mask produces a header it cannot reproduce and a share it
        // rejects — which would look exactly like a byte-order bug.
        const MASK: u32 = 0x1fff_e000;
        let base = 0x2000_0000u32;

        let mut seen = std::collections::HashSet::new();
        for version in VersionRoll::new(base, MASK) {
            assert_eq!(
                version & !MASK,
                base & !MASK,
                "{version:08x} changed a bit outside the mask"
            );
            assert!(seen.insert(version), "{version:08x} was rolled twice");
        }
        assert_eq!(seen.len(), 1 << MASK.count_ones(), "2^16 versions");
    }

    #[test]
    fn a_mask_the_pool_chose_is_used_as_given_rather_than_assumed_contiguous() {
        // BIP320's mask is sixteen contiguous bits, and a shift would do for
        // it. A mask is whatever the pool answered, though, so the scatter is
        // general — and a client that assumed contiguity would roll bits
        // outside a sparse mask without ever noticing against the three pools
        // that send the usual one.
        const SPARSE: u32 = 0b1010_1000;
        let versions: Vec<u32> = VersionRoll::new(0, SPARSE).collect();

        assert_eq!(versions.len(), 8, "three set bits is eight versions");
        for version in &versions {
            assert_eq!(version & !SPARSE, 0, "{version:08b} escaped the mask");
        }
        // Counting in the mask's own bit order: 0, then the lowest set bit, and
        // so on through every combination.
        assert_eq!(versions[0], 0);
        assert_eq!(versions[1], 0b0000_1000);
        assert_eq!(versions[2], 0b0010_0000);
        assert_eq!(versions[3], 0b0010_1000);
        assert_eq!(versions[7], SPARSE);
    }

    #[test]
    fn nothing_rolls_when_the_two_readings_of_bip310_disagree() {
        // The compatibility property. A pool rebuilds a rolled version either
        // as `(announced & !mask) | submitted` — the spec reading — or as
        // `announced ^ submitted`, which is what Pool B's source does.
        // The two coincide only when the announced version has no bits inside
        // the mask, and no choice of submitted bits satisfies both otherwise.
        const MASK: u32 = 0x1fff_e000;

        // The ordinary case, and the one both measured pools are in: the whole
        // space is walked, and both readings rebuild what was hashed.
        let clean = 0x2000_0000u32;
        let versions: Vec<u32> = VersionRoll::new(clean, MASK).collect();
        assert_eq!(versions.len(), 1 << MASK.count_ones());
        for version in &versions {
            let submitted = version & MASK;
            assert_eq!((clean & !MASK) | submitted, *version, "the spec reading");
            assert_eq!(clean ^ submitted, *version, "Pool B's reading");
        }

        // The ambiguous case: one version, which is to say no rolling. Guessing
        // here would mean every share silently rejected against half the pools
        // in the world, for a header the pool cannot reproduce.
        let awkward = 0x2000_2000u32;
        assert_eq!(
            VersionRoll::new(awkward, MASK).collect::<Vec<_>>(),
            vec![awkward],
            "an announced version with bits inside the mask is not rolled"
        );
    }
}
