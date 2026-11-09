//! Verify a real template and the block built from it — everything except the
//! proof of work.
//!
//! The companion to `lottery.rs`, and the only part of this project that has
//! anything to say about mainnet. The node hands out a template; we assemble
//! the block we would grind and check it against every rule that does not
//! involve hashing, ending with the node's own verdict.
//!
//! That last step is the one worth having. `getblocktemplate` in **proposal**
//! mode validates a submitted block exactly as `submitblock` would but skips
//! the proof-of-work check, so a mainnet template can be turned into a block
//! and fully validated by Core without mining anything. A builder that only
//! ever proves itself on regtest has proved itself against a chain with no
//! transactions in it; this is the same builder judged on real ones.
//!
//! The witness commitment gets special treatment: everywhere else in this
//! repository it is copied from the template, because Core computed it for
//! exactly this transaction set. Here it is **recomputed from the block** and
//! compared, which is the check that would catch the transaction set being
//! modified without the commitment being redone.

use bitcoin::{
    Block, ScriptBuf, Transaction, Txid, WitnessMerkleNode, block::Version,
    consensus::encode::serialize, hashes::Hash,
};
use serde_json::{Value, json};

use crate::logger::Logger;

use super::{
    block::{VersionRoll, build_block, check_block, subsidy_at},
    rpc::Rpc,
    template::Template,
};

/// BIP141's block weight limit.
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// The sigop limit, in the weight-scaled units BIP141 counts them in.
const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// The 32-byte reserved value, repeated here because the commitment is being
/// recomputed rather than trusted.
const WITNESS_RESERVED_VALUE: [u8; 32] = [0u8; 32];

/// With `rolling` — `MINER_TEMPLATE_VERSION_ROLLING` — the block is built under
/// the first rolled version that differs from the template's, which is the
/// one the GPU search pairs with it. Proposal mode is then the node's verdict
/// on a rolled block, which is the only mainnet evidence obtainable for one
/// before a real block depends on it.
pub fn run(rpc: &Rpc, payout: &ScriptBuf, rolling: bool, log: &Logger) -> Result<(), String> {
    let template = Template::fetch(rpc)?;
    let time = template.curtime.max(template.mintime);
    let mut block = build_block(&template, payout, 0, time)?;

    log.log(format!(
        "validating a {} template: height {}, {} transactions, {} sat fees",
        rpc.chain().name(),
        template.height,
        template.transactions.len(),
        template.fees,
    ));

    if rolling {
        let announced = template.version as u32;
        let mask = template.rollable_bits();
        match VersionRoll::new(announced, mask).nth(1) {
            Some(rolled) => {
                block.header.version = Version::from_consensus(rolled as i32);
                log.log(format!(
                    "rolled the version from {announced:08x} to {rolled:08x}, inside the \
                     template's rollable bits {mask:08x}"
                ));
            }
            None => log.log(format!(
                "version rolling is on, but template version {announced:08x} has no rollable \
                 bits{}: validating it unrolled",
                if template.vbavailable.is_none() {
                    " (no vbavailable)"
                } else {
                    ""
                }
            )),
        }
    }

    check_block(&block, &template)?;
    log.log("our own check_block passes");

    check_subsidy(rpc, &template, log)?;
    check_witness_commitment(&block, &template, log)?;
    check_weight_and_sigops(&block, log)?;
    check_dependency_order(&block, log)?;
    check_no_duplicates(&block, log)?;

    // The node's verdict on the whole thing, proof of work aside.
    propose(rpc, &block, log)
}

/// The coinbase value the node offered has to be the subsidy we compute plus
/// the fees it listed. Getting this wrong in either direction is a block that
/// is rejected for `bad-cb-amount`, and it is the arithmetic most easily
/// fooled by a template whose fee field means something slightly different.
fn check_subsidy(rpc: &Rpc, template: &Template, log: &Logger) -> Result<(), String> {
    let interval = rpc.chain().halving_interval();
    let ours = subsidy_at(template.height, interval);
    let implied = template.subsidy();

    if ours != implied {
        return Err(format!(
            "our subsidy at height {} is {ours} sat, the template implies {implied} sat",
            template.height
        ));
    }
    if ours + template.fees != template.coinbase_value {
        return Err(format!(
            "subsidy {ours} plus fees {} is not the offered coinbase value {}",
            template.fees, template.coinbase_value
        ));
    }

    log.log(format!(
        "coinbase value {} sat = subsidy {ours} + fees {} ({} halvings in)",
        template.coinbase_value,
        template.fees,
        template.height / interval,
    ));
    Ok(())
}

/// Recompute the witness commitment from the block and compare it against the
/// one the template supplied.
fn check_witness_commitment(
    block: &Block,
    template: &Template,
    log: &Logger,
) -> Result<(), String> {
    let Some(expected) = &template.witness_commitment else {
        log.log("the template asked for no witness commitment, so there is none to check");
        return Ok(());
    };

    // The coinbase's wtxid is defined as all zeros rather than being computed,
    // which is what stops the commitment from having to commit to itself.
    let mut wtxids = vec![WitnessMerkleNode::from_byte_array([0u8; 32]).to_raw_hash()];
    for transaction in block.txdata.iter().skip(1) {
        wtxids.push(transaction.compute_wtxid().to_raw_hash());
    }

    let root = bitcoin::merkle_tree::calculate_root(wtxids.into_iter())
        .ok_or("the block has no transactions to build a witness root from")?;
    let root = WitnessMerkleNode::from_raw_hash(root);

    let commitment = Block::compute_witness_commitment(&root, &WITNESS_RESERVED_VALUE);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    let script = ScriptBuf::from_bytes(script);

    if &script != expected {
        return Err(format!(
            "the commitment we computed is {} and the template's is {}",
            script.to_hex_string(),
            expected.to_hex_string(),
        ));
    }

    log.log(format!(
        "the witness commitment recomputed from {} transactions matches the template's",
        block.txdata.len()
    ));
    Ok(())
}

fn check_weight_and_sigops(block: &Block, log: &Logger) -> Result<(), String> {
    let weight = block.weight().to_wu();
    if weight > MAX_BLOCK_WEIGHT {
        return Err(format!(
            "the block weighs {weight}, over the {MAX_BLOCK_WEIGHT} limit"
        ));
    }

    let serialized = serialize(block).len();
    log.log(format!(
        "weight {weight} of {MAX_BLOCK_WEIGHT} ({:.1}% full), {serialized} bytes serialized",
        weight as f64 / MAX_BLOCK_WEIGHT as f64 * 100.0,
    ));

    // Sigops are only counted here to the extent they can be without the
    // spent outputs, which a miner does not have: this counts what is visible
    // in the block itself and says so rather than implying a full count.
    let visible: u64 = block
        .txdata
        .iter()
        .map(|transaction| legacy_sigops(transaction) * 4)
        .sum();
    if visible > MAX_BLOCK_SIGOPS_COST {
        return Err(format!(
            "the visible sigop cost is already {visible}, over the {MAX_BLOCK_SIGOPS_COST} limit"
        ));
    }
    log.log(format!(
        "visible sigop cost {visible} of {MAX_BLOCK_SIGOPS_COST}, counting only what the block \
         itself shows"
    ));
    Ok(())
}

/// Sigops countable from the block alone: the scriptSigs and scriptPubKeys it
/// contains, without the P2SH redeem scripts or witnesses that need the spent
/// outputs to resolve.
fn legacy_sigops(transaction: &Transaction) -> u64 {
    let inputs: usize = transaction
        .input
        .iter()
        .map(|input| input.script_sig.count_sigops_legacy())
        .sum();
    let outputs: usize = transaction
        .output
        .iter()
        .map(|output| output.script_pubkey.count_sigops_legacy())
        .sum();
    (inputs + outputs) as u64
}

/// A transaction spending an output created in the same block has to come
/// after it. Core hands templates out already ordered, so this is a check on
/// our assembly preserving that order rather than on the node's selection.
fn check_dependency_order(block: &Block, log: &Logger) -> Result<(), String> {
    let mut seen: Vec<Txid> = Vec::with_capacity(block.txdata.len());
    let mut dependencies = 0usize;

    for transaction in &block.txdata {
        for input in &transaction.input {
            let parent = input.previous_output.txid;
            if block
                .txdata
                .iter()
                .any(|other| other.compute_txid() == parent)
            {
                if !seen.contains(&parent) {
                    return Err(format!(
                        "{} spends {parent}, which is in the same block but later",
                        transaction.compute_txid()
                    ));
                }
                dependencies += 1;
            }
        }
        seen.push(transaction.compute_txid());
    }

    log.log(format!(
        "transaction order is dependency-correct, with {dependencies} in-block spends"
    ));
    Ok(())
}

fn check_no_duplicates(block: &Block, log: &Logger) -> Result<(), String> {
    let mut txids: Vec<Txid> = block.txdata.iter().map(Transaction::compute_txid).collect();
    let total = txids.len();
    txids.sort_unstable();
    txids.dedup();
    if txids.len() != total {
        return Err(format!(
            "the block has {total} transactions and only {} distinct txids",
            txids.len()
        ));
    }
    log.log(format!("{total} transactions, all distinct"));
    Ok(())
}

/// Ask the node to validate the block without a valid proof of work.
///
/// BIP23 proposal mode: the node runs the same checks `submitblock` would,
/// stopping short of the hash, and answers null when there is nothing wrong.
/// This is the only external verdict available on a block that will never be
/// mined.
fn propose(rpc: &Rpc, block: &Block, log: &Logger) -> Result<(), String> {
    let hex = super::block::serialize_block(block);
    let verdict = rpc.call(
        "getblocktemplate",
        json!([{
            "mode": "proposal",
            "data": hex,
            "rules": ["segwit"],
        }]),
    )?;

    match verdict {
        Value::Null => {
            log.log(format!(
                "the node validated the proposal: {} bytes, everything but the proof of work",
                hex.len() / 2
            ));
            Ok(())
        }
        Value::String(reason) => Err(format!("the node rejected the proposal: {reason}")),
        other => Err(format!("the node answered the proposal with {other}")),
    }
}
