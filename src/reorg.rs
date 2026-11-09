//! Two blocks at one height, and what it takes to change the node's mind.
//!
//! The experiment: mine two competing blocks on the same
//! parent, watch the node keep the first and hold the second as a fork, then
//! extend the *second* and watch the chain reorganise onto it. It is the
//! shortest demonstration that "accepted" and "best chain" are different
//! claims — which is why `confirm` reads the tip back rather than trusting a
//! null `submitblock`.
//!
//! The third block is the interesting one to build, because the node will not
//! hand out a template for it: `getblocktemplate` builds on the node's tip,
//! which is still the block we are trying to orphan. It has to be assembled
//! from the same template with the parent and height overridden, and that
//! means computing the subsidy rather than being told it.

use bitcoin::{Block, ScriptBuf};
use serde_json::{Value, json};

use crate::logger::Logger;

use super::{
    block::{build_block, check_block, solve, subsidy_at},
    rpc::Rpc,
    template::Template,
};

pub fn run(rpc: &Rpc, payout: &ScriptBuf, log: &Logger) -> Result<(), String> {
    let template = Template::fetch(rpc)?;
    let time = template.curtime.max(template.mintime);
    let parent = template.previous_block_hash;
    let height = template.height;

    // The halving arithmetic, checked against the node before it is relied on.
    // Regtest halves every 150 blocks, so a chain a couple of hundred blocks
    // long is already several halvings in and nothing like 50 BTC.
    let interval = rpc.chain().halving_interval();
    let ours = subsidy_at(height, interval);
    if ours != template.subsidy() {
        return Err(format!(
            "our subsidy for height {height} is {ours} and the template implies {}",
            template.subsidy()
        ));
    }
    log.log(format!(
        "height {height} on {parent}: subsidy {ours} sat, halving every {interval} blocks",
    ));

    // Two blocks on the same parent, differing only in the extranonce — which
    // changes the coinbase, and so the merkle root, and so the hash.
    let first = mine(&template, payout, 0, time)?;
    let second = mine(&template, payout, 1, time)?;
    let first_hash = first.header.block_hash().to_string();
    let second_hash = second.header.block_hash().to_string();
    if first_hash == second_hash {
        return Err("the two candidates are the same block".into());
    }

    log.log(format!("A {first_hash}"));
    log.log(format!("B {second_hash}"));

    submit(rpc, &first, "A", "accepted", log)?;
    if best_hash(rpc)? != first_hash {
        return Err("A was accepted but is not the tip".into());
    }
    log.log(format!("the tip is A, at height {height}"));

    // B is valid and the node stores it, but it does not win: equal work, and
    // A was seen first. The answer is `inconclusive` rather than null — the
    // node had no reason to fully validate a block that does not extend its
    // best chain.
    submit(rpc, &second, "B", "inconclusive", log)?;
    let tip = best_hash(rpc)?;
    if tip != first_hash {
        return Err(format!(
            "submitting B moved the tip to {tip}, which equal work should not have done"
        ));
    }
    log.log(
        "B was stored and the tip is still A: equal work does not displace what was seen first",
    );
    log.log(format!("chain tips now: {}", tips_summary(rpc)?));

    // C extends B. The node's template still builds on A, so this one is
    // assembled by hand: same transactions, new parent, next height, and a
    // subsidy computed rather than quoted.
    let mut extended = template.clone();
    extended.previous_block_hash = second.header.block_hash();
    extended.height = height + 1;
    extended.coinbase_value = subsidy_at(height + 1, interval);
    // The witness commitment is unaffected: a coinbase's wtxid is defined as
    // all zeros, so with the same transaction set the witness merkle root — and
    // therefore the commitment the template carries — is unchanged.
    let third = mine(&extended, payout, 0, time)?;
    let third_hash = third.header.block_hash().to_string();
    log.log(format!(
        "C {third_hash}, built on B at height {}",
        height + 1
    ));

    submit(rpc, &third, "C", "accepted", log)?;
    let tip = best_hash(rpc)?;
    if tip != third_hash {
        return Err(format!("C was accepted but the tip is {tip}"));
    }

    let count = rpc
        .call("getblockcount", json!([]))?
        .as_u64()
        .ok_or("getblockcount did not return a number")?;
    log.log(format!(
        "the chain reorganised onto B and C: the tip is C at height {count}"
    ));

    // A is still a perfectly valid block. It is simply not on the best chain
    // any more, which Core reports as a negative confirmation count.
    let confirmations = rpc
        .call("getblock", json!([first_hash]))?
        .get("confirmations")
        .and_then(Value::as_i64)
        .ok_or("getblock did not report confirmations")?;
    if confirmations != -1 {
        return Err(format!(
            "A should be on a fork with -1 confirmations, the node says {confirmations}"
        ));
    }
    log.log("A is still stored, with -1 confirmations: valid, and not on the best chain");
    log.log(format!("chain tips now: {}", tips_summary(rpc)?));

    Ok(())
}

fn mine(
    template: &Template,
    payout: &ScriptBuf,
    extranonce: u64,
    time: u32,
) -> Result<Block, String> {
    let mut block = build_block(template, payout, extranonce, time)?;
    solve(&mut block, template.target)?;
    check_block(&block, template)?;
    Ok(block)
}

/// Submit a block and insist on a specific answer.
///
/// The answer is part of the result here rather than a formality, because a
/// competing block does not get the one `submitblock` usually gives. A block
/// that extends the best chain comes back null; a block that is valid but
/// builds on a parent the chain has already moved past comes back
/// **`inconclusive`** — BIP22's way of saying the node stored it without fully
/// validating it, since nothing depends on whether it would connect. Reading
/// that as a rejection is the mistake this signature is shaped to prevent.
fn submit(
    rpc: &Rpc,
    block: &Block,
    name: &str,
    expected: &str,
    log: &Logger,
) -> Result<(), String> {
    let answer = match rpc.call("submitblock", json!([super::block::serialize_block(block)]))? {
        Value::Null => "accepted".to_string(),
        Value::String(reason) => reason,
        other => other.to_string(),
    };

    if answer != expected {
        return Err(format!(
            "submitting {name} answered {answer:?}, expected {expected:?}"
        ));
    }
    log.log(format!("{name} submitted: {answer}"));
    Ok(())
}

fn best_hash(rpc: &Rpc) -> Result<String, String> {
    Ok(rpc
        .call("getbestblockhash", json!([]))?
        .as_str()
        .ok_or("getbestblockhash did not return a string")?
        .to_string())
}

/// The node's own view of the branches, which is the outside confirmation that
/// a fork exists rather than our inference from a confirmation count.
///
/// Only the branches at or just below the tip are printed. A node that has been
/// used for these experiments accumulates a long tail of older ones — including
/// every block the invalid-block catalogue submitted, which it remembers by
/// hash and marks `invalid` — and none of that is what this is asking about.
fn tips_summary(rpc: &Rpc) -> Result<String, String> {
    let tips = rpc.call("getchaintips", json!([]))?;
    let tips = tips
        .as_array()
        .ok_or("getchaintips did not return an array")?;

    let highest = tips
        .iter()
        .filter_map(|tip| tip.get("height").and_then(Value::as_i64))
        .max()
        .unwrap_or(0);

    let mut parts = Vec::new();
    let mut older = 0usize;
    for tip in tips {
        let height = tip.get("height").and_then(Value::as_i64).unwrap_or(-1);
        if height < highest - 1 {
            older += 1;
            continue;
        }
        parts.push(format!(
            "{} at {height} ({})",
            &tip.get("hash").and_then(Value::as_str).unwrap_or("?")[..16],
            tip.get("status").and_then(Value::as_str).unwrap_or("?"),
        ));
    }
    if older > 0 {
        parts.push(format!("and {older} older branches"));
    }
    Ok(parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_subsidy_halves_on_schedule() {
        // Regtest, every 150 blocks.
        assert_eq!(subsidy_at(0, 150), 50 * 100_000_000);
        assert_eq!(subsidy_at(149, 150), 50 * 100_000_000);
        assert_eq!(subsidy_at(150, 150), 25 * 100_000_000);
        assert_eq!(subsidy_at(300, 150), 1_250_000_000);

        // Mainnet's first three eras, and the era this is being written in.
        assert_eq!(subsidy_at(0, 210_000), 50 * 100_000_000);
        assert_eq!(subsidy_at(210_000, 210_000), 25 * 100_000_000);
        assert_eq!(subsidy_at(630_000, 210_000), 625_000_000);
        assert_eq!(subsidy_at(960_563, 210_000), 312_500_000);

        // And the end of it: after 64 halvings the coinbase is fees only.
        assert_eq!(subsidy_at(64 * 210_000, 210_000), 0);
    }

    #[test]
    fn the_subsidy_is_expressed_in_satoshis() {
        assert_eq!(
            bitcoin::Amount::from_sat(subsidy_at(0, 210_000)),
            bitcoin::Amount::from_int_btc(50)
        );
    }
}
