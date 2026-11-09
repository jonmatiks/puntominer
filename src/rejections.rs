//! What the node says no to, and exactly how it says it.
//!
//! The set of rejection strings is worth more than any of the successes: a
//! miner that has only ever seen blocks accepted knows nothing about what its
//! builder gets wrong. This takes one valid block and breaks it in a different
//! way each time, submits every version, and records what comes back.
//!
//! Two things make the results mean something.
//!
//! **Every broken block is re-solved.** Core checks proof of work before almost
//! anything else, so a tampered block that is also unsolved comes back as
//! `high-hash` and says nothing about the rule that was actually broken.
//!
//! **The valid control goes last.** Each invalid version is submitted while the
//! tip is unchanged, and the tip is re-read after each to prove the node really
//! refused it. Only then is the untouched block submitted and accepted, which
//! is what shows that every rejection above was caused by its mutation and not
//! by something wrong with the block underneath.
//!
//! Each case is also put through our own [`check_block`] first, so the table
//! says which rules this repository catches locally and which it only learns
//! about from a daemon.

use bitcoin::{Amount, Block, BlockHash, ScriptBuf, TxMerkleNode, Witness, hashes::Hash};
use serde_json::{Value, json};

use crate::logger::Logger;

use super::{
    block::{build_block, build_coinbase, check_block, meets_target, refresh_merkle_root, solve},
    rpc::Rpc,
    template::Template,
};

/// One way to break a block.
struct Case {
    name: &'static str,
    /// What the mutation is meant to violate, in our words rather than Core's.
    /// Printed beside the node's answer so the two can be compared.
    breaks: &'static str,
    mutate: fn(&mut Block, &Template) -> Result<(), String>,
    /// Whether to solve the header after mutating it.
    ///
    /// True for every case but one, including the cases that do not touch the
    /// header at all: a freshly built block carries nonce zero and is *not*
    /// solved, so "no need to re-solve" and "no need to solve" are not the
    /// same thing. Getting that wrong is how the first run of this table
    /// reported `high-hash` for a witness bug.
    solve: bool,
}

/// Build, break, submit, and report.
pub fn run(rpc: &Rpc, payout: &ScriptBuf, log: &Logger) -> Result<(), String> {
    let template = Template::fetch(rpc)?;
    let time = template.curtime.max(template.mintime);
    let tip_before = best_hash(rpc)?;

    log.log(format!(
        "breaking a height {} block {} ways; the tip is {tip_before}",
        template.height,
        cases().len(),
    ));

    for case in cases() {
        let mut block = build_block(&template, payout, 0, time)?;
        (case.mutate)(&mut block, &template)?;
        if case.solve {
            solve(&mut block, template.target)?;
        }

        // What we would have said, before asking anyone.
        let ours = match check_block(&block, &template) {
            Ok(()) => match meets_target(&block.header, template.target) {
                true => "accepted".to_string(),
                false => "the proof of work is not valid".to_string(),
            },
            Err(reason) => reason,
        };

        let theirs = submit_for_reason(rpc, &block)?;

        // A rejection that moved the tip would mean the case is mislabelled
        // and the node accepted something we called broken.
        let tip = best_hash(rpc)?;
        if tip != tip_before {
            return Err(format!(
                "the node accepted the {} case: the tip moved from {tip_before} to {tip}",
                case.name
            ));
        }

        log.log(format!(
            "{:<28} | node: {:<22} | ours: {ours} | breaks: {}",
            case.name, theirs, case.breaks
        ));
        if theirs == "accepted" {
            return Err(format!(
                "the {} case was supposed to be invalid and the node took it",
                case.name
            ));
        }
    }

    // The control. Everything above differs from this block by exactly one
    // mutation, so this being accepted is what makes each rejection
    // attributable to its own case.
    let mut control = build_block(&template, payout, 0, time)?;
    solve(&mut control, template.target)?;
    check_block(&control, &template)?;
    let accepted = submit_for_reason(rpc, &control)?;
    log.log(format!(
        "{:<28} | node: {accepted}",
        "the untouched control"
    ));
    if accepted != "accepted" {
        return Err(format!(
            "the control block was rejected ({accepted}), so none of the results above mean \
             anything"
        ));
    }

    // And the one rejection that needs a block the node has already seen.
    let duplicate = submit_for_reason(rpc, &control)?;
    log.log(format!(
        "{:<28} | node: {duplicate}",
        "the control, submitted twice"
    ));

    let tip = best_hash(rpc)?;
    if tip != control.header.block_hash().to_string() {
        return Err(format!("the control was accepted but the tip is {tip}"));
    }
    log.log(format!(
        "the control was accepted at height {}: every rejection above was caused by its own \
         mutation",
        template.height
    ));

    Ok(())
}

/// Submit a block and return the node's answer as a string, where a null
/// answer — acceptance — is spelled out rather than left empty.
fn submit_for_reason(rpc: &Rpc, block: &Block) -> Result<String, String> {
    match rpc.call("submitblock", json!([super::block::serialize_block(block)]))? {
        Value::Null => Ok("accepted".to_string()),
        Value::String(reason) => Ok(reason),
        other => Ok(other.to_string()),
    }
}

fn best_hash(rpc: &Rpc) -> Result<String, String> {
    Ok(rpc
        .call("getbestblockhash", json!([]))?
        .as_str()
        .ok_or("getbestblockhash did not return a string")?
        .to_string())
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "merkle root flipped",
            breaks: "the header commits to the transactions",
            solve: true,
            mutate: |block, _| {
                let mut bytes = block.header.merkle_root.to_byte_array();
                bytes[0] ^= 0x01;
                block.header.merkle_root = TxMerkleNode::from_byte_array(bytes);
                Ok(())
            },
        },
        Case {
            name: "no witness commitment",
            breaks: "BIP141: a segwit block commits to its witnesses",
            solve: true,
            mutate: |block, _| {
                block.txdata[0]
                    .output
                    .retain(|out| !out.script_pubkey.is_op_return());
                refresh_merkle_root(block)
            },
        },
        Case {
            name: "witness commitment flipped",
            breaks: "BIP141: the commitment is over the witness merkle root",
            solve: true,
            mutate: |block, _| {
                let output = block.txdata[0]
                    .output
                    .iter_mut()
                    .find(|out| out.script_pubkey.is_op_return())
                    .ok_or("the coinbase has no commitment to corrupt")?;
                let mut bytes = output.script_pubkey.to_bytes();
                // Past the OP_RETURN, the push, and the four-byte header, so
                // what changes is the committed root and not the marker Core
                // finds the output by.
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                output.script_pubkey = ScriptBuf::from_bytes(bytes);
                refresh_merkle_root(block)
            },
        },
        Case {
            name: "wrong witness reserved value",
            breaks: "BIP141: the coinbase witness is 32 zero bytes",
            // The witness is not covered by the txid, so this leaves the
            // merkle root alone — but the header still has to be solved,
            // because a freshly built block never was.
            solve: true,
            mutate: |block, _| {
                let mut witness = Witness::new();
                witness.push([0x01u8; 32]);
                block.txdata[0].input[0].witness = witness;
                Ok(())
            },
        },
        Case {
            name: "coinbase pays 1 sat too much",
            breaks: "the coinbase may not exceed subsidy plus fees",
            solve: true,
            mutate: |block, template| {
                block.txdata[0].output[0].value = Amount::from_sat(template.coinbase_value + 1);
                refresh_merkle_root(block)
            },
        },
        Case {
            name: "wrong BIP34 height",
            breaks: "BIP34: the coinbase opens with its own height",
            solve: true,
            mutate: |block, template| {
                let mut wrong = template.clone();
                wrong.height += 1;
                block.txdata[0] = build_coinbase(&wrong, &payout_of(block), 0)?;
                refresh_merkle_root(block)
            },
        },
        Case {
            name: "time before the median",
            breaks: "a block must be later than the median of the last eleven",
            solve: true,
            mutate: |block, template| {
                // mintime is the median-time-past plus one, so one below it is
                // exactly the first value the rule refuses.
                block.header.time = template.mintime - 1;
                Ok(())
            },
        },
        Case {
            name: "time two hours ahead",
            breaks: "a block may not be far ahead of network-adjusted time",
            solve: true,
            mutate: |block, template| {
                block.header.time = template.curtime + 2 * 60 * 60 + 60;
                Ok(())
            },
        },
        Case {
            name: "unknown parent",
            breaks: "the parent must be a block the node has",
            solve: true,
            mutate: |block, _| {
                block.header.prev_blockhash = BlockHash::from_byte_array([0x42; 32]);
                Ok(())
            },
        },
        Case {
            name: "no proof of work",
            breaks: "the header hash must meet the target",
            // The one case left unsolved on purpose: here the header itself
            // is the defect.
            solve: false,
            mutate: |block, template| {
                for nonce in 0..=u32::MAX {
                    block.header.nonce = nonce;
                    if !meets_target(&block.header, template.target) {
                        return Ok(());
                    }
                }
                Err("every nonce solved this header, which cannot happen".into())
            },
        },
    ]
}

/// Recover the payout script from a block being mutated, so a case that
/// rebuilds the coinbase pays to the same place the original did.
fn payout_of(block: &Block) -> ScriptBuf {
    block.txdata[0].output[0].script_pubkey.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_case_is_named_and_says_what_it_breaks() {
        for case in cases() {
            assert!(!case.name.is_empty());
            assert!(!case.breaks.is_empty(), "{} says nothing", case.name);
        }
    }

    #[test]
    fn the_cases_are_distinct() {
        let mut names: Vec<&str> = cases().iter().map(|case| case.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two cases share a name");
    }
}
