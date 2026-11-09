//! The lottery, measured.
//!
//! The companion to `validate.rs`, and the closest this project gets to a
//! result about Bitcoin rather than about this laptop. Point the GPU at a real template,
//! hash for a while, and record every digest that falls below a *reporting*
//! threshold — one chosen to be met often, rather than the one the chain
//! actually requires. Nothing is ever submitted; the threshold has nothing to
//! do with what a block needs and the run has no wallet.
//!
//! What the numbers are then checked against is textbook, which is the point.
//! For a hash function behaving as a uniform random draw over 2^256:
//!
//! - the count of digests below a threshold of difficulty `d` over `n` hashes
//!   is Poisson with mean `n / (d · 2^32)`, so the observed count should sit
//!   within a few standard deviations of that;
//! - **among the digests that beat a threshold, exactly half should beat twice
//!   it**, a quarter four times it, an eighth eight times it. That ladder is a
//!   direct test of uniformity and needs no estimate of the hash rate to
//!   interpret;
//! - the best digest seen over `n` hashes has median difficulty
//!   `n / (2^32 · ln 2)`.
//!
//! Getting these right on 10^10 real SHA256d evaluations says more about what
//! difficulty means than any explanation of it does.

use std::time::Instant;

use bitcoin::{BlockHash, ScriptBuf, Target, block::Header};

use crate::logger::Logger;

use super::{
    block::{Extranonce, NONCE_MAX, build_block, difficulty_of, difficulty_of_hash},
    gpu::GpuMiner,
    template::Template,
    watch::Signals,
};

/// Hashes per unit of difficulty: a difficulty-1 target is met once per 2^32
/// digests, which is the constant every expectation here is built from.
const HASHES_PER_DIFFICULTY: f64 = 4_294_967_296.0;

/// How many doublings of the threshold to report. Each step should halve the
/// count, and eight of them is four hundred-fold, which is as far as a run of
/// this length has the samples to say anything about.
const LADDER: u32 = 8;

/// What one run covers.
#[derive(Clone, Debug)]
pub struct Sweep {
    /// Digests below this are recorded. Deliberately far easier than any real
    /// chain's target — see the module docs.
    pub threshold: Target,
    /// How long to hash for.
    pub seconds: u64,
    /// Where the extranonce walk begins.
    ///
    /// This one matters more here than it does to a search. A run that starts
    /// from zero every time re-hashes the same headers and reports the same
    /// digests, which is one sample repeated rather than a distribution —
    /// so `MINER_EXTRANONCE_START=auto` is what makes successive runs
    /// independent of each other.
    pub extranonce_start: Extranonce,
}

impl Sweep {
    pub fn validate(self) -> Result<Self, String> {
        if self.seconds == 0 {
            return Err("a lottery run needs a duration".into());
        }
        Ok(self)
    }
}

pub fn run(
    template: &Template,
    payout: &ScriptBuf,
    sweep: Sweep,
    miner: &mut GpuMiner,
    signals: &Signals,
    log: &Logger,
) -> Result<(), String> {
    let sweep = sweep.validate()?;
    let started = Instant::now();
    let time = template.curtime.max(template.mintime);
    let span = miner.config().nonces_per_dispatch();
    let seconds = sweep.seconds;

    let threshold_difficulty = sweep.threshold.difficulty_float();
    log.log(format!(
        "hashing height {} for {seconds}s, reporting every digest below difficulty {:.6} \
         (one per {:.3e} hashes) and submitting nothing",
        template.height,
        threshold_difficulty,
        threshold_difficulty * HASHES_PER_DIFFICULTY,
    ));

    let mut hashes = 0u64;
    let mut difficulties: Vec<f64> = Vec::new();
    let mut best: Option<(BlockHash, f64)> = None;
    let mut extranonce = sweep.extranonce_start;

    loop {
        let block = build_block(template, payout, extranonce.0, time)?;
        // Kept as `u64` for the walk itself: `base` advances a whole dispatch at
        // a time and would overflow a nonce on the last step.
        let mut base = 0u64;
        let mut finished = false;

        while base <= u64::from(NONCE_MAX) {
            let done = miner.advance(&block.header, sweep.threshold, base as u32)?;
            base += span;

            if let Some(done) = done {
                hashes += done.nonces;
                if done.winners.overflowed {
                    return Err(
                        "the winner buffer overflowed, so every count below would understate \
                         what was found: raise the reporting threshold's difficulty"
                            .into(),
                    );
                }
                record(
                    &block.header,
                    &done.winners.nonces,
                    &mut difficulties,
                    &mut best,
                );
            }

            if signals.stopped() || started.elapsed().as_secs() >= seconds {
                finished = true;
                break;
            }
        }

        // Whether the run is ending or the sweep is exhausted, the merkle root
        // is about to change and nothing may still be in flight under the old
        // one.
        if let Some(done) = miner.finish()? {
            hashes += done.nonces;
            record(
                &block.header,
                &done.winners.nonces,
                &mut difficulties,
                &mut best,
            );
        }

        if finished {
            break;
        }
        extranonce = extranonce.advance(1);
    }

    report(
        hashes,
        started.elapsed().as_secs_f64(),
        threshold_difficulty,
        &difficulties,
        best,
        // The chain's own difficulty, read from the template rather than
        // remembered: the number this is compared against moves every two
        // weeks, and a stale constant would quietly make the comparison wrong.
        difficulty_of(template.bits),
        log,
    )
}

/// Recompute each claimed nonce with `rust-bitcoin` and keep its difficulty.
///
/// The GPU proposes and the host disposes holds here too, and for once it is
/// not about safety: these digests *are* the measurement, so taking the GPU's
/// word for which nonces qualified would be measuring the shader rather than
/// SHA256d.
fn record(
    header: &Header,
    nonces: &[u32],
    difficulties: &mut Vec<f64>,
    best: &mut Option<(BlockHash, f64)>,
) {
    for nonce in nonces {
        let mut header = *header;
        header.nonce = *nonce;
        let hash = header.block_hash();
        let difficulty = difficulty_of_hash(&hash);

        if best.is_none_or(|(_, previous)| difficulty > previous) {
            *best = Some((hash, difficulty));
        }
        difficulties.push(difficulty);
    }
}

fn report(
    hashes: u64,
    seconds: f64,
    threshold_difficulty: f64,
    difficulties: &[f64],
    best: Option<(BlockHash, f64)>,
    chain_difficulty: f64,
    log: &Logger,
) -> Result<(), String> {
    let expected = hashes as f64 / (threshold_difficulty * HASHES_PER_DIFFICULTY);
    log.log(format!(
        "{hashes} hashes in {seconds:.1}s at {:.2} MH/s",
        hashes as f64 / seconds / 1e6
    ));
    log.log(format!(
        "{} digests beat the threshold, against {expected:.1} expected ({:+.1} sigma)",
        difficulties.len(),
        (difficulties.len() as f64 - expected) / expected.max(1.0).sqrt(),
    ));

    // The ladder. Each doubling of the required difficulty should halve the
    // count, and this needs no hash rate to interpret — it is a statement
    // about the digests among themselves.
    log.log("each doubling of difficulty should halve the count:");
    for step in 0..LADDER {
        let multiple = f64::from(1u32 << step);
        let level = threshold_difficulty * multiple;
        let count = difficulties.iter().filter(|&&d| d >= level).count();
        let predicted = difficulties.len() as f64 / multiple;
        log.log(format!(
            "  difficulty >= {level:>12.6} ({multiple:>4.0}x): {count:>6} against {predicted:>8.1} predicted"
        ));
    }

    if let Some((hash, difficulty)) = best {
        // The median of the running minimum over n draws, which is the number
        // this whole exercise exists to make concrete.
        let median = hashes as f64 / (HASHES_PER_DIFFICULTY * std::f64::consts::LN_2);
        log.log(format!("best digest: {hash}"));
        log.log(format!(
            "that is difficulty {difficulty:.6}, against a median expectation of {median:.6} \
             for {hashes} hashes",
        ));
        log.log(format!(
            "the chain wants difficulty {chain_difficulty:.3e}, which is {:.3e} times harder \
             than the best digest in this run: one block every {:.3e} years at this rate",
            chain_difficulty / difficulty,
            years_per_block(chain_difficulty, hashes as f64 / seconds),
        ));
    } else {
        log.log("no digest beat the threshold, so there is nothing to report: lower it");
    }

    Ok(())
}

/// Years per block at a given difficulty and hash rate. Spelled out rather
/// than quoted so the arithmetic behind the headline number is visible.
fn years_per_block(difficulty: f64, rate: f64) -> f64 {
    difficulty * HASHES_PER_DIFFICULTY / rate / 31_557_600.0
}
