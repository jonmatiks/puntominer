//! The hybrid search: the CPU and the GPU grinding one template at once.
//!
//! Neither half is new. This module owns only the three decisions that appear
//! the moment two devices share a template, and each of them is a way of not
//! wasting work:
//!
//! 1. **The halves must not walk the same headers.** Both searches start from
//!    the extranonce they are handed, and two devices handed the same one build
//!    the same coinbase, the same merkle root and therefore byte-identical
//!    headers — the second device would re-derive digests the first already
//!    has. So they are started half the extranonce space apart, which is the
//!    same argument `MINER_EXTRANONCE_START` makes for two instances.
//! 2. **The half that wins must stop the other.** Both are searching for one
//!    block and only one can be submitted, so the loser's remaining work is
//!    spent under a template that is about to be superseded by our own block.
//!    [`Signals::branch`] is what lets one half stop the other without stopping
//!    the run.
//! 3. **What each half did is reported separately.** A combined rate cannot say
//!    whether the second device was worth adding, because the thing worth
//!    fearing — one device slowing the other down — does not show up in a sum.
//!    See [`Part`]: on this hardware the GPU keeps all 431 MH/s and the CPU
//!    walks 256 where it walks 354 alone, for 686 together against 431 — and the
//!    CPU's shortfall turns out to be a lower clock under a shared package power
//!    budget rather than anything this module can do something about.
//!
//! Whether this is worth having at all is a property of the machine rather than
//! of the idea. It is here because these two devices are the same size — an RTX
//! 4070 Laptop against a 32-thread i9 with SHA-NI, 1.22x — and on a rig whose
//! cards outrun its CPU by three orders of magnitude the CPU half would buy
//! nothing but the contention.
//!
//! Nothing about correctness changes. Each half still verifies its own winner
//! through `rust-bitcoin` before returning it, and the run loop still puts the
//! block through `check_block` before the node ever sees it.

use std::thread;

use bitcoin::ScriptBuf;

use super::{
    block::Extranonce,
    cpu::{self, Cpu, Mined, Part, Search},
    gpu::{self, GpuMiner},
    template::Template,
    watch::{Ending, Signals},
};

/// How far apart the two halves begin their extranonce walks.
///
/// Half the 64-bit space, so each device owns a half and neither can reach the
/// other's: exhausting one means 2^63 merkle roots at 2^32 nonces each, which no
/// hardware will do. Any large separation would work — what matters is only that
/// the two never build the same header, since a header hashed twice is a draw
/// counted twice and a device's worth of electricity spent on nothing.
pub const EXTRANONCE_SPLIT: u64 = 1 << 63;

const CPU: &str = "cpu";
const GPU: &str = "gpu";

/// Search one template on both devices at once.
///
/// The GPU runs on the calling thread and the CPU half on one of its own. That
/// leaves the GPU's host loop competing with `cpu.workers` hashing threads for a
/// core, and the obvious defence — hashing on one core fewer — measures worse
/// than not bothering: the host loop stages a uniform block and then blocks in
/// the driver for the length of a dispatch, so it is descheduled rather than
/// competing. See `MINER_WORKERS`.
///
/// `start` is where the GPU's walk begins; the CPU's begins
/// [`EXTRANONCE_SPLIT`] past it. Both walk the whole nonce space, because what
/// makes their work distinct is the extranonce and therefore the header, not
/// which nonces they try under it.
///
/// `mask` is the GPU half's to roll, as in [`gpu::search`]. The CPU half
/// always searches the template's own version: its lever is the interleaved
/// hasher, not version pairs.
pub fn search(
    template: &Template,
    payout: &ScriptBuf,
    cpu: Cpu,
    miner: &mut GpuMiner,
    signals: &Signals,
    start: Extranonce,
    mask: u32,
) -> Result<Search, String> {
    let gpu_signals = signals.branch();
    let cpu_signals = gpu_signals.clone();
    let cpu_start = start.advance(EXTRANONCE_SPLIT);

    let (cpu_half, gpu_half) = thread::scope(|scope| {
        let hashing = scope.spawn(move || {
            let outcome = cpu::search(template, payout, cpu, &cpu_signals, cpu_start);
            // Raised however this half ended, and for one reason in each case:
            // it won, so the other half's block would never be submitted; or it
            // failed, so the run is over and the other half should not have to
            // be waited out; or something stopped it that stops the other half
            // anyway, and the flag is redundant rather than wrong.
            cpu_signals.stop_branch();
            outcome
        });

        let gpu_half = gpu::search(template, payout, miner, &gpu_signals, start, mask);
        gpu_signals.stop_branch();

        // Joined whatever the GPU half returned: a scope will not end with a
        // thread of its own still running, so an early `?` here would only mean
        // blocking on the CPU half without having stopped it first.
        let cpu_half = hashing
            .join()
            .unwrap_or_else(|_| Err("the CPU half of the hybrid search panicked".into()));
        (cpu_half, gpu_half)
    });

    Ok(combine(cpu_half?, gpu_half?, signals))
}

/// Merge what the two halves did into the one result the run loop expects.
///
/// The hash counts add, because the halves ran on disjoint headers. The seconds
/// do not: they ran at the same time, so the search took as long as the slower
/// of them and the combined rate is the sum of the two rates.
fn combine(cpu: Search, gpu: Search, signals: &Signals) -> Search {
    let parts = vec![
        Part {
            device: CPU,
            hashes: cpu.hashes,
            seconds: cpu.seconds,
        },
        Part {
            device: GPU,
            hashes: gpu.hashes,
            seconds: gpu.seconds,
        },
    ];

    // Either half's winner is a block, and only one can be submitted; when both
    // won — possible, since one half can find a block in the instant before the
    // other's stop reaches it — the second is simply dropped. Which one is kept
    // is arbitrary and therefore fixed: the GPU's, so that a run that produces
    // two blocks in a row does not depend on a race for which it submitted.
    let winner: Option<Mined> = gpu.winner.or(cpu.winner);

    // A block outranks either interruption, exactly as it does in a single
    // search: the halves stop each other the moment one wins, so the stop that
    // ended the other is not a reason to report anything but a block. Without
    // one, the reason is the run's own — the branch stop cannot be it, since
    // nothing raises that until a half has already returned.
    let ending = match &winner {
        Some(_) => Ending::Found,
        None => signals.interrupted().unwrap_or(Ending::Signalled),
    };

    Search {
        winner,
        hashes: cpu.hashes + gpu.hashes,
        seconds: cpu.seconds.max(gpu.seconds),
        ending,
        parts,
        // The better of the two, because the halves walked disjoint headers and
        // the best hash of the search is the best hash either of them saw.
        best: cpu.best.max(gpu.best),
    }
}

#[cfg(test)]
mod tests {
    use crate::{block, template};

    use super::*;

    fn half(device: &'static str, hashes: u64, seconds: f64, ending: Ending) -> Search {
        Search {
            winner: None,
            hashes,
            seconds,
            ending,
            parts: vec![Part {
                device,
                hashes,
                seconds,
            }],
            best: 0.0,
        }
    }

    #[test]
    fn the_halves_start_on_extranonces_neither_can_reach() {
        // The whole point of the split: the two devices must never build the
        // same header. A shared start would have them hashing identical digests
        // and reporting twice the rate for the same search.
        let start = Extranonce(12_345);
        assert_ne!(start, start.advance(EXTRANONCE_SPLIT));
        // And it is a real half, so walking out of one into the other would take
        // 2^63 merkle roots.
        assert_eq!(
            start.advance(EXTRANONCE_SPLIT).advance(EXTRANONCE_SPLIT),
            start,
            "two halves are the whole space"
        );
    }

    #[test]
    fn the_combined_search_adds_hashes_and_takes_the_longer_span() {
        // Concurrent halves: 3s of GPU and 3s of CPU is a 3s search at the sum
        // of the two rates, not a 6s one.
        let signals = Signals::unwatched();
        signals.mark_stale();

        let combined = combine(
            half(CPU, 300_000_000, 3.0, Ending::Stale),
            half(GPU, 1_200_000_000, 2.9, Ending::Stale),
            &signals,
        );

        assert_eq!(combined.hashes, 1_500_000_000);
        assert_eq!(combined.seconds, 3.0);
        assert_eq!(combined.hash_rate(), 500_000_000.0);
        assert_eq!(combined.ending, Ending::Stale);

        let parts: Vec<(&str, u64)> = combined
            .parts
            .iter()
            .map(|part| (part.device, part.hashes))
            .collect();
        assert_eq!(parts, vec![(CPU, 300_000_000), (GPU, 1_200_000_000)]);
    }

    #[test]
    fn a_block_from_either_half_outranks_the_stop_it_raised_on_the_other() {
        // The ending the run loop turns on. The losing half returns `Signalled`
        // because the winner stopped it, and reporting that would abandon a
        // block that was already found.
        let signals = Signals::unwatched();

        let template = template::sample_at(960_563);
        let payout = ScriptBuf::from_hex("0014329649f03db93aef2cf873e9b8544a446d38316d")
            .expect("the sample payout should be hex");
        let mut winning = half(GPU, 10, 1.0, Ending::Found);
        winning.winner = Some(Mined {
            block: block::build_block(&template, &payout, 7, template.curtime)
                .expect("the sample template should build a block"),
            extranonce: Extranonce(7),
        });

        let combined = combine(half(CPU, 5, 1.0, Ending::Signalled), winning, &signals);
        assert_eq!(combined.ending, Ending::Found);
        let winner = combined.winner.expect("the GPU half won");
        assert_eq!(winner.extranonce, Extranonce(7));
    }
}
