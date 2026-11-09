//! Grinding a pool's job, reporting every header that meets the share target.
//!
//! This is the one step of the client that touches hashing, and it is written
//! as a **sibling** of [`cpu::search`](super::super::cpu::search),
//! [`gpu::search`](super::super::gpu::search) and
//! [`hybrid::search`](super::super::hybrid::search) rather than as a
//! generalisation of them. That is a deliberate cost, and the reason is that
//! two of the rules those functions are built on invert here:
//!
//! 1. **Stopping at the first hit.** A block search stops because there is one
//!    block and the rest of the work is spent under a template about to be
//!    superseded. A share search reports and carries on: every share is
//!    separately worth credit, and the job is not over because one was found.
//! 2. **An overflowed GPU winner buffer.** `AGENTS.md` states that it "is not
//!    an error for a search", and that is right for a block search — every
//!    winner is equally a block and only one is submitted. Here every dropped
//!    winner is a dropped share, which is lost credit *and* a stale-rate
//!    measurement that silently understates. It is an error in this file and
//!    stays not-an-error in `gpu.rs`. Do not collapse the two.
//!
//! A single function serving both callers would have to take those inversions
//! as parameters, which is how a rule that is correct in one mode leaks into
//! the mode where it is wrong — and it would put a branch inside the hot loop
//! of the one function this project exists to keep fast. So the loop structure
//! is duplicated, visibly and locally, and `cpu.rs`, `gpu.rs` and `hybrid.rs`
//! are not edited at all.
//!
//! What *is* unchanged carries over exactly:
//!
//! - **Only a `rust-bitcoin`-verified header may be reported.** The fast hasher
//!   finds a share; it never certifies one, and a disagreement fails the run
//!   naming the hasher.
//! - **`GpuMiner::finish` drains before the merkle root changes.** A dispatch in
//!   flight belongs to the header it was submitted under. `abandon` has no
//!   place here: a found share does not make the rest of a dispatch worthless,
//!   so share mode drains where block mode abandons.
//! - **The two hybrid halves walk disjoint extranonces**, through the same
//!   [`EXTRANONCE_SPLIT`] `hybrid.rs` uses — imported, not redefined, because
//!   it means the same thing for an extranonce2 as for a coinbase extranonce.

use std::{
    collections::BTreeMap,
    ops::RangeInclusive,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bitcoin::{
    Target,
    block::{Header, Version},
};

use super::job::ShareTarget;
use crate::{
    block::{self, Extranonce, VersionRoll},
    constants::MINER_CPU_THROTTLE_WINDOW_MILLISECONDS,
    cpu::{Cpu, Hasher, Part, Search},
    gpu::{Completed, GpuMiner, Headers},
    hybrid::EXTRANONCE_SPLIT,
    sha256::{
        self, Backend, HeaderHasher, LANES, NonceHasher, RustCryptoHasher, RustCryptoPlainHasher,
    },
    watch::{Ending, Signals},
};

const CPU: &str = "cpu";
const GPU: &str = "gpu";

/// How often a worker looks up from hashing to see whether to stop.
///
/// The same interval `cpu.rs` uses, and duplicated for the same reason the loop
/// is: that constant is private to `cpu.rs`.
const STOP_CHECK_INTERVAL: u32 = 1 << 16;

/// The bits that may actually be rolled on one job, given what the pool agreed.
///
/// **Decided per job, not per session, because it depends on the version the
/// job announced.** BIP310 says what goes back in `mining.submit` is the rolled
/// bits and leaves how the pool puts them back unstated, so pools differ: the
/// spec reading rebuilds `(announced & !mask) | submitted`, while Pool B's
/// source computes `announced ^ submitted`. Those agree exactly when the
/// announced version has no bits inside the mask, and disagree on *every* share
/// when it does — and no choice of submitted bits satisfies both, because the
/// disagreement is about the pool's own announcement rather than about anything
/// this client sends.
///
/// This is not hypothetical. A regtest chain's `getblocktemplate` announces
/// version `30000000` — bit 28 is inside BIP320's mask, set by the testdummy
/// deployment — and against a local Pool B on 18 September 2026 that made
/// **every** share fail with `Difficulty too low`, for a header the pool had
/// rebuilt differently from the one that was hashed. It looks exactly like a
/// byte-order bug and is not one.
///
/// So where it is ambiguous this returns `None`: nothing rolls, and the caller
/// sends no version parameter at all, which leaves the pool using the version
/// it announced. Both mainnet pools announce `20000000` and lose nothing.
pub fn rollable(version: u32, negotiated: Option<u32>) -> Option<u32> {
    negotiated.filter(|mask| mask & version == 0)
}

/// What a share search needs from a job, whichever protocol described it.
///
/// **Three methods, because that is all `search_shares` uses.** The V1 client
/// deliberately has this module as a *sibling* of `cpu::search` rather than
/// generalising it, and that rule is not being relaxed here — it was about two
/// rules that invert between a block search and a share search, and a V1 share
/// search and an SV2 share search invert in none of them. They differ in where
/// the 80-byte header comes from and in nothing else, so duplicating five
/// hundred lines of CPU, GPU and hybrid loop to vary a header constructor would
/// be the same mistake pointed the other way.
///
/// `job.id()` and `job.clone()` are deliberately absent: they appear only in
/// this module's tests, and the two protocols spell a job id differently — V1's
/// is a `String` the pool chose, SV2's a `u32` scoped to a channel. Neither
/// belongs in the hot path's vocabulary.
pub trait ShareJob: Sync {
    /// The target a header must meet to be a share.
    fn target(&self) -> ShareTarget;

    /// The version the job announced, before any rolling.
    fn version(&self) -> u32;

    /// The header for one extranonce, under one version, with the nonce left
    /// at zero for the search to fill in.
    fn header(&self, extranonce: Extranonce, version: u32) -> Header;
}

/// Whether a share's header also meets the network target its own `bits`
/// name — whether the share is a block.
///
/// **What the client found, not what happened to it.** Neither protocol says
/// whether the pool's block was accepted, and a pool's acceptance of the share
/// says nothing about it either; the chain is the only authority. This exists
/// because without it a solo miner's block is one more share line,
/// indistinguishable from one that missed by a factor of billions.
pub fn is_block(header: &Header) -> bool {
    block::meets_target(header, header.target())
}

/// One header that met the share target.
///
/// The `version` travels with it because version rolling makes it part of what
/// was hashed rather than a property of the job — rolling moves it, and
/// a `mining.submit` that reported a rolled share under the job's announced
/// version would be rejected for a header the pool cannot reproduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub extranonce2: Extranonce,
    pub nonce: u32,
    pub version: u32,
}

/// How a search hands a share back.
///
/// A callback rather than a return value or a channel, for the reason the
/// inversion above implies: there is no single result to return, and a share
/// held until the search ends is a share submitted against a job the pool may
/// have already cleaned. It is `Send` because the CPU half calls it from its
/// workers, and behind a `Mutex` because they all do.
///
/// An error from it ends the search. That is the socket dying, which is the one
/// thing a share miner cannot grind through.
pub type Found<'a> = &'a mut (dyn FnMut(Hit) -> Result<(), String> + Send);

/// The last nonce a share search walks before it rolls the version or the
/// extranonce: the whole space, except under test.
///
/// The session tests in `run.rs` and `v2/run.rs` drive [`search_shares`]
/// through a whole client loop and need a version roll within milliseconds of
/// a debug build, which the whole space would put hours away.
#[cfg(not(test))]
const NONCE_END: u32 = block::NONCE_MAX;
#[cfg(test)]
const NONCE_END: u32 = 0x3ff;

/// Grind one job on whichever devices were handed over.
///
/// The device is chosen by which handles are present rather than by an enum,
/// because `runner.rs`'s `Device` is private to that module and stays that
/// way. Both absent is a caller bug and is named as
/// one rather than silently doing nothing.
pub fn search_shares(
    job: &dyn ShareJob,
    cpu: Option<Cpu>,
    gpu: Option<&mut GpuMiner>,
    signals: &Signals,
    start: Extranonce,
    rolling: Option<u32>,
    found: Found<'_>,
) -> Result<Search, String> {
    search_shares_over(job, cpu, gpu, signals, 0..=NONCE_END, start, rolling, found)
}

/// [`search_shares`] over a range of nonces the caller names, which only the
/// tests here want: each picks the range its difficulty was chosen for.
#[allow(clippy::too_many_arguments)]
fn search_shares_over(
    job: &dyn ShareJob,
    cpu: Option<Cpu>,
    gpu: Option<&mut GpuMiner>,
    signals: &Signals,
    nonces: RangeInclusive<u32>,
    start: Extranonce,
    rolling: Option<u32>,
    found: Found<'_>,
) -> Result<Search, String> {
    // `None` becomes a mask of zero, which is one version and no branch — see
    // [`VersionRoll`]. Nothing downstream has to know whether rolling is on.
    let mask = rolling.unwrap_or(0);
    let found = Mutex::new(found);
    match (cpu, gpu) {
        (Some(cpu), None) => cpu_shares(job, cpu, signals, nonces, start, mask, &found),
        (None, Some(gpu)) => gpu_shares(job, gpu, signals, nonces, start, mask, &found),
        (Some(cpu), Some(gpu)) => {
            hybrid_shares(job, cpu, gpu, signals, nonces, start, mask, &found)
        }
        (None, None) => Err("a share search was asked for with no device to run it on".into()),
    }
}

/// The CPU half: [`cpu::search`](super::super::cpu::search)'s worker loop with
/// the job in place of the template and the callback in place of the winner.
#[allow(clippy::too_many_arguments)]
fn cpu_shares(
    job: &dyn ShareJob,
    cpu: Cpu,
    signals: &Signals,
    nonces: RangeInclusive<u32>,
    start: Extranonce,
    mask: u32,
    found: &Mutex<Found<'_>>,
) -> Result<Search, String> {
    let Cpu {
        workers,
        hasher,
        load_percent,
    } = cpu;
    let (first, last) = (*nonces.start(), *nonces.end());
    let started = Instant::now();
    let hashes = AtomicU64::new(0);

    // One worker failing must stop the others. In a block search the winner
    // flag does that; here there is no winner, and the common failure is the
    // pool socket going away — which every worker would otherwise keep grinding
    // past until something outside raised a signal.
    let failed = AtomicBool::new(false);

    let target = job.target();
    let target_words = sha256::target_words(target.inner());
    let version = job.version();

    let outcome: Result<(), String> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);

        for worker in 0..workers {
            let hashes = &hashes;
            let failed = &failed;
            let target_words = &target_words;

            handles.push(scope.spawn(move || -> Result<(), String> {
                let mut extranonce2 = start.advance(worker as u64);
                let mut local_hashes: u64 = 0;
                let mut throttle = Throttle::new(load_percent);

                loop {
                    // The merkle root is rebuilt once per extranonce2 and the
                    // version rolls inside it, because that is the cheaper of
                    // the two rolls — see `VersionRoll`.
                    let mut header = job.header(extranonce2, version);

                    for rolled in VersionRoll::new(version, mask) {
                        header.version = Version::from_consensus(rolled as i32);

                        // Built once per (merkle root, version), which is what the
                        // midstate is: everything before the nonce, already
                        // compressed. The rolled version bits sit in those first 64
                        // bytes, which is why a version roll rebuilds this and a
                        // nonce roll does not. Writing `header.nonce` below does
                        // not invalidate it — the nonce lives in the tail.
                        let fast = prepare(hasher, &header);

                        // `LANES` nonces at a time where the range has
                        // room for a whole batch, and the remainder one at a
                        // time. Each is then handled in ascending order, as if
                        // hashed alone, so the shares reported are the same.
                        let mut next = u64::from(first);
                        while next <= u64::from(last) {
                            let width = (u64::from(last) - next + 1).min(LANES as u64) as usize;
                            let lanes = match &fast {
                                Some(fast) if width == LANES => {
                                    Some(fast.screen_lanes::<LANES>(next as u32, target_words))
                                }
                                _ => None,
                            };

                            for lane in 0..width {
                                let nonce = (next + lane as u64) as u32;
                                local_hashes += 1;

                                let hit = match (&lanes, &fast) {
                                    (Some(lanes), _) => lanes[lane].0,
                                    (None, Some(fast)) => fast.screen(nonce, target_words).0,
                                    (None, None) => {
                                        header.nonce = nonce;
                                        block::meets_target(&header, target.inner())
                                    }
                                };

                                if hit {
                                    // The fast hashers are trusted to find a share and
                                    // never to certify one.
                                    header.nonce = nonce;
                                    if !block::meets_target(&header, target.inner()) {
                                        failed.store(true, Ordering::Relaxed);
                                        return Err(format!(
                                            "the {} hasher claimed nonce {nonce} at extranonce2 \
                                         {extranonce2}, which rust-bitcoin rejects",
                                            hasher.name()
                                        ));
                                    }

                                    // Reported, and then straight back to hashing. This
                                    // is the inversion: a block search would return
                                    // here, and a share search has no reason to — the
                                    // job is not over because it paid once.
                                    let reported = {
                                        let mut report =
                                            found.lock().expect("share callback mutex poisoned");
                                        report(Hit {
                                            extranonce2,
                                            nonce,
                                            version: rolled,
                                        })
                                    };
                                    if let Err(why) = reported {
                                        failed.store(true, Ordering::Relaxed);
                                        hashes.fetch_add(local_hashes, Ordering::Relaxed);
                                        return Err(why);
                                    }
                                }

                                if nonce.is_multiple_of(STOP_CHECK_INTERVAL) {
                                    if failed.load(Ordering::Relaxed)
                                        || signals.interrupted().is_some()
                                    {
                                        hashes.fetch_add(local_hashes, Ordering::Relaxed);
                                        return Ok(());
                                    }
                                    if let Some(throttle) = throttle.as_mut() {
                                        throttle.pause_if_due();
                                    }
                                }
                            }
                            next += width as u64;
                        }

                        // The nonce space is exhausted under this version, so
                        // the next one takes its turn. Reported here rather
                        // than at the end of the whole roll, so a long version
                        // walk is not invisible in the rate.
                        hashes.fetch_add(local_hashes, Ordering::Relaxed);
                        local_hashes = 0;
                    }

                    // Every version is exhausted too, so roll the extranonce2
                    // this worker owns. Nothing else in the header changes, and
                    // the pool's coinbase halves are spliced around the new
                    // value.
                    extranonce2 = extranonce2.advance(workers as u64);
                }
            }));
        }

        for handle in handles {
            handle.join().map_err(|_| "a share worker panicked")??;
        }
        Ok(())
    });
    outcome?;

    Ok(Search {
        winner: None,
        hashes: hashes.load(Ordering::Relaxed),
        seconds: started.elapsed().as_secs_f64(),
        ending: signals.interrupted().unwrap_or(Ending::Signalled),
        parts: Vec::new(),
        // **Left at zero here, and not because it is unavailable.** A share
        // search already reports every hash worth more than the share target,
        // and the best hash of a job is by definition the best of those — so
        // `stratum/run.rs` has the same number from the shares it submitted,
        // and a second ranking in this loop would measure the same thing twice
        // to say it less precisely.
        best: 0.0,
    })
}

/// The GPU half: [`gpu::search`](super::super::gpu::search)'s loop with every
/// winner reported instead of the first, and no `abandon`.
#[allow(clippy::too_many_arguments)]
fn gpu_shares(
    job: &dyn ShareJob,
    miner: &mut GpuMiner,
    signals: &Signals,
    nonces: RangeInclusive<u32>,
    start: Extranonce,
    mask: u32,
    found: &Mutex<Found<'_>>,
) -> Result<Search, String> {
    // Kept as `u64` for the walk itself: `base` advances a whole dispatch at a
    // time and would overflow a nonce on the last step.
    let (first, last) = (u64::from(*nonces.start()), u64::from(*nonces.end()));
    let started = Instant::now();
    let span = miner.config().nonces_per_dispatch();
    let target = job.target();
    let version = job.version();

    let mut hashes = 0u64;
    let mut extranonce2 = start;

    loop {
        let header = job.header(extranonce2, version);
        let under = |version: u32| Header {
            version: Version::from_consensus(version as i32),
            ..header
        };

        // **Versions two at a time whenever the job rolls at all: AsicBoost.**
        // A span of two or more versions is a power of two, so it splits into
        // pairs exactly, and consecutive versions differ only in the mask's
        // lowest bit. `search_pair` hashes both at every nonce over one shared
        // message schedule. A span of one — no mask, or the ambiguous case
        // `VersionRoll` refuses to roll — is the single search, unchanged.
        let mut roll = VersionRoll::new(version, mask);
        let paired = roll.span() >= 2;
        while let Some(rolled) = roll.next() {
            let headers = if paired {
                let partner = roll
                    .next()
                    .expect("a span of two or more versions is a power of two, so even");
                Headers::pair(under(rolled), under(partner))?
            } else {
                Headers::One(under(rolled))
            };

            let mut base = first;
            while base <= last {
                // A rest drains as well, and what it drains is shares.
                if let Some(done) = miner.rest(signals)? {
                    hashes += done.hashes;
                    claim_shares(&headers, target, extranonce2, &done, found)?;
                }

                // An interruption drains rather than discards: the work is
                // already done, and those winners are shares that have already
                // been paid for in electricity.
                if let Some(ending) = signals.interrupted() {
                    if let Some(done) = miner.finish()? {
                        hashes += done.hashes;
                        claim_shares(&headers, target, extranonce2, &done, found)?;
                    }
                    return Ok(Search {
                        winner: None,
                        hashes,
                        seconds: started.elapsed().as_secs_f64(),
                        ending,
                        parts: Vec::new(),
                        best: 0.0,
                    });
                }

                let completed = miner.advance_headers(&headers, target.inner(), base as u32)?;
                base += span;

                if let Some(done) = completed {
                    hashes += done.hashes;
                    claim_shares(&headers, target, extranonce2, &done, found)?;
                }
            }

            // **The headers are about to change, so nothing may still be in
            // flight under them.** Unchanged from `gpu.rs` and load-bearing for
            // the same reason — those winners would otherwise be verified
            // against a header they were not found under — and it guards the
            // version roll as well as the merkle root, because a rolled
            // version is as much a different header as a new coinbase is.
            if let Some(done) = miner.finish()? {
                hashes += done.hashes;
                claim_shares(&headers, target, extranonce2, &done, found)?;
            }
        }

        extranonce2 = extranonce2.advance(1);
    }
}

/// Report every share one dispatch found.
///
/// **`overflowed` is fatal here.** See this module's header: a dropped winner
/// is a dropped share, and a reject or stale rate measured against a count that
/// silently understates is worse than no measurement. In `gpu.rs` the same flag
/// is correctly ignored, because there every winner is equally a block.
fn claim_shares(
    headers: &Headers,
    target: ShareTarget,
    extranonce2: Extranonce,
    done: &Completed,
    found: &Mutex<Found<'_>>,
) -> Result<(), String> {
    if done.winners.overflowed {
        return Err(format!(
            "the GPU's winner buffer overflowed at extranonce2 {extranonce2}, base nonce {}: \
             every winner past it is a share that was found and not submitted, which is lost \
             credit and a share rate that understates without saying so",
            done.base_nonce
        ));
    }

    // The GPU proposes and `rust-bitcoin` disposes — for every winner, not
    // just the one that would have been submitted, and under a pair it also
    // decides which version each winner is a share under.
    let shares = attribute(&done.winners.nonces, headers, target.inner())
        .map_err(|error| format!("{error}, at extranonce2 {extranonce2}"))?;
    for (nonce, version) in shares {
        let mut report = found.lock().expect("share callback mutex poisoned");
        report(Hit {
            extranonce2,
            nonce,
            version,
        })?;
    }
    Ok(())
}

/// Each winner of a dispatch as `(nonce, version)`, the version being whichever
/// of the dispatch's headers `rust-bitcoin` verifies the nonce under.
///
/// **The GPU never says which version won.** `search_pair` records a nonce
/// once for each version that meets the target, and nothing else, so the
/// winner buffer keeps the layout every caller reads. That makes the count
/// the check: a nonce must be listed exactly as many times as it verifies.
/// Listed once but verifying under both is a winner the GPU dropped; verifying
/// under none is a false claim; and either is an error, because the share
/// reported under the wrong version is a header the pool cannot rebuild — a
/// reject that looks exactly like a byte-order bug.
fn attribute(nonces: &[u32], headers: &Headers, target: Target) -> Result<Vec<(u32, u32)>, String> {
    let mut listed = BTreeMap::<u32, usize>::new();
    for nonce in nonces {
        *listed.entry(*nonce).or_default() += 1;
    }

    let mut shares = Vec::with_capacity(nonces.len());
    for (nonce, count) in listed {
        let verified: Vec<u32> = headers
            .as_slice()
            .iter()
            .filter(|header| GpuMiner::verify(header, target, nonce))
            .map(|header| header.version.to_consensus() as u32)
            .collect();
        if verified.is_empty() {
            return Err(format!(
                "the GPU claimed nonce {nonce}, which rust-bitcoin rejects"
            ));
        }
        if verified.len() != count {
            return Err(format!(
                "the GPU listed nonce {nonce} {count} time(s), but it meets the target under \
                 {} of the dispatch's versions: a winner was dropped or invented",
                verified.len()
            ));
        }
        shares.extend(verified.into_iter().map(|version| (nonce, version)));
    }
    Ok(shares)
}

/// Both devices on one job, on disjoint extranonce2s.
///
/// Modelled on [`hybrid::search`](super::super::hybrid::search), with one
/// difference that matters: **neither half stops the other on a hit.** There,
/// the winner's block makes the loser's remaining work worthless. Here a share
/// found by one device says nothing about whether the other's next header is
/// also a share, so the only reason either half raises the branch stop is that
/// it has stopped itself — interrupted, or failed.
#[allow(clippy::too_many_arguments)]
fn hybrid_shares(
    job: &dyn ShareJob,
    cpu: Cpu,
    miner: &mut GpuMiner,
    signals: &Signals,
    nonces: RangeInclusive<u32>,
    start: Extranonce,
    mask: u32,
    found: &Mutex<Found<'_>>,
) -> Result<Search, String> {
    let gpu_signals = signals.branch();
    let cpu_signals = gpu_signals.clone();
    let cpu_start = start.advance(EXTRANONCE_SPLIT);
    let cpu_nonces = nonces.clone();

    let (cpu_half, gpu_half) = thread::scope(|scope| {
        let hashing = scope.spawn(move || {
            let outcome = cpu_shares(job, cpu, &cpu_signals, cpu_nonces, cpu_start, mask, found);
            // Raised however this half ended: it failed, so the run is over; or
            // something stopped it that stops the other half anyway, and the
            // flag is redundant rather than wrong.
            cpu_signals.stop_branch();
            outcome
        });

        let gpu_half = gpu_shares(job, miner, &gpu_signals, nonces, start, mask, found);
        gpu_signals.stop_branch();

        let cpu_half = hashing
            .join()
            .unwrap_or_else(|_| Err("the CPU half of the hybrid share search panicked".into()));
        (cpu_half, gpu_half)
    });

    Ok(combine(cpu_half?, gpu_half?, signals))
}

/// Merge what the two halves did, the way `hybrid.rs` does.
///
/// Hashes add, because the halves ran on disjoint headers. Seconds do not: they
/// ran at the same time, so the search took as long as the slower of them and
/// the combined rate is the sum of the two rates. There is no winner to choose
/// between, which is the whole of what this drops from the original.
fn combine(cpu: Search, gpu: Search, signals: &Signals) -> Search {
    Search {
        winner: None,
        best: 0.0,
        hashes: cpu.hashes + gpu.hashes,
        seconds: cpu.seconds.max(gpu.seconds),
        // The branch stop cannot be the reason: nothing raises it until a half
        // has already returned.
        ending: signals.interrupted().unwrap_or(Ending::Signalled),
        parts: vec![
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
        ],
    }
}

/// Prepare a hasher for one header, or `None` for the naive path.
///
/// A copy of `Hasher::prepare`, which is private to `cpu.rs`. Built out of the
/// public pieces of `sha256.rs` so that module is not edited either; the whole
/// of it is a `match`, and the alternative was widening a visibility in
/// `cpu.rs`.
fn prepare(hasher: Hasher, header: &Header) -> Option<NonceHasher> {
    match hasher {
        Hasher::Naive => None,
        Hasher::Portable => Some(NonceHasher::Midstate(HeaderHasher::new(
            header,
            Backend::Portable,
        ))),
        Hasher::ShaNi => Some(NonceHasher::Midstate(HeaderHasher::new(
            header,
            Backend::ShaNi,
        ))),
        Hasher::RustCrypto => Some(NonceHasher::RustCrypto(RustCryptoHasher::new(header))),
        Hasher::RustCryptoPlain => Some(NonceHasher::RustCryptoPlain(RustCryptoPlainHasher::new(
            header,
        ))),
    }
}

/// A duty cycle for one share worker.
///
/// A copy of `cpu.rs`'s, private there for the same reason. It is here because
/// `MINER_CPU_LOAD_PERCENT` is a promise about the machine rather than about a
/// mode: a miner told to leave half the CPU alone must do that whether it is
/// building blocks or shares.
struct Throttle {
    window: Duration,
    work: Duration,
    started: Instant,
}

impl Throttle {
    fn new(percent: u8) -> Option<Self> {
        if percent >= 100 {
            return None;
        }
        let window = Duration::from_millis(MINER_CPU_THROTTLE_WINDOW_MILLISECONDS);
        Some(Self {
            window,
            work: window.mul_f64(f64::from(percent) / 100.0),
            started: Instant::now(),
        })
    }

    fn pause_if_due(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed < self.work {
            return;
        }
        if let Some(rest) = self.window.checked_sub(elapsed) {
            thread::sleep(rest);
        }
        self.started = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            fixture,
            job::{Job, Jobs},
            messages::{Incoming, Subscribed},
        },
        *,
    };

    /// A job out of the Pool A capture, at whatever share target the test wants.
    ///
    /// Real pool bytes rather than a synthetic notify: the splice, the branch
    /// and the prevhash are the ones a pool actually sent, so a search that
    /// grinds this is grinding a header the pool would recognise.
    fn captured_job(difficulty: f64) -> Job {
        let frames = fixture::load(fixture::POOL_A);
        let subscribed = Subscribed::parse(
            frames
                .iter()
                .find(|frame| !frame.is_send() && frame.json["id"] == 1)
                .expect("a subscribe reply")
                .result()
                .expect("a result"),
        )
        .expect("a subscribe reply parses");

        let notify = frames
            .iter()
            .find_map(|frame| match Incoming::parse(&frame.line) {
                Ok(Incoming::Notify(notify)) => Some(notify),
                _ => None,
            })
            .expect("the capture has notifies");

        Job::new(
            notify,
            &subscribed,
            ShareTarget::from_difficulty(difficulty).expect("a test difficulty"),
        )
    }

    /// One CPU worker, the fastest hasher this machine has, no throttle.
    fn one_worker() -> Cpu {
        Cpu {
            workers: 1,
            hasher: Hasher::detect(),
            load_percent: 100,
        }
    }

    /// Run a share search that stops itself after `enough` shares.
    ///
    /// The stop is the search's own `Signals`, raised from inside the callback,
    /// which is exactly how `run.rs` stops one on `clean_jobs`.
    ///
    /// `nonces` is short in every test here, for two reasons: the stop flag is
    /// only read at the top of a range, so a short one bounds how long a test
    /// runs past its last share; and these run in a debug build at every step
    /// boundary, where a hash costs an order of magnitude more than it does in
    /// the binary. Every difficulty below is chosen so the whole search is tens
    /// of thousands of hashes.
    fn collect(
        job: &dyn ShareJob,
        cpu: Cpu,
        nonces: RangeInclusive<u32>,
        enough: usize,
    ) -> (Vec<Hit>, Search) {
        let signals = Signals::unwatched();
        let hits = Mutex::new(Vec::new());

        let search = {
            let hits = &hits;
            let signals = &signals;
            let mut report = move |hit: Hit| {
                let mut hits = hits.lock().expect("hit list poisoned");
                hits.push(hit);
                if hits.len() >= enough {
                    signals.mark_stale();
                }
                Ok(())
            };
            search_shares_over(
                job,
                Some(cpu),
                None,
                signals,
                nonces,
                Extranonce::ZERO,
                None,
                &mut report,
            )
            .expect("a share search over a captured job")
        };

        (hits.into_inner().expect("hit list poisoned"), search)
    }

    #[test]
    fn a_share_search_reports_every_share_and_does_not_stop_at_the_first() {
        // The inversion this whole module exists for. A block search returns on
        // its first hit because there is one block; a share search carries on,
        // because every share is separately worth credit and the job is not
        // over because it paid once.
        // 1e-6 is one share per ~4,300 hashes, so eight of them is a search
        // of about 34,000 — cheap even unoptimised.
        let job = captured_job(1e-6);
        let (hits, search) = collect(&job, one_worker(), 0..=0xfff, 8);

        assert!(
            hits.len() >= 8,
            "a share search stopped at {} shares, which means it returned on one",
            hits.len()
        );
        assert!(search.winner.is_none(), "a share miner has no winner");
        assert_eq!(search.ending, Ending::Stale, "the callback raised it");
        assert!(search.hashes > 0 && search.seconds > 0.0);
    }

    #[test]
    fn every_reported_share_rebuilds_into_a_header_that_meets_the_target() {
        // A `Hit` is three numbers; what makes it a share is that the header
        // they name meets the target. Checked here through `rust-bitcoin`
        // rather than through whichever hasher found it — the same rule the
        // search itself applies, applied again from outside.
        let job = captured_job(1e-6);
        let (hits, _) = collect(&job, one_worker(), 0..=0xfff, 8);

        for hit in &hits {
            let mut header = job.header(hit.extranonce2, hit.version);
            header.nonce = hit.nonce;
            assert!(
                job.target().is_met_by(header.block_hash()),
                "reported {hit:?} is not a share"
            );
            assert_eq!(hit.version, job.version(), "nothing rolled the version yet");
        }

        // And they are distinct: a search reporting the same header twice would
        // be counted twice by the pool and rejected as a duplicate.
        let mut seen: Vec<(u64, u32)> = hits
            .iter()
            .map(|hit| (hit.extranonce2.0, hit.nonce))
            .collect();
        seen.sort_unstable();
        let total = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), total, "a share was reported twice");
    }

    #[test]
    fn a_range_that_is_not_a_whole_number_of_lanes_reports_every_share_in_it() {
        // 4 x 765 + 3 nonces, so the walk ends on a remainder whether `LANES`
        // is 2 or 4, and the last nonce, 3062, is one of this job's shares:
        // a walk that dropped its remainder would miss it. Starting at 0
        // keeps a stop check in every range, so the search ends on the first
        // nonce of the next extranonce2, after the callback has asked it to.
        let nonces = 0..=3_062;
        let job = captured_job(1e-7);
        let header = job.header(Extranonce::ZERO, job.version());
        let expected: Vec<Hit> = nonces
            .clone()
            .filter(|&nonce| {
                let mut header = header;
                header.nonce = nonce;
                job.target().is_met_by(header.block_hash())
            })
            .map(|nonce| Hit {
                extranonce2: Extranonce::ZERO,
                nonce,
                version: job.version(),
            })
            .collect();
        assert!(
            expected.len() > 4,
            "the range should hold several shares, not {}",
            expected.len()
        );
        assert_eq!(
            expected.last().map(|hit| hit.nonce),
            Some(3_062),
            "the last nonce is meant to be a share"
        );

        let (hits, _) = collect(&job, one_worker(), nonces, expected.len());
        let first_range: Vec<Hit> = hits
            .into_iter()
            .filter(|hit| hit.extranonce2 == Extranonce::ZERO)
            .collect();
        assert_eq!(first_range, expected);
    }

    #[test]
    fn a_share_is_a_block_only_when_it_meets_its_own_bits() {
        // The mainnet genesis header meets the target its bits name; a share
        // of a captured mainnet job at difficulty 1e-6 misses it by twelve
        // orders of magnitude, and is exactly what a share line ordinarily is.
        use bitcoin::{Network, blockdata::constants::genesis_block};
        assert!(is_block(&genesis_block(Network::Bitcoin).header));

        let job = captured_job(1e-6);
        let (hits, _) = collect(&job, one_worker(), 0..=0xfff, 4);
        for hit in &hits {
            let mut header = job.header(hit.extranonce2, hit.version);
            header.nonce = hit.nonce;
            assert!(job.target().is_met_by(header.block_hash()), "a share");
            assert!(!is_block(&header), "{hit:?} is a share and not a block");
        }
    }

    #[test]
    fn the_extranonce2_rolls_when_the_nonce_space_runs_out() {
        // The walk that makes a job last longer than 2^32 headers. With a
        // single worker and a 16-bit nonce range, the shares have to come from
        // more than one extranonce2 or nothing is rolling.
        // A 1,024-nonce range against one share per ~4,300 hashes, so a share
        // costs about four rolls and eight of them cannot come from one.
        let job = captured_job(1e-6);
        let (hits, _) = collect(&job, one_worker(), 0..=0x3ff, 8);

        let mut rolls: Vec<u64> = hits.iter().map(|hit| hit.extranonce2.0).collect();
        rolls.sort_unstable();
        rolls.dedup();
        assert!(
            rolls.len() > 1,
            "every share came from extranonce2 {rolls:?}, so the roll never happened"
        );
        // Ascending from where it was told to start, one at a time, rather than
        // from wherever a wrap or a stray advance would put it.
        assert!(
            rolls.iter().all(|value| *value < 1_000),
            "the walk left its own neighbourhood: {rolls:?}"
        );
    }

    #[test]
    fn every_worker_walks_its_own_extranonce2() {
        // Two workers handed the same extranonce2 build the same coinbase, the
        // same merkle root and byte-identical headers — a device's worth of
        // electricity spent re-deriving digests the other already has. The same
        // argument `cpu.rs` makes, one layer up.
        let job = captured_job(1e-6);
        let workers = 4;
        let cpu = Cpu {
            workers,
            ..one_worker()
        };
        let (hits, _) = collect(&job, cpu, 0..=0x3ff, 16);

        // Worker `w` starts at extranonce2 `w` and steps by the worker count,
        // so the residue mod the worker count *is* the worker. Asserted that
        // way rather than by counting distinct values, which one worker rolling
        // on its own would also satisfy.
        let mut lanes: Vec<u64> = hits
            .iter()
            .map(|hit| hit.extranonce2.0 % workers as u64)
            .collect();
        lanes.sort_unstable();
        lanes.dedup();
        assert!(
            lanes.len() >= 2,
            "every share came from one worker's lane: {lanes:?}"
        );
        for hit in &hits {
            let lane = hit.extranonce2.0 % workers as u64;
            assert!(
                hit.extranonce2.0 >= lane,
                "worker {lane} walked below the extranonce2 it was handed"
            );
        }
    }

    #[test]
    fn a_failing_callback_ends_the_search_rather_than_being_ground_past() {
        // The pool socket going away is the expected failure here, not an
        // exotic one, and every worker has to stop for it. Without the shared
        // flag the other workers would grind on until something outside raised
        // a signal, which for a dead connection is never.
        let job = captured_job(1e-6);
        let signals = Signals::unwatched();
        let mut report = |_: Hit| Err("the pool closed the connection".to_string());

        // `let ... else` rather than `expect_err`, because `cpu::Search` does
        // not implement `Debug` and `cpu.rs` is not edited to make it.
        let Err(why) = search_shares_over(
            &job,
            Some(Cpu {
                workers: 4,
                ..one_worker()
            }),
            None,
            &signals,
            0..=0xffff,
            Extranonce::ZERO,
            None,
            &mut report,
        ) else {
            panic!("a callback that fails should end the search");
        };

        assert_eq!(why, "the pool closed the connection");
    }

    #[test]
    fn a_search_with_no_device_is_named_rather_than_silently_doing_nothing() {
        let job = captured_job(1.0);
        let signals = Signals::unwatched();
        let mut report = |_: Hit| Ok(());
        let Err(why) = search_shares_over(
            &job,
            None,
            None,
            &signals,
            0..=0xff,
            Extranonce::ZERO,
            None,
            &mut report,
        ) else {
            panic!("no device should not be a search");
        };
        assert!(why.contains("no device"), "{why}");
    }

    #[test]
    fn a_stale_job_stops_the_search_the_way_a_clean_jobs_will() {
        // `clean_jobs` maps onto the existing stale discipline, so the stop
        // path a pool will use is the one already there. Raised before the
        // search starts, which is the worst case for latency: the first check
        // is at the top of the first nonce range.
        let job = captured_job(1.0);
        let signals = Signals::unwatched();
        signals.mark_stale();

        let mut report = |_: Hit| Ok(());
        let search = search_shares_over(
            &job,
            Some(one_worker()),
            None,
            &signals,
            0..=0xffff,
            Extranonce::ZERO,
            None,
            &mut report,
        )
        .expect("a stale search still reports what it did");

        assert_eq!(search.ending, Ending::Stale);
        assert!(search.winner.is_none());
    }

    #[test]
    fn a_job_table_and_a_search_agree_about_which_job_is_current() {
        // The seam `run.rs` is built on: the table says what to grind, the search
        // grinds it, and a share names the job it was found under rather than
        // whichever job is current when it is submitted.
        let job = captured_job(1e-6);
        let mut jobs = Jobs::new();
        jobs.accept(job.clone());

        let current = jobs.current().expect("a job was accepted").clone();
        assert_eq!(current.id(), job.id());

        let (hits, _) = collect(&current, one_worker(), 0..=0xfff, 4);
        for hit in &hits {
            let mut header = current.header(hit.extranonce2, hit.version);
            header.nonce = hit.nonce;
            assert!(
                jobs.get(current.id())
                    .expect("the job is still in the table")
                    .target()
                    .is_met_by(header.block_hash())
            );
        }
    }

    #[test]
    fn a_rolled_share_is_a_share_under_the_version_it_reports() {
        // The end-to-end property: a hit found with a rolled version must
        // rebuild through that version and not the job's announced one. Getting
        // this wrong produces shares the pool rejects for a header it cannot
        // reconstruct — and the search itself would never notice, because it
        // verified against the header it actually hashed.
        const MASK: u32 = 0x1fff_e000;
        let job = captured_job(1e-6);
        let signals = Signals::unwatched();
        let hits = Mutex::new(Vec::new());

        {
            let hits = &hits;
            let signals = &signals;
            let mut report = move |hit: Hit| {
                let mut hits = hits.lock().expect("hit list poisoned");
                hits.push(hit);
                if hits.len() >= 8 {
                    signals.mark_stale();
                }
                Ok(())
            };
            search_shares_over(
                &job,
                Some(one_worker()),
                None,
                signals,
                // One nonce range per version, so the version roll is reached
                // rather than the search sitting in the first one forever.
                0..=0x3ff,
                Extranonce::ZERO,
                Some(MASK),
                &mut report,
            )
            .expect("a rolled share search");
        }

        let hits = hits.into_inner().expect("hit list poisoned");
        assert!(hits.len() >= 8);

        let mut rolled = 0;
        for hit in &hits {
            let mut header = job.header(hit.extranonce2, hit.version);
            header.nonce = hit.nonce;
            assert!(
                job.target().is_met_by(header.block_hash()),
                "{hit:?} is not a share under the version it reports"
            );
            assert_eq!(
                hit.version & !MASK,
                job.version() & !MASK,
                "{hit:?} rolled outside the mask"
            );
            if hit.version != job.version() {
                rolled += 1;
            }
        }
        assert!(
            rolled > 0,
            "every share came from the announced version, so nothing rolled"
        );
    }

    /// A job's header under its announced version and under that version with
    /// bit 13 flipped, at a difficulty easy enough that both win often.
    fn rolled_pair() -> (Job, Header, Header) {
        let job = captured_job(1e-9);
        let first = job.header(Extranonce::ZERO, job.version());
        let second = job.header(Extranonce::ZERO, job.version() ^ (1 << 13));
        (job, first, second)
    }

    /// For each nonce up to `count`: which of the two headers it is a share
    /// under, as rust-bitcoin judges it.
    fn verdicts(job: &Job, headers: [Header; 2], count: u32) -> Vec<(u32, [bool; 2])> {
        (0..count)
            .map(|nonce| {
                (
                    nonce,
                    headers.map(|header| GpuMiner::verify(&header, job.target().inner(), nonce)),
                )
            })
            .collect()
    }

    #[test]
    fn a_pair_winner_is_reported_under_every_version_it_verifies_under() {
        let (job, first, second) = rolled_pair();
        let headers = Headers::pair(first, second).expect("a rolled pair");
        let verdicts = verdicts(&job, [first, second], 400);

        // The list `search_pair` writes: a nonce once per version that wins.
        let mut listed = Vec::new();
        let mut expected = Vec::new();
        for (nonce, wins) in &verdicts {
            for (won, header) in wins.iter().zip([first, second]) {
                if *won {
                    listed.push(*nonce);
                    expected.push((*nonce, header.version.to_consensus() as u32));
                }
            }
        }
        assert!(
            verdicts.iter().any(|(_, wins)| wins == &[true, true]),
            "the sample should hold a nonce that wins under both versions"
        );
        assert!(
            verdicts.iter().any(|(_, wins)| wins == &[true, false])
                && verdicts.iter().any(|(_, wins)| wins == &[false, true]),
            "and nonces that win under only one of them"
        );

        listed.reverse();
        let attributed =
            attribute(&listed, &headers, job.target().inner()).expect("a correct list attributes");
        assert_eq!(attributed, expected);
    }

    #[test]
    fn a_pair_winner_listed_fewer_times_than_it_verifies_was_dropped() {
        let (job, first, second) = rolled_pair();
        let headers = Headers::pair(first, second).expect("a rolled pair");
        let (both, _) = *verdicts(&job, [first, second], 400)
            .iter()
            .find(|(_, wins)| wins == &[true, true])
            .expect("a nonce that wins under both versions");

        let error = attribute(&[both], &headers, job.target().inner())
            .expect_err("a nonce listed once that wins twice has lost a share");
        assert!(error.contains("dropped"), "{error}");
    }

    #[test]
    fn a_pair_winner_listed_more_times_than_it_verifies_is_refused() {
        let (job, first, second) = rolled_pair();
        let headers = Headers::pair(first, second).expect("a rolled pair");
        let (once, _) = *verdicts(&job, [first, second], 400)
            .iter()
            .find(|(_, wins)| wins == &[false, true])
            .expect("a nonce that wins under the second version only");

        let error = attribute(&[once, once], &headers, job.target().inner())
            .expect_err("a nonce that wins once cannot be two shares");
        assert!(error.contains("invented"), "{error}");
    }

    #[test]
    fn a_claimed_nonce_that_verifies_under_no_version_is_refused() {
        let (job, first, second) = rolled_pair();
        let (neither, _) = *verdicts(&job, [first, second], 400)
            .iter()
            .find(|(_, wins)| wins == &[false, false])
            .expect("a nonce that wins under neither version");

        for headers in [
            Headers::One(first),
            Headers::pair(first, second).expect("a rolled pair"),
        ] {
            let error =
                attribute(&[neither], &headers, job.target().inner()).expect_err("a false claim");
            assert!(error.contains("rejects"), "{error}");
        }
    }

    #[test]
    fn a_single_dispatch_attributes_every_winner_to_its_one_version() {
        let (job, first, _) = rolled_pair();
        let winners: Vec<u32> = (0..400)
            .filter(|nonce| GpuMiner::verify(&first, job.target().inner(), *nonce))
            .collect();
        let attributed = attribute(&winners, &Headers::One(first), job.target().inner())
            .expect("a single header's winners attribute");
        assert!(!attributed.is_empty());
        assert!(
            attributed
                .iter()
                .all(|(_, version)| *version == job.version())
        );
    }

    /// A GPU share search under a one-bit mask, against the target it reports
    /// shares at. Run by hand, since it needs a GPU:
    ///
    /// ```sh
    /// cargo test --release stratum::search::tests::the_gpu -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "needs a GPU"]
    fn the_gpu_reports_paired_shares_under_the_versions_that_won() {
        let job = captured_job(1e-6);
        let mut miner = GpuMiner::new(crate::gpu::GpuConfig {
            lanes: 4_096,
            nonces_per_lane: 64,
            capacity: 4_096,
            pipeline: 2,
            load_percent: 100,
        })
        .expect("a GPU");
        let signals = Signals::unwatched();
        let hits = Mutex::new(Vec::new());
        {
            let hits = &hits;
            let signals = &signals;
            let mut report = move |hit: Hit| {
                let mut hits = hits.lock().expect("hit list poisoned");
                hits.push(hit);
                if hits.len() >= 200 {
                    signals.mark_stale();
                }
                Ok(())
            };
            search_shares_over(
                &job,
                None,
                Some(&mut miner),
                signals,
                0..=0xffff,
                Extranonce::ZERO,
                Some(1 << 13),
                &mut report,
            )
            .expect("a paired GPU share search");
        }

        let hits = hits.into_inner().expect("hit list poisoned");
        let mut versions = std::collections::BTreeSet::new();
        for hit in &hits {
            let mut header = job.header(hit.extranonce2, hit.version);
            header.nonce = hit.nonce;
            assert!(
                job.target().is_met_by(header.block_hash()),
                "{hit:?} is not a share under the version it reports"
            );
            versions.insert(hit.version);
        }
        assert_eq!(
            versions,
            [job.version(), job.version() ^ (1 << 13)].into(),
            "both versions of the pair should have produced shares"
        );
    }

    /// The AsicBoost measurement: the GPU share search with and without a
    /// pair to hash, interleaved, at a target nothing meets, so what is
    /// measured is the walk.
    ///
    /// ```sh
    /// cargo test --release stratum::search::tests::the_gpu_share_search_pairs -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "a measurement, not an assertion; needs a GPU"]
    fn the_gpu_share_search_pairs_versions() {
        let job = captured_job(1e12);
        let config = crate::gpu::GpuConfig {
            lanes: crate::constants::MINER_GPU_LANES,
            nonces_per_lane: crate::constants::MINER_GPU_NONCES,
            capacity: crate::constants::MINER_GPU_CAPACITY,
            pipeline: crate::constants::MINER_GPU_PIPELINE,
            load_percent: 100,
        };
        let mut miner = GpuMiner::new(config).expect("a GPU");

        for round in 0..3 {
            for (name, mask) in [("single", None), ("paired", Some(1 << 13))] {
                let signals = Signals::unwatched();
                let stop = signals.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_secs(20));
                    stop.mark_stale();
                });
                let mut report =
                    |hit: Hit| panic!("difficulty 1e12 should find nothing, got {hit:?}");
                let search = search_shares_over(
                    &job,
                    None,
                    Some(&mut miner),
                    &signals,
                    0..=block::NONCE_MAX,
                    Extranonce::ZERO,
                    mask,
                    &mut report,
                )
                .expect("a GPU share search");
                println!(
                    "round {round}, {name}: {} hashes in {:.2}s: {:.2} MH/s",
                    search.hashes,
                    search.seconds,
                    search.hashes as f64 / search.seconds / 1e6,
                );
                std::thread::sleep(Duration::from_secs(10));
            }
        }
    }

    /// The share search's rate against the block search's, run by hand.
    ///
    /// ```sh
    /// cargo test --release stratum::search::tests::the_share_search -- --ignored --nocapture
    /// ```
    ///
    /// A share search measurably slower than the block search has lost the
    /// midstate somewhere — that is the whole risk of this step, and a rate is
    /// the only thing that shows it. Not in the default suite because a timed
    /// measurement on a shared machine is not an assertion.
    #[test]
    #[ignore = "a measurement, not an assertion"]
    fn the_share_search_runs_at_the_block_search_rate() {
        // An impossible target, so nothing is ever reported and what is
        // measured is the walk rather than the reporting.
        let job = captured_job(1e12);
        let cpu = Cpu {
            workers: std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(4),
            hasher: Hasher::detect(),
            load_percent: 100,
        };

        let signals = Signals::unwatched();
        let stop = signals.clone();
        let started = Instant::now();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(10));
            stop.mark_stale();
        });

        let mut report = |hit: Hit| panic!("difficulty 1e12 should find nothing, got {hit:?}");
        let search = search_shares_over(
            &job,
            Some(cpu),
            None,
            &signals,
            0..=block::NONCE_MAX,
            Extranonce::ZERO,
            None,
            &mut report,
        )
        .expect("a share search");

        println!(
            "{} hashes in {:.2}s: {:.2} MH/s from {} on the {} hasher",
            search.hashes,
            search.seconds,
            search.hashes as f64 / search.seconds / 1e6,
            cpu.workers,
            cpu.hasher.name(),
        );
        assert!(started.elapsed() >= Duration::from_secs(9));
        assert!(search.hashes > 0);
    }
}
