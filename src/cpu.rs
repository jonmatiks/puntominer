//! The CPU reference search.
//!
//! This is the correctness oracle every later GPU result is measured against.
//!
//! Three hashers are selectable, and the reason there are three is that the
//! obvious one is not a fair opponent. `Naive` is `rust-bitcoin`'s
//! `block_hash()`, re-serializing all 80 bytes and running three compressions
//! per nonce; the other two go through [`HeaderHasher`], which hoists the
//! first compression out of the loop, and differ only in whether the
//! compression function is portable or the x86 SHA instructions. Quoting a GPU
//! speedup against the naive number would be quoting it against a handicap.
//!
//! Whichever hasher runs, a winner is re-checked through `rust-bitcoin` before
//! it is returned. The fast path proposes; the trusted implementation
//! disposes.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bitcoin::{Block, ScriptBuf, hashes::Hash};

use crate::constants::MINER_CPU_THROTTLE_WINDOW_MILLISECONDS;

use super::{
    block::{
        Extranonce, NONCE_MAX, build_block, difficulty_of_hash, meets_target, refresh_merkle_root,
    },
    sha256::{
        self, Backend, HeaderHasher, LANES, NonceHasher, RustCryptoHasher, RustCryptoPlainHasher,
    },
    template::Template,
    watch::{Ending, Signals},
};

/// Which implementation walks the nonce space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hasher {
    /// `rust-bitcoin`'s `block_hash()` per nonce: no midstate, three
    /// compressions. The original baseline, kept so the later numbers have
    /// something to be measured against.
    Naive,
    /// Midstate plus the portable compression function.
    Portable,
    /// Midstate plus the x86 SHA extensions.
    ShaNi,
    /// The `sha2` crate from RustCrypto, with the midstate hoisted out by
    /// cloning the engine after the header's first 64 bytes.
    RustCrypto,
    /// The `sha2` crate used the obvious way, with no midstate. The direct
    /// analogue of `Naive`.
    RustCryptoPlain,
}

impl Hasher {
    /// The fastest hasher this CPU can run.
    pub fn detect() -> Self {
        if sha256::sha_ni_available() {
            Self::ShaNi
        } else {
            Self::Portable
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::detect()),
            "naive" => Ok(Self::Naive),
            "portable" => Ok(Self::Portable),
            "sha-ni" | "shani" => match Backend::parse("sha-ni") {
                Ok(_) => Ok(Self::ShaNi),
                Err(message) => Err(message),
            },
            "rustcrypto" => Ok(Self::RustCrypto),
            "rustcrypto-naive" => Ok(Self::RustCryptoPlain),
            _ => Err(format!(
                "MINER_HASHER must be auto, naive, portable, sha-ni, rustcrypto or \
                 rustcrypto-naive, got {value}"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Naive => "naive",
            Self::Portable => "portable",
            Self::ShaNi => "sha-ni",
            Self::RustCrypto => "rustcrypto",
            Self::RustCryptoPlain => "rustcrypto-naive",
        }
    }

    /// Prepare this hasher for one header, or `None` for the naive path, which
    /// has no state to prepare and re-hashes the whole header per nonce.
    fn prepare(self, header: &bitcoin::block::Header) -> Option<NonceHasher> {
        match self {
            Self::Naive => None,
            Self::Portable => Some(NonceHasher::Midstate(HeaderHasher::new(
                header,
                Backend::Portable,
            ))),
            Self::ShaNi => Some(NonceHasher::Midstate(HeaderHasher::new(
                header,
                Backend::ShaNi,
            ))),
            Self::RustCrypto => Some(NonceHasher::RustCrypto(RustCryptoHasher::new(header))),
            Self::RustCryptoPlain => Some(NonceHasher::RustCryptoPlain(
                RustCryptoPlainHasher::new(header),
            )),
        }
    }
}

/// The CPU as a search device: how many threads walk, with which hasher, and
/// how hard.
///
/// These travel together everywhere — none of them means anything without the
/// others — and holding them in one place is what makes this the counterpart of
/// [`super::gpu::GpuMiner`]: a handle to a device, so a search that uses both
/// devices takes one of each rather than a list of knobs.
#[derive(Clone, Copy, Debug)]
pub struct Cpu {
    pub workers: usize,
    pub hasher: Hasher,
    /// Duty cycle per worker, 1 to 100. See `MINER_CPU_LOAD_PERCENT`.
    pub load_percent: u8,
}

/// A duty cycle for one search worker.
///
/// Hash for `percent` of every
/// window, then sleep out the rest of it, so a search can be told to leave some
/// of the machine alone.
///
/// It is `None` at 100%, which is the point of the type. A full-speed search is
/// what the rest of this project measures, and it must not start reading a clock
/// every 65,536 nonces to support a feature it is not using.
struct Throttle {
    window: Duration,
    /// How much of each window is spent hashing.
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

    /// Sleep out the rest of this window if the worker has used its share of it.
    ///
    /// The window restarts from the moment the sleep ends rather than from a
    /// fixed grid, so a worker that overshoots — a caller checks this every
    /// 65,536 nonces, not continuously — gives up the overshoot from its next
    /// window instead of accumulating a debt it can never pay back.
    ///
    /// The sleep is the one place a worker is not looking at the stop flag, so
    /// it bounds Ctrl-C latency at one window rather than at the whole run.
    fn pause_if_due(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed < self.work {
            return;
        }
        if let Some(remaining) = self.window.checked_sub(elapsed) {
            thread::sleep(remaining);
        }
        self.started = Instant::now();
    }
}

/// How many nonces a worker walks before it looks at the stop flag. Large
/// enough that the check is free, small enough that Ctrl-C is immediate.
const STOP_CHECK_INTERVAL: u32 = 1 << 16;

/// A block whose header meets the template's target.
pub struct Mined {
    pub block: Block,
    pub extranonce: Extranonce,
}

/// What one device contributed to a search that ran on more than one.
///
/// The hybrid search fills these in; every other search leaves them empty,
/// because its total *is* its one device's contribution. They exist because the
/// combined rate cannot say on its own whether adding the second device was
/// worth anything — the number to look at is the smaller half against the
/// larger, and against what the larger measured alone.
#[derive(Clone, Copy, Debug)]
pub struct Part {
    pub device: &'static str,
    pub hashes: u64,
    pub seconds: f64,
}

impl Part {
    pub fn hash_rate(&self) -> f64 {
        if self.seconds > 0.0 {
            self.hashes as f64 / self.seconds
        } else {
            0.0
        }
    }
}

/// What one search attempt did, whether or not it found anything.
///
/// The work is reported even when the winner is `None`: a search that was
/// stopped still hashed, and that count is the whole point of a timed
/// benchmark run.
pub struct Search {
    pub winner: Option<Mined>,
    /// Hashes every worker performed, not just the winner's.
    pub hashes: u64,
    pub seconds: f64,
    /// Why the search returned. The run loop needs this to tell an exit from a
    /// stale template, which is not a reason to stop — only to fetch again.
    pub ending: Ending,
    /// What each device did, for a search that used more than one. Empty
    /// otherwise — see [`Part`].
    pub parts: Vec<Part>,
    /// The difficulty of the best hash this search saw, or zero if it hashed
    /// nothing.
    ///
    /// The measurement a block search otherwise cannot make. Below the target
    /// nothing is reportable — a search either wins or says nothing — and over
    /// a run of any length the best hash seen is the only evidence of how close
    /// the hardware came, and the only number that is comparable with a pool's
    /// best-difficulty column.
    pub best: f64,
}

impl Search {
    pub fn hash_rate(&self) -> f64 {
        if self.seconds > 0.0 {
            self.hashes as f64 / self.seconds
        } else {
            0.0
        }
    }
}

/// Search for a header meeting the template's target.
///
/// Each worker owns a distinct extranonce and therefore a distinct merkle
/// root, so the workers walk genuinely different headers rather than slices of
/// one nonce range. That is the same split the GPU host loop will need — the
/// 32-bit nonce is exhausted in seconds — so the reference miner prototypes it
/// rather than sidestepping it with a stride.
///
/// The search ends when a worker wins, the user signals an exit, or the
/// template goes stale — the last being the one worth abandoning work for,
/// since every hash under a superseded template is waste.
///
/// Every worker walks the whole nonce space under each merkle root, because
/// what makes their work distinct is the extranonce and therefore the header,
/// not the slice of nonce they take.
///
/// `start` is where worker zero begins; the others take the extranonces just
/// after it, and each then steps by the worker count. Where the walk starts
/// changes nothing about the odds — the digests are independent draws wherever
/// they are sampled from — so the only reason to pass anything but
/// [`Extranonce::ZERO`] is to stay off another instance's headers. See
/// `MINER_EXTRANONCE_START`.
pub fn search(
    template: &Template,
    payout: &ScriptBuf,
    cpu: Cpu,
    signals: &Signals,
    start: Extranonce,
) -> Result<Search, String> {
    let Cpu {
        workers,
        hasher,
        load_percent,
    } = cpu;
    let started = Instant::now();
    let hashes = AtomicU64::new(0);
    let winner: Mutex<Option<(Block, Extranonce)>> = Mutex::new(None);
    let found = AtomicBool::new(false);
    // The best hash any worker saw. A maximum rather than a sum, and merged
    // where each worker reports its hashes, because the two answer the same
    // question — what this search did — and a worker that returns without
    // saying so has thrown its own answer away.
    let best = Mutex::new(0.0f64);

    // The header time is fixed for the whole search: rolling it would be a
    // second search dimension, and at these difficulties there is nothing to
    // roll it for. It has to be at least the template's mintime.
    let time = template.curtime.max(template.mintime);
    let target = sha256::target_words(template.target);

    let outcome: Result<(), String> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);

        for worker in 0..workers {
            let hashes = &hashes;
            let winner = &winner;
            let found = &found;
            let target = &target;
            let best = &best;

            handles.push(scope.spawn(move || -> Result<(), String> {
                let mut extranonce = start.advance(worker as u64);
                let mut block = build_block(template, payout, extranonce.0, time)?;
                let mut local_hashes: u64 = 0;
                let mut throttle = Throttle::new(load_percent);
                // The best hash this worker has seen, as the rank that finds it
                // and the difficulty that reports it. The rank is what the loop
                // compares; the difficulty is recomputed through
                // `rust-bitcoin` at each improvement, which happens about as
                // many times as the nonce space has doublings — twenty-odd over
                // a whole range, against four billion hashes.
                let mut best_rank = u32::MAX;
                let mut best_difficulty = 0.0f64;
                let record_best = |difficulty: f64| {
                    let mut shared = best.lock().expect("best mutex poisoned");
                    if difficulty > *shared {
                        *shared = difficulty;
                    }
                };

                loop {
                    // Built once per merkle root, which is what the midstate
                    // is: everything before the nonce, already compressed.
                    let fast = hasher.prepare(&block.header);

                    // `LANES` nonces at a time, which divides the space
                    // exactly, and then each one in ascending order, exactly
                    // as if they had been hashed one by one: the first winner
                    // is the same nonce either way.
                    for first in (0..=NONCE_MAX).step_by(LANES) {
                        let lanes = fast
                            .as_ref()
                            .map(|fast| fast.screen_lanes::<LANES>(first, target));

                        for lane in 0..LANES {
                            let nonce = first + lane as u32;
                            local_hashes += 1;

                            // The verdict and the rank together, from as much
                            // of the digest as they need: almost always word
                            // seven alone. The naive path hashes through
                            // `rust-bitcoin` either way and keeps the digest it
                            // was about to throw away.
                            let (hit, rank) = match &lanes {
                                Some(lanes) => lanes[lane],
                                None => {
                                    block.header.nonce = nonce;
                                    let hash = block.header.block_hash();
                                    (
                                        template.target.is_met_by(hash),
                                        sha256::best_rank(&sha256::digest_words(
                                            &hash.to_byte_array(),
                                        )),
                                    )
                                }
                            };

                            if rank < best_rank {
                                best_rank = rank;
                                block.header.nonce = nonce;
                                best_difficulty = difficulty_of_hash(&block.header.block_hash());
                            }

                            if hit {
                                // The fast hashers are never trusted for the
                                // result, only for finding it: the header goes
                                // back through `rust-bitcoin` before anyone
                                // hears about it.
                                block.header.nonce = nonce;
                                if !meets_target(&block.header, template.target) {
                                    return Err(format!(
                                        "the {} hasher claimed nonce {nonce} at extranonce \
                                         {extranonce}, which rust-bitcoin rejects",
                                        hasher.name()
                                    ));
                                }

                                let mut winner = winner.lock().expect("winner mutex poisoned");
                                if winner.is_none() {
                                    *winner = Some((block.clone(), extranonce));
                                }
                                found.store(true, Ordering::Relaxed);
                                hashes.fetch_add(local_hashes, Ordering::Relaxed);
                                record_best(best_difficulty);
                                return Ok(());
                            }

                            // One boundary for both: the stop flags decide
                            // whether there is any point going on, and the
                            // throttle decides whether to go on *now*. Checked
                            // in that order, so a search that is over does not
                            // sleep first.
                            if nonce.is_multiple_of(STOP_CHECK_INTERVAL) {
                                if found.load(Ordering::Relaxed) || signals.interrupted().is_some()
                                {
                                    hashes.fetch_add(local_hashes, Ordering::Relaxed);
                                    record_best(best_difficulty);
                                    return Ok(());
                                }
                                if let Some(throttle) = throttle.as_mut() {
                                    throttle.pause_if_due();
                                }
                            }
                        }
                    }

                    // The range is exhausted for this merkle root, so move to
                    // the next extranonce this worker owns. Nothing else in the
                    // block changes, so only the root is redone.
                    hashes.fetch_add(local_hashes, Ordering::Relaxed);
                    local_hashes = 0;
                    extranonce = extranonce.advance(workers as u64);
                    block.txdata[0] = super::block::build_coinbase(template, payout, extranonce.0)?;
                    refresh_merkle_root(&mut block)?;
                }
            }));
        }

        for handle in handles {
            handle.join().map_err(|_| "a mining worker panicked")??;
        }
        Ok(())
    });
    outcome?;

    let winner = winner
        .into_inner()
        .expect("winner mutex poisoned")
        .map(|(block, extranonce)| Mined { block, extranonce });

    // A block outranks either interruption: the workers stop the moment one of
    // them wins, so a stale flag raised in the same instant does not un-find it.
    let ending = match &winner {
        Some(_) => Ending::Found,
        None => signals.interrupted().unwrap_or(Ending::Signalled),
    };

    Ok(Search {
        winner,
        hashes: hashes.load(Ordering::Relaxed),
        seconds: started.elapsed().as_secs_f64(),
        ending,
        parts: Vec::new(),
        best: best.into_inner().expect("best mutex poisoned"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::check_block;
    use serde_json::json;

    fn regtest_template() -> Template {
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
    fn a_full_duty_cycle_builds_no_throttle_at_all() {
        // The hot path must not start reading a clock every 65,536 nonces to
        // support a setting nobody asked for, so 100% is the absence of the
        // type rather than a throttle that happens never to sleep.
        assert!(Throttle::new(100).is_none());
        assert!(Throttle::new(99).is_some());
        assert!(Throttle::new(1).is_some());
    }

    #[test]
    fn a_throttled_worker_sleeps_out_the_rest_of_its_window() {
        let window = Duration::from_millis(MINER_CPU_THROTTLE_WINDOW_MILLISECONDS);
        let mut throttle = Throttle::new(50).expect("50% is throttled");

        // Nothing is due yet: the worker has spent none of its half.
        let immediate = Instant::now();
        throttle.pause_if_due();
        assert!(
            immediate.elapsed() < window / 4,
            "a worker inside its share of the window must not sleep"
        );

        // Past its share, so the call has to sleep out the remainder — and the
        // work and the sleep together are one window, which is what makes the
        // percentage mean what it says.
        thread::sleep(throttle.work);
        let paused = Instant::now();
        throttle.pause_if_due();
        let slept = paused.elapsed();
        assert!(
            slept >= window / 4 && slept <= window,
            "expected roughly the rest of the window, slept {slept:?}"
        );

        // And the next window starts from the wake-up, so the worker is owed
        // its full share again rather than paying for the last one twice.
        let after = Instant::now();
        throttle.pause_if_due();
        assert!(after.elapsed() < window / 4);
    }

    #[test]
    fn a_throttled_search_still_finds_a_block_and_reports_its_real_rate() {
        // Throttling changes how fast a search goes, never what it produces:
        // the block still verifies, and the sleeping is inside the seconds the
        // rate is computed from rather than hidden from it.
        let template = regtest_template();
        let signals = Signals::unwatched();

        let search = search(
            &template,
            &payout(),
            Cpu {
                workers: 2,
                hasher: Hasher::detect(),
                load_percent: 25,
            },
            &signals,
            Extranonce::ZERO,
        )
        .expect("the search should not fail");

        let mined = search.winner.expect("regtest difficulty is met quickly");
        check_block(&mined.block, &template).expect("a throttled block is still a valid block");
        assert!(search.seconds > 0.0);
    }

    #[test]
    fn the_search_finds_a_regtest_header_and_it_verifies() {
        let template = regtest_template();
        let signals = Signals::unwatched();

        for hasher in hashers() {
            let search = search(
                &template,
                &payout(),
                Cpu {
                    workers: 2,
                    hasher,
                    load_percent: 100,
                },
                &signals,
                Extranonce::ZERO,
            )
            .expect("the search should not fail");
            assert_eq!(search.ending, Ending::Found);
            let mined = search
                .winner
                .expect("regtest difficulty should be met quickly");

            assert!(meets_target(&mined.block.header, template.target));
            check_block(&mined.block, &template).expect("the mined block should be valid");
            assert!(search.hashes > 0);
        }
    }

    /// Every hasher this CPU can run.
    fn hashers() -> Vec<Hasher> {
        let mut hashers = vec![
            Hasher::Naive,
            Hasher::Portable,
            Hasher::RustCrypto,
            Hasher::RustCryptoPlain,
        ];
        if sha256::sha_ni_available() {
            hashers.push(Hasher::ShaNi);
        }
        hashers
    }

    #[test]
    fn every_hasher_finds_the_same_first_winner() {
        // The hashers must agree on *which* nonce wins, not merely that some
        // nonce does. A hasher that missed a valid nonce would still look
        // healthy on its own — it would just quietly find a later one — and on
        // a real chain that is a lost block.
        let template = regtest_template();
        let signals = Signals::unwatched();

        let nonces: Vec<u32> = hashers()
            .into_iter()
            .map(|hasher| {
                search(
                    &template,
                    &payout(),
                    Cpu {
                        workers: 1,
                        hasher,
                        load_percent: 100,
                    },
                    &signals,
                    Extranonce::ZERO,
                )
                .expect("the search should not fail")
                .winner
                .expect("regtest difficulty should be met quickly")
                .block
                .header
                .nonce
            })
            .collect();

        assert!(
            nonces.windows(2).all(|pair| pair[0] == pair[1]),
            "the hashers disagreed on the winning nonce: {nonces:?}"
        );
    }

    #[test]
    fn a_raised_stop_flag_ends_the_search_without_a_block() {
        let mut template = regtest_template();
        // An impossible target, so the only way out is the stop flag.
        template.target = bitcoin::Target::ZERO;
        let signals = Signals::unwatched();
        signals.stop();

        let search = search(
            &template,
            &payout(),
            Cpu {
                workers: 2,
                hasher: Hasher::detect(),
                load_percent: 100,
            },
            &signals,
            Extranonce::ZERO,
        )
        .expect("the search should not fail");
        assert!(search.winner.is_none());
        assert_eq!(search.ending, Ending::Signalled);
    }

    #[test]
    fn a_stale_template_ends_the_search_and_says_so() {
        // The distinction the run loop turns on: this search returned with no
        // block and no reason to stop, so the run has to fetch a template and
        // carry on rather than treat it as the end.
        let mut template = regtest_template();
        template.target = bitcoin::Target::ZERO;
        let signals = Signals::unwatched();
        signals.mark_stale();

        let search = search(
            &template,
            &payout(),
            Cpu {
                workers: 2,
                hasher: Hasher::detect(),
                load_percent: 100,
            },
            &signals,
            Extranonce::ZERO,
        )
        .expect("the search should not fail");
        assert!(search.winner.is_none());
        assert_eq!(search.ending, Ending::Stale);
    }

    #[test]
    fn the_walk_begins_where_it_was_told_to() {
        // The point of a non-zero start is that the coinbase actually carries
        // it: a start that were quietly dropped would still mine a valid block,
        // and the duplicate work it exists to avoid would go on happening
        // invisibly. So this asserts on where the winner was found, not merely
        // that one was.
        let template = regtest_template();
        let signals = Signals::unwatched();
        let start = Extranonce(9_000_000_000_000_000_000);

        let mined = search(
            &template,
            &payout(),
            Cpu {
                workers: 2,
                hasher: Hasher::detect(),
                load_percent: 100,
            },
            &signals,
            start,
        )
        .expect("the search should not fail")
        .winner
        .expect("regtest difficulty should be met quickly");

        // Two workers, so worker zero owns `start` and worker one `start + 1`.
        // At regtest difficulty neither gets far enough to roll.
        assert!(
            mined.extranonce == start || mined.extranonce == start.advance(1),
            "the winner came from extranonce {} rather than {start} or {}",
            mined.extranonce,
            start.advance(1),
        );
        check_block(&mined.block, &template).expect("the mined block should be valid");
    }

    #[test]
    fn a_start_at_the_end_of_the_space_wraps_instead_of_panicking() {
        // Unreachable by walking, but reachable by configuration — and a debug
        // build would panic on the overflow rather than repeat a merkle root.
        let template = regtest_template();
        let signals = Signals::unwatched();

        let mined = search(
            &template,
            &payout(),
            Cpu {
                workers: 2,
                hasher: Hasher::detect(),
                load_percent: 100,
            },
            &signals,
            Extranonce(u64::MAX),
        )
        .expect("a start at u64::MAX should search, not overflow")
        .winner
        .expect("regtest difficulty should be met quickly");

        check_block(&mined.block, &template).expect("the mined block should be valid");
    }
}
