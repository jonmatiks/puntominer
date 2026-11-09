//! Template freshness: the longpoll watcher, and the flags a search checks
//! between batches of work.
//!
//! A miner that keeps grinding a template the node has moved past is spending
//! real watts on a block that can no longer be accepted. `getblocktemplate`
//! hands out a `longpollid` for exactly this: a second call carrying it blocks
//! until there is better work, so the miner is told rather than left to poll.
//!
//! What "better work" means is worth being precise about, because it is not
//! only a new tip. Core returns the held call when the best block changes, and
//! also — once a minute has passed — when the mempool has been updated. Both
//! are reasons to abandon what is in flight, but for different reasons: after a
//! new tip the block would be rejected, while after new transactions it would
//! simply collect fewer fees than it could. This module does not distinguish
//! them; the search abandons either way, which is what a production miner does
//! when its pool pushes new work.
//!
//! There is one thing a longpoll cannot tell you, and testnet4 is built on it:
//! the min-difficulty window opens twenty minutes after the previous block,
//! which is the clock advancing rather than anything the node could notify
//! about. That is why templates also carry an expiry — see [`Ending::Expired`].
//!
//! The answer to a longpoll is itself a full template, and this module used to
//! discard it so that the run loop stayed the only place a template came from.
//! It is now parsed here and handed over instead — see [`Watcher::prefetched`] —
//! because discarding it meant the run loop stopped hashing for a round trip it
//! had already paid for. The invariant that mattered is kept: the run loop still
//! decides what to do with a template, and this thread never builds a block.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::json;

use crate::{
    constants::{MINER_LONGPOLL_RETRY_SECONDS, MINER_LONGPOLL_SECONDS},
    logger::Logger,
};

use super::{rpc::Rpc, template::Template};

/// Why a search returned.
///
/// The distinction the run loop needs is between "stop" and "start over": a
/// stale template is not a reason to end the run, only to fetch another one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// A header met the target.
    Found,
    /// The user asked the run to stop.
    Signalled,
    /// The node has better work, so everything under this template is waste.
    Stale,
    /// The template is simply old, and nothing has happened to say so.
    ///
    /// This exists because of testnet4. Its min-difficulty window opens twenty
    /// minutes after the previous block — **a function of the clock, not of any
    /// event the node can notify about.** A longpoll answers on a new tip or a
    /// changed mempool and neither of those happens when a window opens, so a
    /// miner that only refetches when told to would grind the hard target
    /// straight through the one minute in twenty it could actually win.
    Expired,
}

impl Ending {
    pub fn name(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::Signalled => "signalled",
            Self::Stale => "stale",
            Self::Expired => "expired",
        }
    }
}

/// The reasons a search abandons work in progress.
///
/// Kept together because every search loop has to check all of them, and
/// cloneable because the watcher thread raises one while the search reads it.
#[derive(Clone)]
pub struct Signals {
    stop: Arc<AtomicBool>,
    /// A second stop, raised by one half of a search on the other.
    ///
    /// A hybrid search grinds one template on the CPU and the GPU at once, and
    /// the half that wins has to stop the other — but not the run, which has a
    /// block to submit and another template to fetch. So a pair of halves share
    /// a stop of their own, made by [`Self::branch`], and `stop` stays the
    /// run's. Every other search carries one of these too; it is simply never
    /// raised.
    branch_stop: Arc<AtomicBool>,
    stale: Arc<AtomicBool>,
    /// When the run began, copied into every clone so they share one clock.
    started: Instant,
    /// Milliseconds after `started` at which the current template expires, or
    /// `u64::MAX` for a template with no expiry.
    ///
    /// Stored as an offset rather than an `Instant` so it can live in an
    /// atomic: this is read on the hot path — once per dispatch on the GPU and
    /// every 65,536 nonces per worker on the CPU — and a mutex there would be
    /// paying for a lock to read a deadline that changes once a minute.
    expiry: Arc<AtomicU64>,
}

impl Signals {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            branch_stop: Arc::new(AtomicBool::new(false)),
            stale: Arc::new(AtomicBool::new(false)),
            started: Instant::now(),
            expiry: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }

    /// A copy of these signals carrying a stop only its own clones can see.
    ///
    /// Everything a search abandons work for stays shared — the user's signal, a
    /// stale template, an expiry — because those are properties of the run and
    /// the template rather than of the device grinding it. What a branch adds is
    /// the one reason a half stops that the run must not hear about: the other
    /// half found the block. Raising the run's stop for that would end the run
    /// on its first success.
    ///
    /// The two halves of a hybrid search take one branch and a clone of it, so
    /// that [`Self::stop_branch`] on either reaches the other and nothing else.
    pub fn branch(&self) -> Self {
        Self {
            branch_stop: Arc::new(AtomicBool::new(false)),
            ..self.clone()
        }
    }

    /// Stop this branch and every clone of it, leaving the run's own stop alone.
    pub fn stop_branch(&self) {
        self.branch_stop.store(true, Ordering::Relaxed);
    }

    /// Signals nothing ever raises: benchmarks and tests, where there is no
    /// watcher and no template to go stale.
    pub fn unwatched() -> Self {
        Self::new(Arc::new(AtomicBool::new(false)))
    }

    /// The flag the process signal handler is registered against.
    pub fn stop_flag(&self) -> &Arc<AtomicBool> {
        &self.stop
    }

    /// Why the work in progress should be abandoned, or `None` to keep going.
    ///
    /// The user's signal wins: a run that is exiting has no use for a fresher
    /// template.
    pub fn interrupted(&self) -> Option<Ending> {
        if self.stopped() {
            Some(Ending::Signalled)
        } else if self.stale.load(Ordering::Relaxed) {
            Some(Ending::Stale)
        } else if self.expired() {
            Some(Ending::Expired)
        } else {
            None
        }
    }

    /// Give the current template a lifetime, after which the search returns so
    /// the run loop can fetch another one.
    ///
    /// Zero means no expiry, which is what every chain but testnet4 wants: a
    /// template there only changes when something happens, and something
    /// happening is what the longpoll is for.
    pub fn renew(&self, seconds: u64) {
        let expiry = match seconds {
            0 => u64::MAX,
            seconds => self
                .elapsed_ms()
                .saturating_add(seconds.saturating_mul(1_000)),
        };
        self.expiry.store(expiry, Ordering::Relaxed);
    }

    pub fn expired(&self) -> bool {
        self.elapsed_ms() >= self.expiry.load(Ordering::Relaxed)
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.branch_stop.load(Ordering::Relaxed)
    }

    pub fn stale(&self) -> bool {
        self.stale.load(Ordering::Relaxed)
    }

    pub fn mark_stale(&self) {
        self.stale.store(true, Ordering::Relaxed);
    }

    /// Declare the template fresh again, which only the run loop may do, and
    /// only once it holds a new one.
    pub fn freshen(&self) {
        self.stale.store(false, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A thread holding one longpoll open against the node.
///
/// Its outputs are the stale flag and — when the longpoll answers with work the
/// run loop is still waiting for — the template that answer carried. It builds
/// no block and submits nothing: the run loop remains the only thing that
/// decides a template is worth grinding, and it applies the same checks to a
/// template handed over here as to one it fetched itself.
pub struct Watcher {
    requests: mpsc::Sender<(u64, String)>,
    notices: mpsc::Receiver<String>,
    /// Templates carried by a longpoll answer, tagged with the generation whose
    /// answer produced them. Separate from `notices` so that draining the log
    /// does not mean deciding about a template, and vice versa.
    templates: mpsc::Receiver<(u64, Template)>,
    /// Which template the run loop is on. The watcher compares the generation
    /// it polled against this before raising the flag, which is what stops a
    /// longpoll that answered late from marking a template stale that was
    /// fetched *because* of it.
    generation: Arc<AtomicU64>,
}

impl Watcher {
    /// Start watching. The thread is deliberately never joined: it spends its
    /// life blocked in a read the node owns the other end of, and a run that is
    /// exiting should not wait out a minute of that. Dropping the sender ends
    /// it at its next turn around the loop.
    /// `prefetch` decides whether the answer to a longpoll is kept and offered
    /// to the run loop or thrown away for the run loop to fetch again.
    pub fn start(rpc: &Rpc, signals: &Signals, prefetch: bool) -> Self {
        let (requests, incoming) = mpsc::channel::<(u64, String)>();
        let (outgoing, notices) = mpsc::channel::<String>();
        let (carried, templates) = mpsc::channel::<(u64, Template)>();
        let generation = Arc::new(AtomicU64::new(0));

        let rpc = rpc.clone();
        let signals = signals.clone();
        let current = Arc::clone(&generation);
        thread::spawn(move || {
            watch(
                &rpc, &signals, &current, &incoming, &outgoing, &carried, prefetch,
            )
        });

        Self {
            requests,
            notices,
            templates,
            generation,
        }
    }

    /// Hold a longpoll open on this template, and declare it fresh.
    ///
    /// Two orderings carry the whole correctness argument.
    ///
    /// The flag is cleared *before* the request is sent, and the watcher never
    /// raises it for a request it has not received, so a change arriving
    /// between the two cannot be cleared away unseen.
    ///
    /// The generation is bumped first, which handles the opposite race. Mining
    /// a block changes the tip, so the longpoll on the template we just mined
    /// answers immediately — and it answers *after* the run loop has already
    /// fetched the next template. Without the generation that late answer would
    /// mark the fresh template stale, and the run would throw away a search it
    /// had only just started.
    ///
    /// Returns false for a node that offered no `longpollid`, which leaves the
    /// run grinding until it wins — correct, just blind.
    pub fn watch(&self, template: &Template, signals: &Signals) -> bool {
        let Some(id) = template.longpollid.clone() else {
            return false;
        };
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        signals.freshen();
        self.requests.send((generation, id)).is_ok()
    }

    /// The template the current longpoll answered with, if one arrived.
    ///
    /// The channel is drained on every call, whether or not the caller ends up
    /// with anything, so an answer the run has moved past is released here
    /// rather than left holding a mainnet transaction set alive until the next
    /// one replaces it.
    ///
    /// Only a template from the generation the run loop is on is returned, and
    /// that check is doing the same job here as it does for the stale flag: a
    /// longpoll that answered late is answering about a template the run has
    /// already replaced, so its template is not the one to grind next. The
    /// caller is expected to be stricter still — see the run loop, which trusts
    /// this only after a search that ended stale.
    pub fn prefetched(&self) -> Option<Template> {
        let generation = self.generation.load(Ordering::Relaxed);
        let mut carried = None;
        while let Ok((sent, template)) = self.templates.try_recv() {
            if sent == generation {
                carried = Some(template);
            }
        }
        carried
    }

    /// Log whatever the watcher has to say.
    ///
    /// It cannot log for itself: `Logger` is borrowed by the run, and the
    /// watcher outlives every scope that could lend it. Failures therefore
    /// queue here and surface the next time the run loop comes around, which
    /// is at worst one search.
    pub fn report(&self, log: &Logger) {
        while let Ok(notice) = self.notices.try_recv() {
            log.log(notice);
        }
    }
}

/// The watcher loop: one longpoll per template, retried until it answers.
///
/// A failed longpoll is not a failed run. The worst it costs is the early
/// warning — the miner keeps working on a template that may be stale, which is
/// exactly what it did before this module existed — so it is reported and
/// retried rather than propagated.
fn watch(
    rpc: &Rpc,
    signals: &Signals,
    current: &AtomicU64,
    requests: &mpsc::Receiver<(u64, String)>,
    notices: &mpsc::Sender<String>,
    carried: &mpsc::Sender<(u64, Template)>,
    prefetch: bool,
) {
    while let Ok((generation, id)) = requests.recv() {
        let mut failures = 0u32;

        while !signals.stopped() {
            let held = rpc.call_timeout(
                "getblocktemplate",
                json!([{"rules": ["segwit"], "longpollid": id}]),
                Duration::from_secs(MINER_LONGPOLL_SECONDS),
            );

            match held {
                Ok(answer) => {
                    if failures > 0 {
                        let _ = notices.send(format!(
                            "longpoll recovered after {failures} failed attempts"
                        ));
                    }
                    // Only if the run loop is still on the template this was
                    // asked about. Anything older has already been replaced.
                    if current.load(Ordering::Relaxed) == generation {
                        // The answer is a full template for the work the node
                        // has just moved to, so it is parsed here rather than
                        // refetched there. This thread is the right place for
                        // it: parsing is the expensive half of a fetch on
                        // mainnet — several thousand transactions to
                        // deserialize — and it happens while the search is
                        // still hashing the template this answer supersedes.
                        //
                        // Sent *before* the flag is raised, and that order is
                        // the point. The search can stop as soon as it sees
                        // stale, so a flag raised first would let the run loop
                        // look for a template still being parsed, find nothing,
                        // and fetch one — paying the round trip this exists to
                        // avoid, occasionally and unreproducibly.
                        if prefetch {
                            match Template::parse(&answer) {
                                Ok(template) => {
                                    let _ = carried.send((generation, template));
                                }
                                // Not fatal, and not even worth retrying: the
                                // run loop fetches its own template whenever
                                // none is offered, which is exactly what this
                                // code did before it offered any.
                                Err(error) => {
                                    let _ = notices.send(format!(
                                        "a longpoll answer did not parse, so the run loop \
                                         will fetch its own template: {error}"
                                    ));
                                }
                            }
                        }
                        signals.mark_stale();
                    }
                    break;
                }
                Err(error) => {
                    failures += 1;
                    if failures == 1 {
                        let _ = notices.send(format!(
                            "longpoll failed, retrying every {MINER_LONGPOLL_RETRY_SECONDS}s \
                             until it answers: {error}"
                        ));
                    }
                    thread::sleep(Duration::from_secs(MINER_LONGPOLL_RETRY_SECONDS));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stop_signal_outranks_a_stale_template() {
        let signals = Signals::unwatched();
        assert_eq!(signals.interrupted(), None);

        signals.mark_stale();
        assert_eq!(signals.interrupted(), Some(Ending::Stale));

        // A run that is exiting has no use for a fresher template, so the
        // reason it reports is the user's.
        signals.stop();
        assert_eq!(signals.interrupted(), Some(Ending::Signalled));
    }

    #[test]
    fn a_template_expires_on_the_clock_with_nothing_else_raised() {
        // The testnet4 case: no new tip, no new transactions, nothing for a
        // longpoll to answer — and the work should still be abandoned, because
        // the min-difficulty window opens on time rather than on an event.
        let signals = Signals::unwatched();
        assert_eq!(signals.interrupted(), None);

        signals.renew(0);
        assert!(!signals.expired(), "zero seconds means no expiry at all");

        signals.renew(1);
        assert!(!signals.expired());
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(signals.expired());
        assert_eq!(signals.interrupted(), Some(Ending::Expired));

        // And it ranks below both of the others: a run that is exiting, or a
        // template the node has superseded, does not need a fresher one.
        signals.mark_stale();
        assert_eq!(signals.interrupted(), Some(Ending::Stale));
        signals.stop();
        assert_eq!(signals.interrupted(), Some(Ending::Signalled));
    }

    /// A watcher with no thread behind it, so the handoff can be driven by hand.
    struct Handoff {
        watcher: Watcher,
        /// Stands in for the watcher thread: what it would send on parsing an
        /// answer to the longpoll for a given generation.
        carried: mpsc::Sender<(u64, Template)>,
        /// The far ends nothing here uses, held rather than dropped: dropping
        /// either would disconnect a channel the watcher still owns.
        _requests: mpsc::Receiver<(u64, String)>,
        _notices: mpsc::Sender<String>,
    }

    fn handoff(generation: u64) -> Handoff {
        let (requests, incoming) = mpsc::channel();
        let (outgoing, notices) = mpsc::channel();
        let (carried, templates) = mpsc::channel();
        Handoff {
            watcher: Watcher {
                requests,
                notices,
                templates,
                generation: Arc::new(AtomicU64::new(generation)),
            },
            carried,
            _requests: incoming,
            _notices: outgoing,
        }
    }

    #[test]
    fn an_answer_for_the_template_being_ground_is_offered_once() {
        let held = handoff(3);
        held.carried
            .send((3, crate::template::sample_at(961_092)))
            .expect("the watcher holds the receiver");

        let offered = held.watcher.prefetched().expect("generation 3 is current");
        assert_eq!(offered.height, 961_092);

        // Drained, not merely read: a second search must not be handed the
        // template the first one was already given.
        assert!(held.watcher.prefetched().is_none());
    }

    #[test]
    fn an_answer_from_a_superseded_longpoll_is_dropped_and_not_left_queued() {
        let held = handoff(5);
        held.carried
            .send((4, crate::template::sample_at(961_000)))
            .expect("the watcher holds the receiver");

        assert!(
            held.watcher.prefetched().is_none(),
            "generation 4 answered about a template the run has already replaced"
        );

        // And it was released rather than left to be mistaken for a fresh
        // answer once the generation caught up with it.
        held.carried
            .send((5, crate::template::sample_at(961_092)))
            .expect("the watcher holds the receiver");
        assert_eq!(
            held.watcher.prefetched().map(|offered| offered.height),
            Some(961_092)
        );
    }

    #[test]
    fn the_last_answer_wins_when_several_are_queued() {
        let held = handoff(7);
        for height in [961_090, 961_091, 961_092] {
            held.carried
                .send((7, crate::template::sample_at(height)))
                .expect("the watcher holds the receiver");
        }

        assert_eq!(
            held.watcher.prefetched().map(|offered| offered.height),
            Some(961_092),
            "the newest answer describes the node's work; the others are behind it"
        );
    }

    #[test]
    fn a_branch_stops_its_siblings_without_stopping_the_run() {
        // The hybrid search's whole requirement: the half that wins ends the
        // other half's work, and the run goes on to submit the block and fetch
        // another template.
        let run = Signals::unwatched();
        let gpu = run.branch();
        let cpu = gpu.clone();

        cpu.stop_branch();
        assert!(gpu.stopped(), "a branch reaches its clones");
        assert_eq!(gpu.interrupted(), Some(Ending::Signalled));
        assert!(!run.stopped(), "and stops there, not at the run");

        // A second search branches again and starts unstopped, which is what
        // makes the flag per-search rather than per-run.
        assert!(!run.branch().stopped());

        // The run's own signals still reach every branch: they are the reasons
        // that belong to the run and the template rather than to a device.
        let branch = run.branch();
        run.mark_stale();
        assert_eq!(branch.interrupted(), Some(Ending::Stale));
        run.stop();
        assert!(branch.stopped());
    }

    #[test]
    fn freshening_clears_only_the_stale_flag() {
        let signals = Signals::unwatched();
        signals.mark_stale();
        signals.stop();

        signals.freshen();
        assert!(!signals.stale());
        assert!(signals.stopped());
    }
}
