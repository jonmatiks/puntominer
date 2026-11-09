//! `MINER_MODE=stratum`: the loop that connects, takes work, and submits shares.
//!
//! The shape is
//! [`run_watch`](super::super::runner)'s rather than the mining loop's: a
//! thread owns the socket and pushes what arrives at the thread doing the work.
//! That is the existing precedent for anything in this repository that has to
//! react to something outside while a search is running.
//!
//! Three properties this mode has that no other mode here does:
//!
//! - **No node is contacted at all.** `Rpc::new`, the initial-block-download
//!   guard and `payout_script` are all skipped, the way `MINER_MODE=probe`
//!   returns before the RPC client is built. A pool client has no use for a
//!   local node, and requiring one would make this untestable on a machine
//!   without `bitcoind`.
//! - **Nothing is ever submitted to a chain.** What goes out is a
//!   `mining.submit` to one pool, which is a claim on credit rather than a
//!   block. So this mode is not in `Mode::writes_blocks` and is not restricted
//!   to regtest — the risk that rule guards against does not exist here.
//! - **The payout is not this miner's to choose.** The pool builds the
//!   coinbase; this client splices an extranonce into the middle of it and
//!   reads it only to report who it pays — see [`payout`](super::payout).
//!   `MINER_ADDRESS` reaches the pool as a *name* to be credited, not as a
//!   script in a transaction, which is the whole difference between pooled and
//!   solo mining.

use std::{
    sync::{
        Mutex,
        mpsc::{self, Receiver, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    block::{Extranonce, difficulty_of, difficulty_of_hash},
    cpu::Cpu,
    gpu::{GpuConfig, GpuMiner},
    logger::Logger,
    utils::{cpu_model, format_duration, format_scaled},
    watch::{Ending, Signals},
};

use serde_json::{Value, json};

use super::{
    conn::{self, Conn, Writer},
    job::{Job, Jobs, ShareTarget},
    messages::{Incoming, failure},
    payout::{self, Payout},
    pool::{BIP320_MASK, Pool, VersionRolling},
    search::{Hit, is_block, rollable, search_shares},
};

/// What a session did, for the line printed when it ends.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    submitted: u64,
    /// Submitted shares that also met the network target. What this client
    /// found, not what the chain kept — see [`is_block`].
    blocks: u64,
    accepted: u64,
    rejected: u64,
    hashes: u64,
    seconds: f64,
    /// The hardest share this session found, on the scale
    /// `mining.set_difficulty` names — what a pool dashboard shows as best
    /// difficulty. A maximum rather than a total, so it is carried between
    /// tallies with `max` and never added.
    best: f64,
}

/// Mine for a pool until the user stops.
///
/// Reconnects are a normal part of the loop rather than an error: pools drop
/// idle sockets and restart, and a run that ended on the first one would be
/// useless overnight. What a reconnect costs is every job in flight, because
/// the new `extranonce1` makes every coinbase built under the old one wrong.
pub fn run(
    pool: &Pool,
    cpu: Option<Cpu>,
    gpu: Option<GpuConfig>,
    start: Extranonce,
    signals: &Signals,
    log: &Logger,
) -> Result<(), String> {
    if pool.address.is_empty() {
        return Err(
            "MINER_MODE=stratum needs MINER_POOL set to a pool's host:port; there is no \
             default pool"
                .into(),
        );
    }

    // **Checked before a socket is opened, beside the regtest gate in `run` and
    // for the same reason.** `force` sends shares whose version bits the pool
    // never agreed to, which is a thing to do to a server you are testing and
    // not to a stranger's. A run that discovered this after connecting would
    // already have authorized as somebody's worker.
    if pool.version_rolling == VersionRolling::Force && !conn::resolves_to_loopback(&pool.address)?
    {
        return Err(format!(
            "MINER_VERSION_ROLLING=force deliberately rolls version bits the pool did not \
             agree to, so it is refused against {}, which is not on the loopback. It exists \
             to test that a pool rejects those shares, and that is a thing to do to your own \
             pool",
            pool.address
        ));
    }

    // The same two lines a node-backed run opens with, in the same order and
    // for the same reason: which device is grinding, and on which hasher, is
    // the first thing to check when a rate looks wrong, and a log that only
    // named the GPU said nothing about the half of a hybrid run that is not
    // one. What a chain's name occupies there the pool's address occupies
    // here — this mode is pointed at a stranger's server rather than at a
    // network, and that is the thing worth naming first.
    log.log(format!(
        "miner started on {} over stratum v1 with the {} device",
        pool.address,
        match (cpu.is_some(), gpu.is_some()) {
            (true, true) => "hybrid",
            (true, false) => "cpu",
            _ => "gpu",
        },
    ));

    if let Some(cpu) = cpu {
        log.log(format!(
            "cpu model {}, {} workers on the {} hasher",
            cpu_model(),
            cpu.workers,
            cpu.hasher.name()
        ));
    }

    // Opened once and kept across reconnects: acquiring an adapter and compiling
    // the shader costs a second or two, and a pool restarting is not a reason to
    // pay it again.
    let mut gpu = match gpu {
        Some(config) => {
            let miner = GpuMiner::new(config)?;
            log.log(format!(
                "gpu model {} ({}), {} lanes x {} nonces, {} in flight",
                miner.adapter().name,
                miner.adapter().backend,
                config.lanes,
                config.nonces_per_lane,
                config.pipeline,
            ));
            Some(miner)
        }
        None => None,
    };

    // The pool is named by the line above and by `connected to` below; what is
    // left here is what only this line knows.
    log.log(format!(
        "mining as {}, asking for share difficulty {}",
        pool.user, pool.difficulty,
    ));

    let mut total = Tally::default();
    let mut sessions = 0u64;

    while !signals.stopped() {
        sessions += 1;
        match session(pool, cpu, gpu.as_mut(), start, signals, log, total.best) {
            Ok((tally, asked_to_reconnect)) => {
                total.submitted += tally.submitted;
                total.blocks += tally.blocks;
                total.accepted += tally.accepted;
                total.rejected += tally.rejected;
                total.hashes += tally.hashes;
                total.seconds += tally.seconds;
                // The one field a reconnect does not reset: the hardest share
                // of the run is the hardest share of any session in it.
                total.best = total.best.max(tally.best);

                // **No backoff, and the same address.** The pool asked, so
                // there is nothing to wait out; and a V1 frame is not
                // authenticated, so wherever it pointed is not where this run
                // goes.
                if asked_to_reconnect {
                    log.log(format!(
                        "reconnecting to {} now, as the pool asked",
                        pool.address
                    ));
                    continue;
                }
            }
            Err(why) => {
                // A failed session is not a failed run. The exception is a
                // refused authorization, which will be refused identically
                // forever and is worth stopping for rather than retrying every
                // five seconds until somebody notices.
                if why.contains("refused to authorize") {
                    return Err(why);
                }
                log.log(format!("session {sessions} ended: {why}"));
            }
        }

        if signals.stopped() {
            break;
        }
        log.log(format!(
            "reconnecting in {}s; every job in flight is dropped, \
             because a new extranonce1 invalidates all of them",
            pool.reconnect.as_secs()
        ));
        // Polled rather than slept through, so Ctrl-C during a backoff is as
        // responsive as it is inside a search.
        let until = Instant::now() + pool.reconnect;
        while Instant::now() < until && !signals.stopped() {
            thread::sleep(Duration::from_millis(100));
        }
    }

    log.log(format!(
        "{} sessions: {} shares submitted, {} of them blocks, {} accepted, {} rejected, \
         {} hashes over {}{}",
        sessions,
        total.submitted,
        total.blocks,
        total.accepted,
        total.rejected,
        format_scaled(total.hashes as f64, false),
        format_duration(total.seconds),
        best_note(total.best),
    ));
    Ok(())
}

/// How long a quiet pool is tolerated before the socket is called dead.
///
/// Well past any pool's notify interval: Pool A's measured interval is tens
/// of seconds and a quiet mainnet stretch is minutes. This is tuned to "the far
/// end is gone", not to "there should have been work by now".
const IDLE_MAX: Duration = Duration::from_secs(600);

/// How often the reader thread looks up from the socket to check the stop flag.
const READ_POLL: Duration = Duration::from_millis(500);

/// The share ledger, shared between the thread that submits and the thread that
/// hears back.
///
/// Shared rather than passed along the channel because a verdict is worth
/// having the moment it lands. A reply routed through the grinding thread would
/// be logged only when its search ended, which at a 30-second job interval
/// means a share's fate is reported half a minute after the pool decided it —
/// and the whole reason to watch a pool run is seeing that promptly.
#[derive(Debug, Default)]
struct Shares {
    /// Submit id to the share it was sent for, so a reject can name which
    /// share the pool disliked rather than only that one was disliked.
    pending: std::collections::HashMap<u64, Submitted>,
    submitted: u64,
    blocks: u64,
    accepted: u64,
    rejected: u64,
    /// The hardest share submitted this session.
    ///
    /// Kept beside the counts because it is the same kind of record — what this
    /// session sent — and because the ledger is already locked at the moment a
    /// share goes out, which is the moment the number can change. **What it
    /// measures is shares found, not shares the pool liked**: a stale share was
    /// still that hard to find, so this can read slightly above a dashboard
    /// that counts only what it accepted.
    best: f64,
}

/// One share, as it went out.
///
/// The version travels with it so that a verdict can say which version found
/// the share. That is the only evidence available that version rolling is
/// actually doing something: a run with rolling on that only ever submits the
/// announced version has negotiated an extension and not used it, and the
/// accept rate looks identical either way.
#[derive(Clone, Debug)]
struct Submitted {
    job: String,
    nonce: u32,
    version: u32,
    /// What this share was actually worth, so a verdict can say how hard the
    /// share it is about was. A reject at 4.51K and a reject at 1.00 are
    /// different events — the first is a good share the pool refused on
    /// policy, and that distinction is invisible from the counts alone.
    difficulty: f64,
}

/// One connection, from handshake to whatever ends it.
///
/// Returns the tally and whether the pool asked for the reconnect that ends it.
#[allow(clippy::too_many_arguments)]
fn session(
    pool: &Pool,
    cpu: Option<Cpu>,
    gpu: Option<&mut GpuMiner>,
    start: Extranonce,
    signals: &Signals,
    log: &Logger,
    // The run's best share so far, carried in so that the number a session
    // reports is the run's rather than this socket's. A pool drops an idle
    // connection as a matter of course, and a best difficulty that fell back to
    // nothing every time one was replaced would be measuring the socket.
    best: f64,
) -> Result<(Tally, bool), String> {
    let mut conn = Conn::connect(&pool.address)?;
    log.log(format!("connected to {}", conn.peer()));

    let done = conn::handshake(
        &mut conn,
        &pool.agent,
        &pool.user,
        &pool.pass,
        pool.difficulty,
    )?;
    log.log(rolling_note(
        pool.version_rolling,
        done.offered_mask,
        done.version_mask,
    ));

    let mut subscribed = done.subscribed;
    log.log(format!(
        "subscribed: extranonce1 {}, extranonce2_size {}",
        subscribed
            .extranonce1
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        subscribed.extranonce2_size,
    ));

    let writer = conn.writer()?;
    // Short, so the reader is never parked longer than a Ctrl-C should take to
    // be noticed. Silence becomes an error at `IDLE_MAX`, not here.
    conn.set_read_timeout(READ_POLL)?;

    let shares = Mutex::new(Shares {
        best,
        ..Shares::default()
    });
    let (sender, incoming) = mpsc::channel();

    // **A branch, not the run's own signals.** `Signals::stopped` is true when
    // either the run's stop or the branch stop is raised, so ending this
    // session through the run's stop would end the run — and reconnecting is
    // the normal course of a pool session rather than the end of one. The
    // branch stops the reader thread and reaches nothing else; Ctrl-C still
    // reaches both, because the run's stop flag is shared into every clone.
    let session_signals = signals.branch();

    // Scoped, so the reader thread can borrow the logger and the ledger rather
    // than everything being wrapped in an `Arc` to satisfy `'static`.
    let outcome = thread::scope(|scope| {
        let reader = scope.spawn({
            let shares = &shares;
            let signals = &session_signals;
            let pushed = done.pushed;
            let writer = &writer;
            let agent = pool.agent.as_str();
            move || read_frames(conn, sender, pushed, shares, signals, writer, agent, log)
        });

        let outcome = grind(
            pool,
            cpu,
            gpu,
            start,
            done.version_mask,
            &session_signals,
            log,
            &writer,
            &incoming,
            &mut subscribed,
            &shares,
        );

        // The reader checks this every `READ_POLL`, so the scope cannot hang on
        // a pool that has gone quiet.
        session_signals.stop_branch();
        drop(incoming);
        let _ = reader.join();
        outcome
    });

    let (mut tally, asked_to_reconnect) = outcome?;
    let shares = shares.into_inner().expect("share ledger poisoned");
    tally.submitted = shares.submitted;
    tally.blocks = shares.blocks;
    tally.accepted = shares.accepted;
    tally.rejected = shares.rejected;
    tally.best = shares.best;
    Ok((tally, asked_to_reconnect))
}

/// What the log says about version rolling, when a session settles the mask
/// and again whenever the pool moves it.
///
/// `offered` is the pool's mask as sent and `agreed` is what is left of it
/// after [`conn::clamp_mask`]; the two are named apart only when the pool
/// reached outside BIP320.
fn rolling_note(rolling: VersionRolling, offered: Option<u32>, agreed: Option<u32>) -> String {
    let clamped = match offered {
        Some(offered) if offered & !BIP320_MASK != 0 => format!(
            "; the pool offered {offered:08x}, which reaches outside BIP320's \
             {BIP320_MASK:08x}, and only the bits inside it are rolled"
        ),
        _ => String::new(),
    };
    match (agreed, rolling.mask(agreed)) {
        (_, None) => format!("version rolling off{clamped}"),
        (Some(agreed), Some(rolled)) if agreed == rolled => {
            format!("version rolling on, mask {agreed:08x} as the pool agreed{clamped}")
        }
        (agreed, Some(rolled)) => format!(
            "version rolling FORCED to mask {rolled:08x}; the pool agreed to {}. \
             Roughly half the shares should be rejected, and a run where none are \
             means the pool is not checking",
            agreed.map_or("nothing".to_string(), |mask| format!("{mask:08x}"))
        ),
    }
}

/// The reader thread: own the socket, answer for every submit, and wake the
/// grinder whenever the work changes.
///
/// Replies are handled here and never forwarded, and so are the two requests
/// this client answers. Everything else goes down the channel, because acting
/// on it needs the job table the grinder owns.
#[allow(clippy::too_many_arguments)]
fn read_frames(
    mut conn: Conn,
    sender: mpsc::Sender<Result<Incoming, String>>,
    pushed: Vec<Incoming>,
    shares: &Mutex<Shares>,
    signals: &Signals,
    writer: &Writer,
    agent: &str,
    log: &Logger,
) {
    // The frames the pool pushed during the handshake go first and in order,
    // through the same handling as everything that follows. Pool A sends the
    // session's first `set_difficulty` and first `mining.notify` before it
    // answers `mining.authorize` — and, because it coerces a null id to zero, an
    // `{"id":0,"result":true}` acknowledging the `mining.suggest_difficulty`
    // nothing was waiting for. A client that dropped the first two would start
    // at the default difficulty against a later job.
    for frame in pushed {
        if !handle(frame, &sender, shares, signals, writer, agent, log) {
            return;
        }
    }

    let mut last = Instant::now();
    loop {
        if signals.stopped() {
            return;
        }

        match conn.read_timed() {
            Ok(None) => {
                if last.elapsed() > IDLE_MAX {
                    let _ = sender.send(Err(format!(
                        "the pool sent nothing for {}",
                        format_duration(last.elapsed().as_secs_f64())
                    )));
                    signals.mark_stale();
                    return;
                }
            }

            Ok(Some(frame)) => {
                last = Instant::now();
                if !handle(frame, &sender, shares, signals, writer, agent, log) {
                    return;
                }
            }

            Err(why) => {
                let _ = sender.send(Err(why));
                // Ends the search the grinder is inside, so a dead socket is
                // noticed now rather than after the current nonce range.
                signals.mark_stale();
                return;
            }
        }
    }
}

/// Act on one frame from the pool. `false` means the grinder has gone.
///
/// Replies are answered here and never forwarded, because everything a verdict
/// needs is in the ledger and routing one through the grinding thread would
/// mean logging it when the current search ended — half a minute later, at a
/// mainnet pool's job interval.
fn handle(
    frame: Incoming,
    sender: &mpsc::Sender<Result<Incoming, String>>,
    shares: &Mutex<Shares>,
    signals: &Signals,
    writer: &Writer,
    agent: &str,
    log: &Logger,
) -> bool {
    if let Incoming::Reply { id, result, error } = &frame {
        let mut ledger = shares.lock().expect("share ledger poisoned");
        // A null id matches nothing, which is correct rather than a special
        // case: this client numbers every call it expects an answer to.
        match id.and_then(|id| ledger.pending.remove(&id)) {
            Some(share) => match failure(result, error) {
                None => {
                    ledger.accepted += 1;
                    log.log(format!(
                        "share: job {} nonce {:08x} version {:08x} \
                         difficulty {} ({} accepted, {} rejected)",
                        share.job,
                        share.nonce,
                        share.version,
                        format_scaled(share.difficulty, false),
                        ledger.accepted,
                        ledger.rejected
                    ));
                }
                Some(why) => {
                    ledger.rejected += 1;
                    log.log(format!(
                        "share REJECTED: job {} nonce {:08x} version {:08x} \
                         difficulty {}: {why} ({} accepted, {} rejected)",
                        share.job,
                        share.nonce,
                        share.version,
                        format_scaled(share.difficulty, false),
                        ledger.accepted,
                        ledger.rejected
                    ));
                }
            },
            // Expected rather than alarming: a pool may answer a frame this
            // client is not waiting on, and the two measured pools do it in
            // two different spellings — Pool A under id 0, Pool B by
            // echoing a null id.
            None => log.log(format!(
                "the pool answered id {}, which nothing was waiting for",
                id.map_or("null".to_string(), |id| id.to_string())
            )),
        }
        return true;
    }

    // **Answered here, through the shared writer, and never forwarded.** The
    // grinder reads its channel only between searches, so a `pong` routed
    // through it would wait for the job in hand to end — tens of seconds on a
    // mainnet pool, which is long enough for a pool that pings to call the
    // miner dead. `pong` as a method rather than a result is odd, and it is
    // what ESP-Miner sends, which is the largest installed base there is.
    if let Incoming::Ping(id) | Incoming::GetVersion(id) = &frame {
        let (method, reply) = match &frame {
            Incoming::Ping(_) => (
                "mining.ping",
                json!({"id": id, "method": "pong", "params": []}),
            ),
            _ => (
                "client.get_version",
                json!({"id": id, "result": agent, "error": Value::Null}),
            ),
        };
        // A null id is a notification, and asks for nothing back.
        if id.is_null() {
            log.log(format!(
                "ignored {method} with a null id, which asks for no answer"
            ));
            return true;
        }
        if let Err(why) = writer.send(reply) {
            let _ = sender.send(Err(why));
            signals.mark_stale();
            return false;
        }
        log.log(format!("answered {method} id {id}"));
        return true;
    }

    // A new job, or an extranonce1 that invalidates every old one. Either way
    // the search in progress is grinding work the pool has moved on from, so it
    // is ended here and restarted on the newest job — `clean_jobs` decides
    // whether the *held* jobs survive, which the grinder handles.
    // A new job, a new extranonce1, or a new difficulty. The third belongs
    // here for a reason found the hard way: a pool that raises its difficulty
    // mid-job judges the job already in flight at the new one, so a client that
    // only noticed when its search happened to end submits shares below the bar
    // for as long as the search lasts. Against a local Pool B that was 52
    // seconds and seven rejects. A new version mask belongs here for the same
    // reason — the pool judges every share from now on by it — and a
    // `client.reconnect` because it ends the session.
    let wake = matches!(
        frame,
        Incoming::Notify(_)
            | Incoming::SetExtranonce { .. }
            | Incoming::SetDifficulty(_)
            | Incoming::SetVersionMask(_)
            | Incoming::Reconnect(_)
    );
    if sender.send(Ok(frame)).is_err() {
        return false;
    }
    if wake {
        signals.mark_stale();
    }
    true
}

/// The grinding loop: take the newest job, search it, submit what it finds.
///
/// `negotiated` is the mask the handshake settled, clamped, and it moves with
/// every `mining.set_version_mask`. Returns whether the pool asked for a
/// reconnect.
#[allow(clippy::too_many_arguments)]
fn grind(
    pool: &Pool,
    cpu: Option<Cpu>,
    mut gpu: Option<&mut GpuMiner>,
    start: Extranonce,
    mut negotiated: Option<u32>,
    signals: &Signals,
    log: &Logger,
    writer: &Writer,
    incoming: &Receiver<Result<Incoming, String>>,
    subscribed: &mut super::messages::Subscribed,
    shares: &Mutex<Shares>,
) -> Result<(Tally, bool), String> {
    let mut jobs = Jobs::new();
    let mut target = ShareTarget::from_difficulty(pool.difficulty)?;
    let mut tally = Tally::default();
    let mut last_notify: Option<Instant> = None;
    let mut payout = Payout::new(&pool.user);

    loop {
        if signals.stopped() {
            return Ok((tally, false));
        }

        // **Cleared before the channel is drained, never after.** This is
        // `watch.rs`'s generation counter in its simplest form: a notify that
        // landed between a drain and a later clear would have its flag wiped,
        // and the search would then grind a job the pool had already replaced
        // for as long as the pool stayed quiet. Clearing first costs at most
        // one immediately-ended search; clearing last costs the session.
        signals.freshen();

        match drain(
            incoming,
            &mut jobs,
            &mut target,
            &mut negotiated,
            pool.version_rolling,
            &mut tally,
            subscribed,
            &mut last_notify,
            log,
        )? {
            Drained::Closed(why) => return Err(why),
            Drained::Reconnect => return Ok((tally, true)),
            Drained::Open => {}
        }

        let Some(job) = jobs.current().cloned() else {
            // Before the first notify. Every pool sends one within a second of
            // authorizing, so this is a wait rather than a state.
            thread::sleep(Duration::from_millis(50));
            continue;
        };

        for line in payout.check(&job.coinbase(payout::DECODED_AT)) {
            log.log(line);
        }

        // Per job, because whether the version may be rolled at all depends on
        // the version this job announced — see `search::rollable`, and the
        // regtest chain that made every share fail until it did. And against
        // the mask in force now, which a `mining.set_version_mask` moves.
        let rolling = rollable(job.version(), pool.version_rolling.mask(negotiated));

        let mut submitted = 0u64;
        let search = {
            let job_id = job.id().to_string();
            let asked = job.target().difficulty();
            let mut report = |hit: Hit| -> Result<(), String> {
                let mut header = job.header(hit.extranonce2, hit.version);
                header.nonce = hit.nonce;
                // Measured here rather than in the search because this is the
                // one place the header exists in the form the pool will rebuild
                // it in, hash and all. One extra SHA256d per *share*, which is
                // once every few minutes and not once per nonce.
                let hash = header.block_hash();
                let difficulty = difficulty_of_hash(&hash);
                let block = is_block(&header);
                let params = job.submit_params(&pool.user, hit.extranonce2, &header, rolling);

                // The id is taken and recorded *before* the frame goes out, so
                // the reader thread cannot answer a submit this one has not
                // finished writing down.
                let mut ledger = shares.lock().expect("share ledger poisoned");
                let id = writer.call("mining.submit", params)?;
                ledger.pending.insert(
                    id,
                    Submitted {
                        job: job_id.clone(),
                        nonce: hit.nonce,
                        version: hit.version,
                        difficulty,
                    },
                );
                ledger.submitted += 1;
                ledger.blocks += u64::from(block);
                let improved = difficulty > ledger.best;
                if improved {
                    ledger.best = difficulty;
                }
                drop(ledger);

                // **At submit time and apart from the share line**, which is
                // written when the verdict arrives and would otherwise be the
                // only trace. A `true` from the pool accepts the share; nothing
                // in the protocol says whether the block was accepted.
                if block {
                    log.log(format!(
                        "BLOCK FOUND! job {job_id} nonce {:08x} hash {hash} meets the network \
                         difficulty {}; the chain, not the pool's verdict, says whether it \
                         was kept",
                        hit.nonce,
                        format_scaled(difficulty_of(header.bits), false),
                    ));
                }

                // Said the moment it happens, because for a solo pool this is
                // the only progress there is to watch: a session that never
                // finds a block still has a best share, and how close it came
                // is the whole story the counts do not tell. The multiple is
                // there because the difficulty alone means nothing without what
                // was asked for — 5.73K is luck at a share target of 512 and a
                // rounding error at one of 4096.
                if improved {
                    log.log(format!(
                        "best share so far: difficulty {}, {:.1}x the share target of {}",
                        format_scaled(difficulty, false),
                        difficulty / asked,
                        format_scaled(asked, false),
                    ));
                }

                submitted += 1;
                Ok(())
            };

            search_shares(
                &job,
                cpu,
                gpu.as_deref_mut(),
                signals,
                start,
                rolling,
                &mut report,
            )?
        };

        tally.hashes += search.hashes;
        tally.seconds += search.seconds;

        let best = shares.lock().expect("share ledger poisoned").best;
        log.log(format!(
            "job {} ended {}: {submitted} shares from {} hashes in {} at {}H/s{}",
            job.id(),
            search.ending.name(),
            format_scaled(search.hashes as f64, false),
            format_duration(search.seconds),
            format_scaled(search.hashes as f64 / search.seconds.max(1e-9), false),
            best_note(best),
        ));

        if search.ending == Ending::Signalled {
            return Ok((tally, false));
        }
    }
}

/// The best-difficulty tail a progress line ends with, empty until a share has
/// been found.
///
/// Empty rather than `0.00`, because a zero here is not a measurement — it is a
/// session that has not paid yet, and printing it as a number invites reading
/// it as one.
fn best_note(best: f64) -> String {
    if best <= 0.0 {
        return String::new();
    }
    format!(", difficulty {}", format_scaled(best, false))
}

/// Whether the connection is still there after a drain.
enum Drained {
    Open,
    Closed(String),
    /// The pool sent `client.reconnect`.
    Reconnect,
}

/// Take everything the reader thread has pushed and act on it.
#[allow(clippy::too_many_arguments)]
fn drain(
    incoming: &Receiver<Result<Incoming, String>>,
    jobs: &mut Jobs,
    target: &mut ShareTarget,
    negotiated: &mut Option<u32>,
    rolling: VersionRolling,
    tally: &mut Tally,
    subscribed: &mut super::messages::Subscribed,
    last_notify: &mut Option<Instant>,
    log: &Logger,
) -> Result<Drained, String> {
    loop {
        let frame = match incoming.try_recv() {
            Ok(Ok(frame)) => frame,
            Ok(Err(why)) => return Ok(Drained::Closed(why)),
            Err(TryRecvError::Empty) => return Ok(Drained::Open),
            Err(TryRecvError::Disconnected) => {
                return Ok(Drained::Closed("the pool reader thread stopped".into()));
            }
        };

        match frame {
            Incoming::Notify(notify) => {
                let interval = last_notify
                    .replace(Instant::now())
                    .map(|at| {
                        format!(
                            ", {} after the last",
                            format_duration(at.elapsed().as_secs_f64())
                        )
                    })
                    .unwrap_or_default();
                // Built with the target in force *now*, and it keeps that
                // target for as long as it lives: a `set_difficulty` arriving
                // later must not retroactively change what this job's shares
                // were worth.
                let job = Job::new(notify, subscribed, *target);
                let id = job.id().to_string();
                let clean = job.clean_jobs();
                jobs.accept(job);
                log.log(format!(
                    "job {id}, clean_jobs {clean}, {} held{interval}",
                    jobs.len()
                ));
            }

            Incoming::SetDifficulty(difficulty) => {
                *target = ShareTarget::from_difficulty(difficulty)?;
                // Every held job follows, because the pool judges by what it
                // currently wants rather than by what it announced — see
                // `Jobs::retarget`, which is where that measurement lives.
                jobs.retarget(*target);
                // **The expected seconds per share, at this run's own measured
                // rate.** A difficulty on its own is a number; the same number
                // spelled out as "49 minutes per share" is the difference
                // between noticing a floor of 512 immediately and mistaking it
                // for a hung socket, which is the failure the cross-pool
                // measurements were about. Before any hashing there is no rate, so
                // the expected hash count is said instead.
                let hashes = difficulty * 4_294_967_296.0;
                let expected = if tally.seconds > 0.0 && tally.hashes > 0 {
                    let rate = tally.hashes as f64 / tally.seconds;
                    format!(
                        "{} hashes, one every {} at {}H/s",
                        format_scaled(hashes, false),
                        format_duration(hashes / rate),
                        format_scaled(rate, false),
                    )
                } else {
                    format!("{} hashes per share", format_scaled(hashes, false))
                };
                log.log(format!("share difficulty {difficulty}: {expected}"));
            }

            Incoming::SetExtranonce {
                extranonce1,
                extranonce2_size,
            } => {
                // A new extranonce1 invalidates every coinbase built under the
                // old one, so the table goes wholesale — the same reason a
                // reconnect drops it. The session's pair moves with it, because
                // every job after this one is built from it: a table cleared
                // under an unchanged pair only drops work to rebuild it wrong.
                jobs.clear();
                subscribed.extranonce1 = extranonce1;
                if let Some(size) = extranonce2_size {
                    subscribed.extranonce2_size = size;
                }
                log.log(format!(
                    "the pool set the extranonce1 to {}, extranonce2_size {}{}; every job in \
                     flight is dropped",
                    subscribed
                        .extranonce1
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    subscribed.extranonce2_size,
                    if extranonce2_size.is_none() {
                        " (unchanged)"
                    } else {
                        ""
                    },
                ));
            }

            Incoming::SetVersionMask(mask) => {
                // `Off` stays off and `Force` keeps its forced bit: only what
                // the pool agreed to moves, and the policy is applied to it
                // afresh before the next search. A share already in flight
                // under the old mask may be rejected, and is counted rather
                // than retried.
                *negotiated = conn::clamp_mask(mask);
                log.log(format!(
                    "the pool set the version mask to {mask:08x}: {}",
                    rolling_note(rolling, Some(mask), *negotiated)
                ));
            }

            Incoming::Reconnect(params) => {
                // **The frame's host and port are never followed.** V1 has no
                // authentication, so following one is the "a pool is a
                // stranger's server" rule broken by the stranger. The SV2
                // client follows a redirect only because the authority key
                // still has to verify at the other end; there is no V1
                // equivalent, so this stays put.
                log.log(format!(
                    "the pool sent client.reconnect {}; this session ends, and the next one \
                     is to the pool this run was given rather than to anything the frame names",
                    Value::Array(params)
                ));
                return Ok(Drained::Reconnect);
            }

            // Never forwarded: the reader thread owns the ledger and answers
            // every reply itself.
            Incoming::Reply { id, .. } => log.log(format!(
                "a reply to id {id:?} reached the grinder, which the reader should have kept"
            )),

            Incoming::Ping(_) | Incoming::GetVersion(_) => {
                log.log("a request reached the grinder, which the reader should have answered")
            }

            Incoming::Unknown(method) => log.log(format!(
                "ignored {method}, which this client does not implement"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::pool::{Authority, Protocol},
        *,
    };

    fn pool(rolling: VersionRolling) -> Pool {
        Pool {
            address: "192.0.2.1:3333".into(),
            user: "bc1qa0wd8gy8vtgj3vs2e5emzv7lnmfdf9e8nfq8ug.puntominer".into(),
            pass: "d=1".into(),
            difficulty: 1.0,
            agent: "puntominer/0.1".into(),
            reconnect: Duration::from_secs(5),
            version_rolling: rolling,
            // The V1 client never reads these three, and a test that set
            // them to anything but the defaults would be asserting something
            // about the other protocol's loop.
            protocol: Protocol::V1,
            authority: Authority::Unset,
            hashrate: 0.0,
            capture: String::new(),
        }
    }

    #[test]
    fn force_is_refused_against_any_pool_that_is_not_on_this_machine() {
        // The gate, checked before a socket is opened and beside the one that
        // keeps `rejections` and `reorg` on regtest. A run that discovered this
        // after connecting would already have authorized as somebody's worker.
        let log = Logger::open("/dev/null").expect("the null logger opens");
        let why = run(
            &pool(VersionRolling::Force),
            None,
            None,
            Extranonce::ZERO,
            &Signals::unwatched(),
            &log,
        )
        .expect_err("force against a public pool is refused");

        assert!(why.contains("loopback"), "{why}");
        assert!(why.contains("192.0.2.1"), "the message names it: {why}");
    }

    #[test]
    fn a_pool_client_with_nowhere_to_point_says_so() {
        // There is no default pool, and `MINER_POOL` empty is what keeps this
        // binary from opening a socket to anyone without being told to.
        let log = Logger::open("/dev/null").expect("the null logger opens");
        let mut nowhere = pool(VersionRolling::Auto);
        nowhere.address = String::new();

        let why = run(
            &nowhere,
            None,
            None,
            Extranonce::ZERO,
            &Signals::unwatched(),
            &log,
        )
        .expect_err("a pool client needs a pool");
        assert!(why.contains("MINER_POOL"), "{why}");
    }
}

/// Whole V1 sessions against a pool on the loopback.
///
/// The handshake has its own scripted pool in `conn.rs`; these run the *loop*
/// — a real CPU share search, submits reaching a server, and frames the pool
/// sends mid-session — because the mask, the ping and the reconnect only mean
/// anything once a session is under way.
#[cfg(test)]
mod session_tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread::JoinHandle,
    };

    use super::{
        super::{
            pool::{Authority, Protocol},
            wire,
        },
        *,
    };
    use crate::cpu::Hasher;

    /// The agent the client announces, which `client.get_version` answers with.
    const AGENT: &str = "PuntoMiner/test";

    /// A pool on the loopback that answers each frame from `script`, across as
    /// many connections as the client makes, until `stop` is raised.
    ///
    /// The script is handed the connection's index and the frame. The handle
    /// yields every frame the client sent, one list per connection.
    fn scripted_pool(
        stop: Arc<AtomicBool>,
        mut script: impl FnMut(usize, &Value) -> Vec<String> + Send + 'static,
    ) -> (String, JoinHandle<Vec<Vec<Value>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the loopback should be bindable");
        let address = listener.local_addr().expect("a bound port").to_string();
        listener
            .set_nonblocking(true)
            .expect("a nonblocking listener");

        let handle = thread::spawn(move || {
            let mut sessions = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                let Ok((stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream.set_nonblocking(false).expect("a blocking stream");
                let mut writer = stream.try_clone().expect("the socket should clone");
                let mut reader = BufReader::new(stream);
                let index = sessions.len();
                let mut sent = Vec::new();
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let Ok(frame) = serde_json::from_str::<Value>(line.trim()) else {
                        break;
                    };
                    for answer in script(index, &frame) {
                        let _ = writeln!(writer, "{answer}");
                    }
                    sent.push(frame);
                }
                sessions.push(sent);
            }
            sessions
        });
        (address, handle)
    }

    /// The handshake answers, with the given frames sent after `authorize`'s
    /// reply. `None` for anything the handshake does not send.
    fn handshake(frame: &Value, after_authorize: &[String]) -> Option<Vec<String>> {
        let id = &frame["id"];
        Some(match frame["method"].as_str()? {
            "mining.configure" => vec![format!(
                r#"{{"id":{id},"result":{{"version-rolling":true,"version-rolling.mask":"1fffe000"}},"error":null}}"#
            )],
            "mining.subscribe" => vec![format!(
                r#"{{"id":{id},"result":[[["mining.notify","10086bd1"]],"10086bd1",8],"error":null}}"#
            )],
            "mining.suggest_difficulty" => vec![],
            "mining.authorize" => {
                let mut answers = vec![format!(r#"{{"id":{id},"result":true,"error":null}}"#)];
                answers.extend_from_slice(after_authorize);
                answers
            }
            _ => return None,
        })
    }

    /// A job on version `20000000` at an empty merkle branch.
    fn notify(job: &str) -> String {
        format!(
            r#"{{"id":null,"method":"mining.notify","params":["{job}","98ccd6c190d927b95a692b4a65b6d5137f93c9c2000228520000000000000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff","ffffffff0100f2052a01000000160014329649f03db93aef2cf873e9b8544a446d38316d00000000",[],"20000000","1702355e","6aac80b6",true]}}"#
        )
    }

    /// About one share every 4,300 hashes, so a session pays in milliseconds.
    const EASY: &str = r#"{"id":null,"method":"mining.set_difficulty","params":[0.000001]}"#;

    /// Mine against `address` on one worker until `stop` is raised, or for
    /// thirty seconds at most so that a regression fails rather than hangs.
    /// Returns what the run logged.
    fn mine(address: String, stop: &Arc<AtomicBool>, reconnect: Duration) -> String {
        let watchdog = Arc::clone(stop);
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(30));
            watchdog.store(true, Ordering::SeqCst);
        });

        let pool = Pool {
            address,
            user: "bcrt1qexample.puntominer".into(),
            pass: "d=1".into(),
            difficulty: 1.0,
            agent: AGENT.into(),
            reconnect,
            version_rolling: VersionRolling::Auto,
            protocol: Protocol::V1,
            authority: Authority::Unset,
            hashrate: 0.0,
            capture: String::new(),
        };
        // Numbered, because the tests run in parallel and would otherwise
        // share, and delete, one file.
        static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "puntominer-v1-session-{}-{}.log",
            std::process::id(),
            RUNS.fetch_add(1, Ordering::SeqCst)
        ));
        let log = Logger::open(&path).expect("the session log opens");
        run(
            &pool,
            Some(Cpu {
                workers: 1,
                hasher: Hasher::detect(),
                load_percent: 100,
            }),
            None,
            Extranonce::ZERO,
            &Signals::new(Arc::clone(stop)),
            &log,
        )
        .expect("the run ends on the stop flag");

        drop(log);
        let text = std::fs::read_to_string(&path).expect("the session log reads back");
        let _ = std::fs::remove_file(&path);
        text
    }

    /// The submits a session sent for one job.
    fn submits<'a>(sent: &'a [Value], job: &str) -> Vec<&'a [Value]> {
        sent.iter()
            .filter(|frame| frame["method"] == "mining.submit" && frame["params"][1] == job)
            .map(|frame| frame["params"].as_array().expect("params").as_slice())
            .collect()
    }

    #[test]
    fn a_new_version_mask_governs_every_submit_after_it() {
        // Job `a` rolls under the handshake's 1fffe000. After four shares the
        // pool narrows the mask to two bits and sends job `b`, and after six
        // more it switches rolling off with a mask of zero and sends job `c`.
        // The mask travels ahead of the job on the same socket, so every
        // submit naming `b` or `c` was found after the client took it.
        let stop = Arc::new(AtomicBool::new(false));
        let mut counts = std::collections::HashMap::<String, usize>::new();
        let (address, pool) = scripted_pool(Arc::clone(&stop), {
            let stop = Arc::clone(&stop);
            move |_, frame| {
                if let Some(answers) = handshake(frame, &[EASY.to_string(), notify("a")]) {
                    return answers;
                }
                if frame["method"] != "mining.submit" {
                    return vec![];
                }
                let job = frame["params"][1].as_str().unwrap().to_string();
                let seen = counts.entry(job.clone()).or_default();
                *seen += 1;
                let mut answers = vec![format!(
                    r#"{{"id":{},"result":true,"error":null}}"#,
                    frame["id"]
                )];
                match (job.as_str(), *seen) {
                    ("a", 4) => answers.extend([
                        r#"{"id":null,"method":"mining.set_version_mask","params":["00006000"]}"#
                            .to_string(),
                        notify("b"),
                    ]),
                    ("b", 6) => answers.extend([
                        r#"{"id":null,"method":"mining.set_version_mask","params":["00000000"]}"#
                            .to_string(),
                        notify("c"),
                    ]),
                    ("c", 4) => stop.store(true, Ordering::SeqCst),
                    _ => {}
                }
                answers
            }
        });

        mine(address, &stop, Duration::from_secs(5));
        let sessions = pool.join().expect("the pool thread");
        let sent = &sessions[0];

        let under = |job: &str, mask: u32| {
            let found = submits(sent, job);
            assert!(!found.is_empty(), "job {job} was mined");
            for params in &found {
                assert_eq!(params.len(), 6, "a rolled submit: {params:?}");
                let bits = wire::be_u32_from_hex(params[5].as_str().unwrap()).unwrap();
                assert_eq!(
                    bits & !mask,
                    0,
                    "job {job} rolled {bits:08x} outside {mask:08x}"
                );
            }
            found
        };
        under("a", 0x1fff_e000);
        let narrowed = under("b", 0x0000_6000);
        assert!(
            narrowed.iter().any(|params| params[5] != "00000000"),
            "the narrowed mask was rolled, not merely respected: {narrowed:?}"
        );

        // A mask of zero is rolling off, which is five parameters.
        let off = submits(sent, "c");
        assert!(off.len() >= 4, "{off:?}");
        assert!(off.iter().all(|params| params.len() == 5), "{off:?}");
    }

    #[test]
    fn a_new_extranonce1_builds_every_job_after_it_and_is_logged() {
        // The handshake subscribes under 10086bd1 with eight bytes of
        // extranonce2. After three shares on job `a` the pool moves the session
        // to deadbeef with four bytes and sends job `b`, so every submit naming
        // `b` must have been hashed under the new pair — a header rebuilt
        // under the old one meets the share target by chance once in 4,300.
        let stop = Arc::new(AtomicBool::new(false));
        let mut counts = std::collections::HashMap::<String, usize>::new();
        let (address, pool) = scripted_pool(Arc::clone(&stop), {
            let stop = Arc::clone(&stop);
            move |_, frame| {
                if let Some(answers) = handshake(frame, &[EASY.to_string(), notify("a")]) {
                    return answers;
                }
                if frame["method"] != "mining.submit" {
                    return vec![];
                }
                let job = frame["params"][1].as_str().unwrap().to_string();
                let seen = counts.entry(job.clone()).or_default();
                *seen += 1;
                let mut answers = vec![format!(
                    r#"{{"id":{},"result":true,"error":null}}"#,
                    frame["id"]
                )];
                match (job.as_str(), *seen) {
                    ("a", 3) => answers.extend([
                        r#"{"id":null,"method":"mining.set_extranonce","params":["deadbeef",4]}"#
                            .to_string(),
                        notify("b"),
                    ]),
                    ("b", 4) => stop.store(true, Ordering::SeqCst),
                    _ => {}
                }
                answers
            }
        });

        let log = mine(address, &stop, Duration::from_secs(5));
        let sessions = pool.join().expect("the pool thread");
        let sent = &sessions[0];

        let before = submits(sent, "a");
        assert!(!before.is_empty(), "job a was mined");
        assert!(
            before
                .iter()
                .all(|params| params[2].as_str().unwrap().len() == 16),
            "job a carries the handshake's eight bytes: {before:?}"
        );

        let after = submits(sent, "b");
        assert!(after.len() >= 4, "job b was mined: {after:?}");
        let notify_b: Value = serde_json::from_str(&notify("b")).unwrap();
        let job = Job::new(
            super::super::messages::Notify::parse(notify_b["params"].as_array().unwrap()).unwrap(),
            &super::super::messages::Subscribed {
                extranonce1: vec![0xde, 0xad, 0xbe, 0xef],
                extranonce2_size: 4,
            },
            ShareTarget::from_difficulty(0.000001).unwrap(),
        );
        for params in &after {
            let extranonce2 = params[2].as_str().unwrap();
            assert_eq!(
                extranonce2.len(),
                8,
                "four bytes of extranonce2: {params:?}"
            );
            let rolled = params.get(5).map_or(0, |bits| {
                wire::be_u32_from_hex(bits.as_str().unwrap()).unwrap()
            });
            let mut header = job.header(
                Extranonce(u64::from_str_radix(extranonce2, 16).unwrap()),
                job.version() | rolled,
            );
            header.time = wire::be_u32_from_hex(params[3].as_str().unwrap()).unwrap();
            header.nonce = wire::be_u32_from_hex(params[4].as_str().unwrap()).unwrap();
            assert!(
                job.target().is_met_by(header.block_hash()),
                "a share on job b rebuilds under deadbeef: {params:?}"
            );
        }

        assert!(
            log.contains("subscribed: extranonce1 10086bd1, extranonce2_size 8"),
            "{log}"
        );
        assert!(
            log.contains("the pool set the extranonce1 to deadbeef, extranonce2_size 4"),
            "{log}"
        );
    }

    #[test]
    fn a_ping_and_a_version_request_are_answered_and_nothing_else_is() {
        let stop = Arc::new(AtomicBool::new(false));
        let (address, pool) = scripted_pool(Arc::clone(&stop), {
            let stop = Arc::clone(&stop);
            move |_, frame| {
                let after = [
                    EASY.to_string(),
                    notify("a"),
                    r#"{"id":"p1","method":"mining.ping","params":[]}"#.to_string(),
                    r#"{"id":77,"method":"client.get_version","params":[]}"#.to_string(),
                    // A request this client does not implement, which must
                    // stay unanswered: an error reply is a guess about what
                    // the pool does with it.
                    r#"{"id":78,"method":"client.show_message","params":["hi"]}"#.to_string(),
                    // And a ping with no id to answer under.
                    r#"{"id":null,"method":"mining.ping","params":[]}"#.to_string(),
                ];
                if let Some(answers) = handshake(frame, &after) {
                    return answers;
                }
                // Stopped once the client has shown it is mining past them.
                if frame["method"] == "mining.submit" {
                    stop.store(true, Ordering::SeqCst);
                }
                vec![]
            }
        });

        mine(address, &stop, Duration::from_secs(5));
        let sessions = pool.join().expect("the pool thread");

        let replies: Vec<&Value> = sessions[0]
            .iter()
            // Everything this client sent that is not one of its own calls.
            .filter(|frame| {
                !frame["method"]
                    .as_str()
                    .is_some_and(|method| method.starts_with("mining."))
            })
            .collect();
        assert_eq!(
            replies,
            vec![
                &json!({"id": "p1", "method": "pong", "params": []}),
                &json!({"id": 77, "result": AGENT, "error": null}),
            ],
            "exactly two replies, under the pool's own ids"
        );
    }

    #[test]
    fn a_reconnect_returns_to_the_same_pool_at_once_and_never_to_the_one_it_names() {
        // A backoff of a minute, so that a reconnect which waited it out would
        // miss the thirty-second watchdog and fail.
        let stop = Arc::new(AtomicBool::new(false));
        let (address, pool) = scripted_pool(Arc::clone(&stop), {
            let stop = Arc::clone(&stop);
            move |session, frame| {
                let after: Vec<String> = match session {
                    0 => vec![
                        r#"{"id":null,"method":"client.reconnect","params":["pool.example",4444,0]}"#
                            .to_string(),
                    ],
                    _ => {
                        if frame["method"] == "mining.authorize" {
                            stop.store(true, Ordering::SeqCst);
                        }
                        vec![]
                    }
                };
                handshake(frame, &after).unwrap_or_default()
            }
        });

        let started = Instant::now();
        mine(address, &stop, Duration::from_secs(60));
        let sessions = pool.join().expect("the pool thread");

        assert_eq!(
            sessions.len(),
            2,
            "one session, and a second on the same address"
        );
        assert!(
            sessions[1]
                .iter()
                .any(|frame| frame["method"] == "mining.authorize"),
            "the second session handshook"
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "no backoff was waited: {:?}",
            started.elapsed()
        );
    }
}
