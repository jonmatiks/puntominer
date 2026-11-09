//! `MINER_POOL_PROTOCOL=v2`: connect, open a channel, take work, submit
//! shares.
//!
//! The same shape as [`run`](super::super::run)'s — a thread owns the socket
//! and pushes what arrives at the thread doing the work — and the same three
//! properties: no node is contacted, nothing is ever submitted to a chain,
//! and the payout is not this miner's to choose.
//!
//! Three things genuinely differ, and each has a section below:
//!
//! 1. **The share ledger is not V1's.** A `SubmitShares.Success` acknowledges
//!    a *batch* and carries the pool's own counts, so there is no reply per
//!    share to match an id against.
//! 2. **What wakes the search is narrower**, because two of the four messages
//!    that look like they should wake it are specified not to change the job
//!    in flight at all.
//! 3. **A redirect is followed, and the certificate is still checked against
//!    the key this run was configured with** — never one the redirect
//!    supplies, because it supplies none.

use std::{
    collections::BTreeMap,
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

use super::{
    super::{
        conn::resolves_to_loopback,
        job::ShareTarget,
        payout::{self, Payout},
        pool::{Authority, Pool, VersionRolling},
        search::{Hit, ShareJob, is_block, search_shares},
    },
    conn::{self, Conn, Writer},
    job::{ChannelState, Jobs, Took},
    messages::{self, Incoming, OpenedChannel, flags},
};

/// The extranonce width this client asks for, which is [`Extranonce`]'s own.
///
/// A pool granting more is normal and the high bytes stay zero; a pool
/// granting fewer is refused at channel open rather than silently truncated,
/// because a narrower counter repeats and two searches would then walk the
/// same headers.
const MIN_EXTRANONCE_SIZE: u16 = 8;

/// The one `request_id` this client ever uses. It opens one channel.
const CHANNEL_REQUEST_ID: u32 = 1;

/// How long a quiet pool is tolerated before the socket is called dead.
const IDLE_MAX: Duration = Duration::from_secs(600);

/// How often the reader thread looks up from the socket to check the stop flag.
const READ_POLL: Duration = Duration::from_millis(500);

/// What a session did, for the line printed when it ends.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    submitted: u64,
    /// Submitted shares that also met the network target. What this client
    /// found, not what the chain kept — see [`is_block`].
    blocks: u64,
    accepted: u64,
    rejected: u64,
    /// The pool's own `new_shares_sum`, accumulated across batches.
    ///
    /// **Reported beside this client's arithmetic rather than reconciled with
    /// it.** They are two different claims about the same shares and printing
    /// both is more useful than asserting either.
    shares_sum: u64,
    hashes: u64,
    seconds: f64,
    best: f64,
}

/// Mine for an SV2 pool until the user stops.
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
            "MINER_MODE=stratum needs MINER_POOL set to a pool's host:port or to a \
             stratum2+tcp:// URL; there is no default pool"
                .into(),
        );
    }

    let loopback = resolves_to_loopback(&pool.address)?;
    authority_gate(pool, loopback)?;

    if pool.version_rolling == VersionRolling::Force && !loopback {
        return Err(format!(
            "MINER_VERSION_ROLLING=force deliberately rolls version bits the pool did not \
             agree to, so it is refused against {}, which is not on the loopback. It exists \
             to test that a pool rejects those shares, and that is a thing to do to your own \
             pool",
            pool.address
        ));
    }

    // `MINER_POOL_PASS` has no SV2 counterpart, and `runner::run` says so
    // before calling this, where the spelling the run used is known.

    log.log(format!(
        "miner started on {} over stratum v2 with the {} device",
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

    // **"or harder", and the difference is not pedantry.** §5.3.4's
    // `max_target` is a ceiling on the *target*, so `MINER_POOL_DIFFICULTY`
    // is a floor under the *difficulty* and cannot ask a pool to come down —
    // the exact opposite of what the same number means under V1, where `d=`
    // and `mining.suggest_difficulty` are both requests to come down. A pool
    // that answers difficulty 512 to a client asking for 1 has honoured the
    // request. The only lever that lowers a V2 difficulty is the hash rate
    // the pool sizes the target from, which is why it is said here too.
    log.log(format!(
        "mining as {}, accepting share difficulty {} or harder and {}{}",
        pool.user,
        pool.difficulty,
        if pool.hashrate == 0.0 {
            "claiming no hash rate, so the pool's own default decides it".to_string()
        } else {
            format!(
                "claiming {}H/s for the pool to size it from",
                format_scaled(f64::from(pool.hashrate), false),
            )
        },
        match pool.authority {
            Authority::Pinned(key) => format!(", pinned to authority key {key}"),
            Authority::Skipped => ", with certificate verification skipped by request \
                                   (MINER_POOL_AUTHORITY=skip)"
                .to_string(),
            Authority::Unset =>
                ", with no authority key pinned, which is allowed on the loopback only".to_string(),
        },
    ));

    if !pool.capture.is_empty() {
        log.log(format!(
            "recording every frame after the handshake to {}, in plaintext",
            pool.capture
        ));
    }

    let mut total = Tally::default();
    let mut sessions = 0u64;
    // Moved by a `Reconnect`, and never to a pool whose certificate does not
    // verify under the key above — see `session`.
    let mut address = pool.address.clone();

    while !signals.stopped() {
        sessions += 1;
        match session(
            pool,
            &address,
            cpu,
            gpu.as_mut(),
            start,
            signals,
            log,
            total.best,
        ) {
            Ok((tally, redirect)) => {
                total.submitted += tally.submitted;
                total.blocks += tally.blocks;
                total.accepted += tally.accepted;
                total.rejected += tally.rejected;
                total.shares_sum += tally.shares_sum;
                total.hashes += tally.hashes;
                total.seconds += tally.seconds;
                total.best = total.best.max(tally.best);

                if let Some(to) = redirect {
                    log.log(format!(
                        "the pool asked this client to reconnect to {to}; the certificate \
                         there must still verify under the same authority key"
                    ));
                    address = to;
                    continue;
                }
            }
            Err(why) => {
                // A failed session is not a failed run, with two exceptions
                // that will fail identically forever: a refused channel and a
                // certificate that is refused for any reason — a signature,
                // but also a window, which Pool B proved by serving
                // one a week out of date. Retrying either every five seconds
                // until somebody notices is worse than stopping.
                if why.contains("refused to open")
                    || why.contains("pinned")
                    || why.contains("the pool's certificate")
                {
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
             because a new channel means a new extranonce prefix",
            pool.reconnect.as_secs()
        ));
        let until = Instant::now() + pool.reconnect;
        while Instant::now() < until && !signals.stopped() {
            thread::sleep(Duration::from_millis(100));
        }
    }

    log.log(format!(
        "{} sessions: {} shares submitted, {} of them blocks, {} accepted, {} rejected, \
         {} credited by the pool, {} hashes over {}{}",
        sessions,
        total.submitted,
        total.blocks,
        total.accepted,
        total.rejected,
        format_scaled(total.shares_sum as f64, false),
        format_scaled(total.hashes as f64, false),
        format_duration(total.seconds),
        best_note(total.best),
    ));
    Ok(())
}

/// **The gate that makes the certificate check worth having**, checked before
/// a socket is opened and beside the two that are already here for the same
/// reason.
///
/// A pool publishes an authority key precisely so that miners pin it, and a
/// client that connects without one has thrown the whole authentication story
/// away for one line of convenience. There is deliberately no
/// trust-on-first-use path: nothing is remembered between runs. What this
/// protects against is someone who chose SV2 believing they were
/// authenticated when they were not, so only [`Authority::Unset`] is refused;
/// `skip` is the one explicit opt-out, and it is never a default.
fn authority_gate(pool: &Pool, loopback: bool) -> Result<(), String> {
    if pool.authority != Authority::Unset || loopback {
        return Ok(());
    }
    Err(format!(
        "MINER_POOL_PROTOCOL=v2 against {} needs MINER_POOL_AUTHORITY set to the pool's \
         authority key, and there is no trust-on-first-use: without it a certificate \
         cannot be checked against anything and the session is encrypted to whoever \
         answered. The key is public — pools publish their own — and the easiest \
         way to give it is the URL the pool prints, \
         stratum2+tcp://host:port/<key>. Unpinned is allowed on the loopback only, \
         unless MINER_POOL_AUTHORITY=skip asks to connect without verifying the \
         certificate at all",
        pool.address
    ))
}

/// The share ledger.
///
/// **This is where a quiet miscount would live, so three rules are written
/// down rather than implied.**
///
/// V1 matches a JSON-RPC id to a share and gets one verdict per submit. SV2
/// does not: §5.3.13 says a `SubmitShares.Success` "can be provided for
/// multiple `SubmitShare` messages aggregated together", carrying the last
/// sequence number it covers and how many it accepted. A `SubmitShares.Error`
/// names one sequence number and arrives immediately.
#[derive(Debug, Default)]
struct Shares {
    /// The next `sequence_number` to send. Per channel, and monotonic.
    next_sequence: u32,
    /// Sequence number to what the share was worth, so a verdict can say
    /// *which* shares rather than only how many. Pruned at
    /// `last_sequence_number`.
    pending: BTreeMap<u32, Submitted>,
    submitted: u64,
    blocks: u64,
    /// **From `new_submits_accepted_count`, never from counting the map.**
    /// The pool's number is the authoritative one; the map exists for the log
    /// line and for pruning.
    accepted: u64,
    rejected: u64,
    /// The pool's own `new_shares_sum`, accumulated across batches.
    ///
    /// **The batch counters reset per batch**, per §5.3.13's closing note, so
    /// what accumulates is this running total and never the pool's fields.
    shares_sum: u64,
    best: f64,
}

/// One share, as it went out.
#[derive(Clone, Debug)]
struct Submitted {
    job: u32,
    nonce: u32,
    version: u32,
    difficulty: f64,
}

/// One connection, from handshake to whatever ends it.
///
/// Returns the tally and, if the pool asked for one, where to reconnect.
#[allow(clippy::too_many_arguments)]
fn session(
    pool: &Pool,
    address: &str,
    cpu: Option<Cpu>,
    gpu: Option<&mut GpuMiner>,
    start: Extranonce,
    signals: &Signals,
    log: &Logger,
    best: f64,
) -> Result<(Tally, Option<String>), String> {
    // **The authority key is this run's, on every reconnect.** §3.3 designs
    // `Reconnect` to carry no pool public key for exactly this reason: a
    // compromised pool server must not be able to redirect hashrate
    // somewhere its certificate would not verify. Unset is the loopback
    // case, refused against anything else before a socket is opened.
    let authority = pool.authority;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "this machine's clock is before 1970, and a certificate is time-checked")?
        .as_secs() as u32;

    // Opened per session and appended to, so a reconnect continues the file
    // under a `#` line of its own rather than starting it again.
    let capture = match pool.capture.as_str() {
        "" => None,
        path => Some(conn::Capture::open(path)?),
    };

    let (mut conn, writer) = conn::connect(address, authority.key(), now, capture)?;
    // Said exactly as it is, on every connect. Claiming a verified
    // certificate on a session that did not check one would be the single
    // most misleading line this client could print — and naming the setting
    // when it was skipped is what shows it was chosen rather than forgotten.
    log.log(format!(
        "connected to {} and the Noise handshake completed; {}",
        conn.peer(),
        match authority {
            Authority::Pinned(_) =>
                "the pool's certificate verifies under the pinned authority key",
            Authority::Skipped =>
                "the pool's certificate is in date and UNVERIFIED — verification was skipped \
                 by request, MINER_POOL_AUTHORITY=skip",
            Authority::Unset =>
                "the pool's certificate is in date and UNVERIFIED — no authority key was \
                 pinned, which is why this is refused off the loopback",
        }
    ));

    let asked = ShareTarget::from_difficulty(pool.difficulty)?;
    let (channel, rolling_allowed, pushed) = open_channel(&mut conn, &writer, pool, asked, log)?;

    // Requested as 8 and refused below that, because a narrower counter
    // repeats and the hybrid split would then have both halves walking the
    // same headers.
    if channel.extranonce_size < usize::from(MIN_EXTRANONCE_SIZE) {
        return Err(format!(
            "the pool granted {} extranonce bytes and this client asked for at least \
             {MIN_EXTRANONCE_SIZE}; fewer would make the extranonce walk repeat",
            channel.extranonce_size
        ));
    }

    let granted = ShareTarget::from_u256(channel.target);
    log.log(format!(
        "channel {} open: {}, extranonce_size {}, prefix {}",
        channel.channel_id,
        granted,
        channel.extranonce_size,
        channel
            .extranonce_prefix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    ));

    conn.set_read_timeout(READ_POLL)?;

    let shares = Mutex::new(Shares {
        best,
        ..Shares::default()
    });
    let (sender, incoming) = mpsc::channel();
    let session_signals = signals.branch();

    let jobs = Jobs::new(
        ChannelState {
            channel_id: channel.channel_id,
            extranonce_prefix: channel.extranonce_prefix.clone(),
            extranonce_size: channel.extranonce_size,
        },
        granted,
    );

    let outcome = thread::scope(|scope| {
        let reader = scope.spawn({
            let shares = &shares;
            let signals = &session_signals;
            move || read_frames(conn, sender, pushed, shares, signals, log)
        });

        let outcome = grind(
            pool,
            asked,
            cpu,
            gpu,
            start,
            rolling_allowed,
            authority,
            &session_signals,
            log,
            &writer,
            &incoming,
            jobs,
            &shares,
        );

        session_signals.stop_branch();
        drop(incoming);
        let _ = reader.join();
        outcome
    });

    let (mut tally, redirect) = outcome?;
    let shares = shares.into_inner().expect("share ledger poisoned");
    tally.submitted = shares.submitted;
    tally.blocks = shares.blocks;
    tally.accepted = shares.accepted;
    tally.rejected = shares.rejected;
    tally.shares_sum = shares.shares_sum;
    tally.best = shares.best;
    Ok((tally, redirect))
}

/// `SetupConnection` then `OpenExtendedMiningChannel`, read synchronously.
///
/// Returns the channel, whether the *server* will accept a rolled version at
/// all, and any frames the pool pushed while this was going on. That last one
/// is V1's lesson repeated: Pool A pushes work before it has finished
/// answering, and a handshake that swallowed those frames would start its
/// first search against the second job.
fn open_channel(
    conn: &mut Conn,
    writer: &Writer,
    pool: &Pool,
    asked: ShareTarget,
    log: &Logger,
) -> Result<(OpenedChannel, bool, Vec<Incoming>), String> {
    let (host, port) = pool
        .address
        .rsplit_once(':')
        .ok_or_else(|| format!("the pool address {} has no port", pool.address))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("the pool address {} has no port", pool.address))?;

    writer.send(&messages::setup_connection(host, port, &pool.agent)?)?;

    let mut pushed = Vec::new();
    let rolling_allowed = loop {
        match conn.read()? {
            Incoming::SetupConnectionSuccess {
                used_version,
                flags,
            } => {
                // §5.3.1: the server says here whether it will take a changed
                // version field at all. A job's `version_rolling_allowed` is
                // the finer control and both have to agree.
                let rolling_allowed = flags & flags::server::REQUIRES_FIXED_VERSION == 0;
                log.log(format!(
                    "stratum v2 version {used_version}, server flags {flags:#010x}{}",
                    if rolling_allowed {
                        ""
                    } else {
                        " (REQUIRES_FIXED_VERSION, so nothing rolls)"
                    }
                ));
                break rolling_allowed;
            }
            Incoming::SetupConnectionError { flags, error_code } => {
                return Err(format!(
                    "the pool refused to open the connection: {error_code} \
                     (the flags it cannot support are {flags:#010x})"
                ));
            }
            other => pushed.push(other),
        }
    };

    writer.send(&messages::open_extended_mining_channel(
        CHANNEL_REQUEST_ID,
        &pool.user,
        pool.hashrate,
        &asked.to_u256(),
        MIN_EXTRANONCE_SIZE,
    )?)?;

    loop {
        match conn.read()? {
            Incoming::OpenExtendedChannelSuccess(channel) => {
                return Ok((channel, rolling_allowed, pushed));
            }
            Incoming::OpenMiningChannelError {
                request_id,
                error_code,
            } => {
                // **The one fatal reply.** A typo'd worker name is the
                // likeliest cause and no pool says which field it disliked,
                // so the name goes in the message — the alternative is a run
                // that reconnects every five seconds forever.
                return Err(format!(
                    "the pool refused to open a channel for {} (request {request_id}): \
                     {error_code} (is the payout address right, is it an address this pool \
                     accepts, and is MINER_POOL_DIFFICULTY a target it will grant?)",
                    pool.user
                ));
            }
            other => pushed.push(other),
        }
    }
}

/// The reader thread: own the socket, answer for every submit, and wake the
/// grinder whenever the work changes.
fn read_frames(
    mut conn: Conn,
    sender: mpsc::Sender<Result<Incoming, String>>,
    pushed: Vec<Incoming>,
    shares: &Mutex<Shares>,
    signals: &Signals,
    log: &Logger,
) {
    for frame in pushed {
        if !handle(frame, &sender, shares, signals, log) {
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
                if !handle(frame, &sender, shares, signals, log) {
                    return;
                }
            }

            Err(why) => {
                let _ = sender.send(Err(why));
                signals.mark_stale();
                return;
            }
        }
    }
}

/// Act on one frame from the pool. `false` means the grinder has gone.
fn handle(
    frame: Incoming,
    sender: &mpsc::Sender<Result<Incoming, String>>,
    shares: &Mutex<Shares>,
    signals: &Signals,
    log: &Logger,
) -> bool {
    match &frame {
        Incoming::SubmitSharesSuccess {
            last_sequence_number,
            new_submits_accepted_count,
            new_shares_sum,
            ..
        } => {
            let mut ledger = shares.lock().expect("share ledger poisoned");

            // The pool's count is authoritative. Counting the pruned entries
            // instead would silently disagree with it whenever a share was
            // acknowledged that this client had already forgotten.
            ledger.accepted += u64::from(*new_submits_accepted_count);
            ledger.shares_sum += *new_shares_sum;

            // Everything up to and including the acknowledged sequence number
            // has had its verdict, one way or the other.
            let covered: Vec<u32> = ledger
                .pending
                .range(..=*last_sequence_number)
                .map(|(sequence, _)| *sequence)
                .collect();
            for sequence in &covered {
                ledger.pending.remove(sequence);
            }

            log.log(format!(
                "shares accepted: {new_submits_accepted_count} through sequence \
                 {last_sequence_number}, worth {} to the pool ({} accepted, {} rejected, \
                 {} unanswered)",
                format_scaled(*new_shares_sum as f64, false),
                ledger.accepted,
                ledger.rejected,
                ledger.pending.len(),
            ));
            return true;
        }

        Incoming::SubmitSharesError {
            sequence_number,
            error_code,
            ..
        } => {
            let mut ledger = shares.lock().expect("share ledger poisoned");
            ledger.rejected += 1;
            let share = ledger.pending.remove(sequence_number);
            let accepted = ledger.accepted;
            let rejected = ledger.rejected;
            drop(ledger);

            match share {
                Some(share) => log.log(format!(
                    "share REJECTED: sequence {sequence_number} job {} nonce {:08x} \
                     version {:08x} difficulty {}: {error_code} ({accepted} accepted, \
                     {rejected} rejected)",
                    share.job,
                    share.nonce,
                    share.version,
                    format_scaled(share.difficulty, false),
                )),
                // Expected rather than alarming: a batch acknowledgement may
                // already have pruned it, and §5.3.14 allows a delayed error.
                None => log.log(format!(
                    "share REJECTED: sequence {sequence_number}, which this client had \
                     already accounted for: {error_code} ({accepted} accepted, \
                     {rejected} rejected)"
                )),
            }
            return true;
        }

        _ => {}
    }

    // **What wakes the search, and what does not.**
    //
    // A `SetNewPrevHash` always activates a job, and a
    // `NewExtendedMiningJob` with `min_ntime` set is immediately minable —
    // both mean there is new current work and the search in progress is on a
    // block the pool has moved past.
    //
    // A *future* job does not wake it: it is queued, which is the entire
    // point of future jobs, and waking on one would throw away a search for
    // work that is not yet minable.
    //
    // Neither does a `SetTarget` or a `SetExtranoncePrefix`, and that is the
    // surprising one. §5.3.21 and §5.3.10 both say they apply to jobs not yet
    // received or not yet activated — so neither changes anything about the
    // job being ground, and restarting the search would abandon valid work to
    // arrive at exactly the same header. **This is a reading of the spec,
    // worth confirming against any new pool**, because if a pool means either
    // of them
    // immediately then every share until the next job is a reject, and that
    // is precisely the kind of rule the V1 build had to overturn by
    // measurement.
    let wake = match &frame {
        Incoming::SetNewPrevHash(_) => true,
        Incoming::NewExtendedMiningJob(job) => job.min_ntime.is_some(),
        _ => false,
    };

    if sender.send(Ok(frame)).is_err() {
        return false;
    }
    if wake {
        signals.mark_stale();
    }
    true
}

/// The grinding loop: take the current job, search it, submit what it finds.
#[allow(clippy::too_many_arguments)]
fn grind(
    pool: &Pool,
    asked: ShareTarget,
    cpu: Option<Cpu>,
    mut gpu: Option<&mut GpuMiner>,
    start: Extranonce,
    rolling_allowed: bool,
    authority: Authority,
    signals: &Signals,
    log: &Logger,
    writer: &Writer,
    incoming: &Receiver<Result<Incoming, String>>,
    mut jobs: Jobs,
    shares: &Mutex<Shares>,
) -> Result<(Tally, Option<String>), String> {
    let mut tally = Tally::default();
    let mut last_job: Option<Instant> = None;
    let mut told_the_pool = false;
    let mut payout = Payout::new(&pool.user);

    loop {
        if signals.stopped() {
            return Ok((tally, None));
        }

        // Cleared before the channel is drained, never after — `watch.rs`'s
        // generation counter in its simplest form, and the same reasoning as
        // V1's: a job that landed between a drain and a later clear would
        // have its flag wiped, and the search would then grind work the pool
        // had replaced for as long as the pool stayed quiet.
        signals.freshen();

        match drain(incoming, &mut jobs, &mut last_job, authority, log)? {
            Drained::Closed(why) => return Err(why),
            Drained::Redirect(to) => return Ok((tally, Some(to))),
            Drained::Open => {}
        }

        let Some(job) = jobs.current().cloned() else {
            // Before the first activated job. A pool sends one within a
            // second of the channel opening, so this is a wait rather than a
            // state.
            thread::sleep(Duration::from_millis(50));
            continue;
        };

        // The extended channel is what makes this possible: a standard channel
        // would hand over a merkle root and no coinbase at all.
        for line in payout.check(&job.coinbase(payout::DECODED_AT)) {
            log.log(line);
        }

        // Per job, by an explicit boolean rather than by the BIP310
        // reconstruction argument V1 has to make — see `Job::rollable`. The
        // session-wide flag is the server's veto and the job's is the finer
        // control; both have to say yes.
        let rolling = pool
            .version_rolling
            .mask(rolling_allowed.then(|| job.rollable()).flatten());

        let mut submitted = 0u64;
        let search = {
            let asked = job.target().difficulty();
            let mut report = |hit: Hit| -> Result<(), String> {
                let mut header = job.header(hit.extranonce2, hit.version);
                header.nonce = hit.nonce;
                let hash = header.block_hash();
                let difficulty = difficulty_of_hash(&hash);
                let block = is_block(&header);

                // The sequence number is taken and recorded *before* the
                // frame goes out, so the reader thread cannot acknowledge a
                // share this one has not finished writing down.
                let mut ledger = shares.lock().expect("share ledger poisoned");
                let sequence = ledger.next_sequence;
                ledger.next_sequence = ledger.next_sequence.wrapping_add(1);
                ledger.pending.insert(
                    sequence,
                    Submitted {
                        job: job.id(),
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

                writer.send(&job.submit(sequence, hit.extranonce2, &header)?)?;

                // **Logged at submit time rather than at verdict time**,
                // because there may be no individual verdict: a batch
                // acknowledgement names a sequence range and not a share.
                log.log(format!(
                    "share: sequence {sequence} job {} nonce {:08x} version {:08x} \
                     difficulty {}",
                    job.id(),
                    hit.nonce,
                    hit.version,
                    format_scaled(difficulty, false),
                ));

                // **Said apart from the share line**, because on mainnet it is
                // the one a solo miner waits months for. The pool's verdict
                // below is on the share: neither it nor anything else in the
                // protocol says whether the block was accepted.
                if block {
                    log.log(format!(
                        "BLOCK FOUND! sequence {sequence} job {} hash {hash} meets the network \
                         difficulty {}; the chain, not the pool's verdict, says whether it \
                         was kept",
                        job.id(),
                        format_scaled(difficulty_of(header.bits), false),
                    ));
                }

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

        // **One `UpdateChannel`, once, and only when the channel was opened
        // with no claim to update.** `MINER_POOL_HASHRATE` defaults to zero,
        // which is honest for a client that has not measured itself — and
        // after one search it has. A pool that uses `nominal_hash_rate` to
        // pick a target can then pick a better one. Sending it repeatedly
        // would be a vardiff negotiation nobody asked for.
        //
        // **`maximum_target` is `asked` and never `jobs.target()`**, which it
        // was until a live pool showed what that costs. §5.3.7 makes the
        // field a *ceiling on the target*, so a smaller one is a demand for
        // harder work that the server "must reflect"; echoing back the target
        // the pool is currently serving therefore does not restate the
        // request, it replaces it with the pool's own floor and forbids the
        // pool from ever going easier for the rest of the session. Against
        // Pool A that turned a hash-rate report into a difficulty-512
        // ratchet. The ceiling this client wants never changes, so the
        // channel's own value is the only correct thing to send.
        if !told_the_pool && pool.hashrate == 0.0 && tally.seconds > 0.0 && tally.hashes > 0 {
            let measured = (tally.hashes as f64 / tally.seconds) as f32;
            writer.send(&messages::update_channel(
                job.channel_id(),
                measured,
                &asked.to_u256(),
            )?)?;
            log.log(format!(
                "told the pool this client measures {}H/s, which it opened the channel \
                 claiming nothing about",
                format_scaled(f64::from(measured), false),
            ));
            told_the_pool = true;
        }

        if search.ending == Ending::Signalled {
            return Ok((tally, None));
        }
    }
}

/// The best-difficulty tail a progress line ends with, empty until a share
/// has been found.
fn best_note(best: f64) -> String {
    if best <= 0.0 {
        return String::new();
    }
    format!(", difficulty {}", format_scaled(best, false))
}

/// Whether the connection is still there after a drain, and where to go next.
enum Drained {
    Open,
    Closed(String),
    Redirect(String),
}

/// Take everything the reader thread has pushed and act on it.
fn drain(
    incoming: &Receiver<Result<Incoming, String>>,
    jobs: &mut Jobs,
    last_job: &mut Option<Instant>,
    authority: Authority,
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
            Incoming::NewExtendedMiningJob(job) => {
                let id = job.job_id;
                let future = job.min_ntime.is_none();
                let interval = last_job
                    .replace(Instant::now())
                    .map(|at| {
                        format!(
                            ", {} after the last",
                            format_duration(at.elapsed().as_secs_f64())
                        )
                    })
                    .unwrap_or_default();

                match jobs.accept(job) {
                    Ok(Took::Queued) => log.log(format!(
                        "future job {id} queued, {} waiting for a prevhash{interval}",
                        jobs.queued()
                    )),
                    Ok(Took::Activated) => {
                        log.log(format!("job {id} is active immediately{interval}"))
                    }
                    // A pool error rather than a socket error, so the session
                    // carries on: the job is dropped and the next one may be
                    // fine.
                    Err(why) => log.log(format!("ignored job {id}: {why}")),
                }
                debug_assert!(future || jobs.current().is_some_and(|job| job.id() == id));
            }

            Incoming::SetNewPrevHash(prev) => {
                // **The latency number SV2 exists for**, and it is reported
                // separately from the job interval above on purpose: the two
                // are what future jobs are for separating, and a pool that
                // never pre-distributes looks identical on the totals.
                match jobs.set_prev_hash(prev) {
                    Ok(_) => log.log(format!(
                        "prevhash {} activates job {}, at {}",
                        prev.prev_hash, prev.job_id, prev.min_ntime
                    )),
                    Err(why) => log.log(format!("ignored a SetNewPrevHash: {why}")),
                }
            }

            Incoming::SetTarget { maximum_target, .. } => {
                let target = ShareTarget::from_u256(maximum_target);
                jobs.set_target(target);
                // Spelled out as seconds per share, for the reason V1's is:
                // a floor of 512 at this hardware's rate is one share every
                // 49 minutes, which from the outside is a hung socket.
                let hashes = target.difficulty() * 4_294_967_296.0;
                log.log(format!(
                    "share {target} from here on, {} hashes per share; \
                     the job in flight keeps the target it was activated under",
                    format_scaled(hashes, false),
                ));
            }

            Incoming::SetExtranoncePrefix {
                extranonce_prefix, ..
            } => {
                let hex: String = extranonce_prefix
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                jobs.set_extranonce_prefix(extranonce_prefix);
                log.log(format!(
                    "extranonce prefix {hex} from here on; jobs already in hand keep theirs"
                ));
            }

            Incoming::Reconnect { new_host, new_port } => {
                // **Refused outright when no authority key is pinned**,
                // skipped or not. Unpinned happens on the loopback or by
                // request for the one pool this run was given, and a redirect
                // would take the run to a host nobody named, whose
                // certificate this run has nothing to check.
                match authority {
                    Authority::Pinned(_) => {}
                    Authority::Skipped => {
                        return Err(format!(
                            "the pool sent a Reconnect to {new_host}:{new_port}, and with \
                             MINER_POOL_AUTHORITY=skip no key is pinned. Following it would \
                             move this run to a host nobody named, with nothing to verify there"
                        ));
                    }
                    Authority::Unset => {
                        return Err(format!(
                            "the pool sent a Reconnect to {new_host}:{new_port} and no authority \
                             key is pinned. Unpinned is allowed on the loopback only, and \
                             following this would leave it"
                        ));
                    }
                }
                return Ok(Drained::Redirect(redirect_to(&new_host, new_port)?));
            }

            Incoming::UpdateChannelError {
                channel_id,
                error_code,
            } => log.log(format!(
                "the pool refused this client's hash rate claim on channel {channel_id}: \
                 {error_code}"
            )),

            // Answered by the reader thread, which owns the ledger.
            Incoming::SubmitSharesSuccess { .. } | Incoming::SubmitSharesError { .. } => {
                log.log("a share verdict reached the grinder, which the reader should have kept")
            }

            Incoming::SetupConnectionSuccess { .. }
            | Incoming::SetupConnectionError { .. }
            | Incoming::OpenExtendedChannelSuccess(_)
            | Incoming::OpenMiningChannelError { .. } => {
                log.log("the pool repeated a setup message mid-session, which was ignored")
            }

            Incoming::Unknown {
                extension_type,
                msg_type,
            } => log.log(format!(
                "ignored extension {extension_type:#06x} message {msg_type:#04x}, \
                 which this client does not implement"
            )),
        }
    }
}

/// Where a `Reconnect` points, given that either field may be empty.
///
/// §3.6.5: an empty `new_host` means the present host and a `new_port` of 0
/// the present port. Both empty is the pool asking for the handshake to be
/// run again against itself, which is a legitimate thing to be told.
///
/// The caller keeps the present address, so this only has to refuse the one
/// case it cannot express.
fn redirect_to(new_host: &str, new_port: u16) -> Result<String, String> {
    if new_host.is_empty() && new_port == 0 {
        return Err(
            "the pool sent a Reconnect naming neither a host nor a port, which is a \
             request to reconnect to itself"
                .into(),
        );
    }
    if new_host.is_empty() || new_port == 0 {
        return Err(format!(
            "the pool sent a Reconnect to host {new_host:?} port {new_port}, and this \
             client does not carry either half of the present address forward — name both"
        ));
    }
    Ok(format!("{new_host}:{new_port}"))
}

#[cfg(test)]
mod tests {
    use super::{
        super::super::pool::{Protocol, VersionRolling},
        *,
    };

    fn pool() -> Pool {
        Pool {
            address: "192.0.2.1:3333".into(),
            user: "bc1qa0wd8gy8vtgj3vs2e5emzv7lnmfdf9e8nfq8ug.puntominer".into(),
            pass: String::new(),
            difficulty: 1.0,
            agent: "PuntoMiner/0.1".into(),
            reconnect: Duration::from_secs(5),
            version_rolling: VersionRolling::Auto,
            protocol: Protocol::V2,
            authority: Authority::Unset,
            hashrate: 0.0,
            capture: String::new(),
        }
    }

    fn logger() -> Logger {
        Logger::open("/dev/null").expect("the null logger opens")
    }

    #[test]
    fn an_unpinned_authority_key_is_refused_against_anything_but_the_loopback() {
        // **The gate this whole protocol's security rests on**, checked
        // before a socket is opened and beside the two that were already
        // here. A client that connected without a key to check against would
        // have an encrypted session with whoever answered.
        let why = run(
            &pool(),
            None,
            None,
            Extranonce::ZERO,
            &Signals::unwatched(),
            &logger(),
        )
        .expect_err("v2 against a public pool needs a pinned key");

        assert!(why.contains("MINER_POOL_AUTHORITY"), "{why}");
        assert!(why.contains("trust-on-first-use"), "{why}");
        assert!(why.contains("192.0.2.1"), "it names the pool: {why}");
        assert!(
            why.contains("MINER_POOL_AUTHORITY=skip"),
            "and the way out: {why}"
        );
    }

    #[test]
    fn skip_passes_the_gate_off_the_loopback_and_unset_and_empty_do_not() {
        // The gate on its own, so that "off the loopback" needs no socket to a
        // stranger to test. An empty MINER_POOL_AUTHORITY parses to Unset.
        let mut skipped = pool();
        skipped.authority = Authority::Skipped;
        assert_eq!(authority_gate(&skipped, false), Ok(()));

        let empty = Authority::parse("").expect("empty is a value");
        for authority in [Authority::Unset, empty] {
            let mut unset = pool();
            unset.authority = authority;
            let why = authority_gate(&unset, false).expect_err("unset is refused");
            assert!(why.contains("skip"), "{why}");
            assert_eq!(
                authority_gate(&unset, true),
                Ok(()),
                "and allowed on the loopback"
            );
        }
    }

    #[test]
    fn a_redirect_is_refused_when_verification_was_skipped() {
        // `skip` covers the one pool this run was given, and nothing a
        // redirect names.
        use super::super::job::ChannelState;

        let mut jobs = Jobs::new(
            ChannelState {
                channel_id: 1,
                extranonce_prefix: Vec::new(),
                extranonce_size: 8,
            },
            ShareTarget::from_difficulty(1.0).unwrap(),
        );
        let (sender, receiver) = mpsc::channel();
        sender
            .send(Ok(Incoming::Reconnect {
                new_host: "pool.example".into(),
                new_port: 3350,
            }))
            .unwrap();

        let Err(why) = drain(
            &receiver,
            &mut jobs,
            &mut None,
            Authority::Skipped,
            &logger(),
        ) else {
            panic!("a redirect under skip is refused");
        };
        assert!(why.contains("pool.example:3350"), "{why}");
        assert!(why.contains("MINER_POOL_AUTHORITY=skip"), "{why}");
        // Worded so that the run ends on it, as it does for the unset case.
        assert!(why.contains("pinned"), "{why}");
    }

    #[test]
    fn a_pool_client_with_nowhere_to_point_says_so() {
        // There is no default pool under either protocol, and `MINER_POOL`
        // empty is what keeps this binary from opening a socket to anyone
        // without being told to.
        let mut nowhere = pool();
        nowhere.address = String::new();

        let why = run(
            &nowhere,
            None,
            None,
            Extranonce::ZERO,
            &Signals::unwatched(),
            &logger(),
        )
        .expect_err("a pool client needs a pool");
        assert!(why.contains("MINER_POOL"), "{why}");
    }

    #[test]
    fn force_is_refused_off_the_loopback_under_v2_as_it_is_under_v1() {
        let mut forced = pool();
        // Pinned, so that the authority gate is not what refuses this.
        forced.authority = Authority::Pinned(
            super::super::noise::authority_key(
                "24b1551ef29e71a667310c33e8b46f9745628d3b9bdeecf86f2a18b9f20c5635",
            )
            .expect("the test key"),
        );
        forced.version_rolling = VersionRolling::Force;

        let why = run(
            &forced,
            None,
            None,
            Extranonce::ZERO,
            &Signals::unwatched(),
            &logger(),
        )
        .expect_err("force against a public pool is refused");
        assert!(why.contains("loopback"), "{why}");
    }

    #[test]
    fn a_reconnect_must_name_both_halves_of_where_it_is_going() {
        assert_eq!(
            redirect_to("pool.example", 3350).unwrap(),
            "pool.example:3350"
        );

        for (host, port) in [("", 0u16), ("", 3350), ("pool.example", 0)] {
            assert!(
                redirect_to(host, port).is_err(),
                "{host:?}:{port} does not name a destination this client can reach"
            );
        }
    }

    #[test]
    fn the_batch_acknowledgement_counts_what_the_pool_says_and_prunes_what_it_covers() {
        // §5.3.13, and the three rules the ledger's doc comment states. The
        // pool acknowledges four submits in one message; this client had five
        // outstanding.
        let shares = Mutex::new(Shares::default());
        {
            let mut ledger = shares.lock().unwrap();
            for sequence in 0..5u32 {
                ledger.pending.insert(
                    sequence,
                    Submitted {
                        job: 1,
                        nonce: sequence,
                        version: 0x2000_0000,
                        difficulty: 1.0,
                    },
                );
            }
            ledger.submitted = 5;
        }

        let (sender, _receiver) = mpsc::channel();
        let signals = Signals::unwatched();
        handle(
            Incoming::SubmitSharesSuccess {
                channel_id: 1,
                last_sequence_number: 3,
                new_submits_accepted_count: 4,
                new_shares_sum: 4096,
            },
            &sender,
            &shares,
            &signals,
            &logger(),
        );

        let ledger = shares.lock().unwrap();
        assert_eq!(ledger.accepted, 4, "the pool's count, not the map's length");
        assert_eq!(ledger.shares_sum, 4096);
        assert_eq!(
            ledger.pending.len(),
            1,
            "sequences 0 through 3 are answered; 4 is not"
        );
        assert!(ledger.pending.contains_key(&4));
        assert_eq!(ledger.rejected, 0);
    }

    #[test]
    fn a_second_batch_does_not_accumulate_the_pools_own_per_batch_counters() {
        // The bug the third rule exists to prevent: `new_submits_accepted_count`
        // and `new_shares_sum` "MUST be reset when a new batch starts being
        // processed", so what accumulates is this client's running total and
        // never the pool's field.
        let shares = Mutex::new(Shares::default());
        let (sender, _receiver) = mpsc::channel();
        let signals = Signals::unwatched();

        for last in [3u32, 7] {
            handle(
                Incoming::SubmitSharesSuccess {
                    channel_id: 1,
                    last_sequence_number: last,
                    new_submits_accepted_count: 4,
                    new_shares_sum: 4096,
                },
                &sender,
                &shares,
                &signals,
                &logger(),
            );
        }

        let ledger = shares.lock().unwrap();
        assert_eq!(ledger.accepted, 8, "four and four");
        assert_eq!(ledger.shares_sum, 8192);
    }

    #[test]
    fn a_reject_names_the_share_it_is_about_and_survives_one_it_cannot_find() {
        let shares = Mutex::new(Shares::default());
        shares.lock().unwrap().pending.insert(
            9,
            Submitted {
                job: 3,
                nonce: 0x0122_0aa8,
                version: 0x2000_0004,
                difficulty: 4510.0,
            },
        );

        let (sender, _receiver) = mpsc::channel();
        let signals = Signals::unwatched();
        for sequence in [9u32, 99] {
            handle(
                Incoming::SubmitSharesError {
                    channel_id: 1,
                    sequence_number: sequence,
                    error_code: "difficulty-too-low".into(),
                },
                &sender,
                &shares,
                &signals,
                &logger(),
            );
        }

        let ledger = shares.lock().unwrap();
        assert_eq!(ledger.rejected, 2, "both count, found or not");
        assert!(ledger.pending.is_empty());
    }

    #[test]
    fn only_work_that_can_be_mined_now_wakes_the_search() {
        // A future job is queued and must not end a search in progress; an
        // activated one and a prevhash must. A `SetTarget` and a
        // `SetExtranoncePrefix` change nothing about the job in flight, so
        // neither wakes it — see `handle`'s comment, and `scripted.rs`.
        use super::super::messages::{ExtendedJob, NewPrevHash};
        use bitcoin::{BlockHash, CompactTarget, hashes::Hash};

        let job = |min_ntime| ExtendedJob {
            channel_id: 1,
            job_id: 1,
            min_ntime,
            version: 0x2000_0000,
            version_rolling_allowed: true,
            merkle_path: Vec::new(),
            coinbase_tx_prefix: Vec::new(),
            coinbase_tx_suffix: Vec::new(),
        };

        let cases = [
            (Incoming::NewExtendedMiningJob(job(None)), false),
            (Incoming::NewExtendedMiningJob(job(Some(1))), true),
            (
                Incoming::SetNewPrevHash(NewPrevHash {
                    channel_id: 1,
                    job_id: 1,
                    prev_hash: BlockHash::from_byte_array([0u8; 32]),
                    min_ntime: 1,
                    bits: CompactTarget::from_consensus(0x207f_ffff),
                }),
                true,
            ),
            (
                Incoming::SetTarget {
                    channel_id: 1,
                    maximum_target: [0xff; 32],
                },
                false,
            ),
            (
                Incoming::SetExtranoncePrefix {
                    channel_id: 1,
                    extranonce_prefix: vec![1, 2],
                },
                false,
            ),
        ];

        for (frame, expected) in cases {
            let signals = Signals::unwatched();
            let (sender, receiver) = mpsc::channel();
            let shares = Mutex::new(Shares::default());
            assert!(handle(frame, &sender, &shares, &signals, &logger()));
            assert_eq!(
                signals.interrupted() == Some(Ending::Stale),
                expected,
                "waking on {:?}",
                receiver.try_recv().map(|frame| format!("{frame:?}")),
            );
        }
    }
}

/// One whole session against a pool on the loopback.
///
/// **What this is and what it is not.** It is the first test that runs the
/// *loop* — the setup exchange, the job/prevhash split, a real CPU share
/// search, a `SubmitSharesExtended` reaching a server, and the batched
/// acknowledgement coming back — end to end over a real socket with a real
/// Noise tunnel, whose keys come from an independent implementation.
///
/// It is **not** a test against an independent pool. The fake pool below
/// builds its frames with this repository's own `messages.rs`, so the two ends
/// agree about whatever that file has wrong: it is a self-correlated check of
/// the encoding and an uncorrelated check of nothing but the handshake. The
/// scripted pool in `scripted.rs`, whose frames come from SRI's encoder, and
/// the live captures in `tests/fixtures/` are what catch a misunderstanding
/// shared by both ends of this test.
#[cfg(test)]
mod session_tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
    };

    use bitcoin::{
        hashes::Hash,
        secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    };

    use super::{
        super::{
            super::pool::{Protocol, VersionRolling},
            frame::{CHANNEL_MSG, ENCRYPTED_HEADER_LEN, Header, MAC_LEN, MAX_PT_CHUNK, msg},
            messages::{ExtendedJob, NewPrevHash, Outgoing},
        },
        *,
    };
    use crate::cpu::Hasher;

    /// A share target of about one share every 4,300 hashes, so the search
    /// pays within a fraction of a second and the test is not a benchmark.
    const EASY: f64 = 1e-6;
    /// The ceiling the client asks for, deliberately easier than [`EASY`],
    /// which is what the pool grants. Under V2 a `max_target` easier than
    /// the served target is a no-op request rather than a conflict — and
    /// keeping the two distinct is the only way a test can see which of them
    /// an `UpdateChannel` carries.
    const ASKED: f64 = 1e-9;

    /// A pool that speaks just enough of the protocol to run one session.
    struct FakePool {
        stream: TcpStream,
        engine: noise_sv2::NoiseEngine,
    }

    impl FakePool {
        fn send(&mut self, frame: &Outgoing) {
            let mut sealed = frame.header.to_bytes().to_vec();
            self.engine.encrypt(&mut sealed).expect("the header");
            self.stream.write_all(&sealed).expect("it goes out");
            for chunk in frame.payload.chunks(MAX_PT_CHUNK) {
                let mut sealed = chunk.to_vec();
                self.engine.encrypt(&mut sealed).expect("a chunk");
                self.stream.write_all(&sealed).expect("it goes out");
            }
            self.stream.flush().expect("flushed");
        }

        fn recv(&mut self) -> (Header, Vec<u8>) {
            let mut sealed = vec![0u8; ENCRYPTED_HEADER_LEN];
            self.stream.read_exact(&mut sealed).expect("a header");
            self.engine.decrypt(&mut sealed).expect("it decrypts");
            let header = Header::parse(sealed.as_slice().try_into().unwrap()).expect("a header");

            let mut payload = Vec::new();
            let mut remaining = header.length as usize;
            while remaining > 0 {
                let plain = remaining.min(MAX_PT_CHUNK);
                let mut sealed = vec![0u8; plain + MAC_LEN];
                self.stream.read_exact(&mut sealed).expect("a chunk");
                self.engine.decrypt(&mut sealed).expect("it decrypts");
                payload.extend_from_slice(&sealed);
                remaining -= plain;
            }
            (header, payload)
        }

        /// A frame built from a body, with the header this client expects.
        fn frame(msg_type: u8, payload: Vec<u8>) -> Outgoing {
            Outgoing {
                header: Header::new(CHANNEL_MSG, msg_type, payload.len() as u32),
                payload,
            }
        }
    }

    #[test]
    fn a_whole_session_runs_against_a_pool_on_the_loopback() {
        // Regtest bits, which every share at `EASY` also meets: each one is
        // a block, and the log has to say so.
        let log = one_session(Authority::Pinned, 0x207f_ffff);
        let shares = log.matches(" share: sequence ").count();
        assert!(shares > 0, "{log}");
        assert_eq!(
            log.matches(" BLOCK FOUND! sequence ").count(),
            shares,
            "{log}"
        );
        assert!(
            log.contains(" BLOCK FOUND! sequence 0 job 11 hash "),
            "{log}"
        );
        let (submitted, blocks) = summary(&log);
        assert!(submitted >= shares as u64, "{log}");
        assert_eq!(blocks, submitted, "every share was a block: {log}");
    }

    /// The same session with nothing pinned, which is the shape a local pool
    /// on the loopback runs in.
    ///
    /// No local SV2 pool harness ships with this repository, so this is the
    /// only exercise the unpinned path gets: the handshake completes, the
    /// certificate is parsed and its window checked, no signature is verified,
    /// and the session runs.
    /// The gate that keeps this on the loopback is tested separately.
    #[test]
    fn the_same_session_runs_unpinned_on_the_loopback() {
        // Difficulty-1 bits, a million times harder than `EASY`: a share
        // here is only a share, and a block line would be a false one.
        let log = one_session(|_| Authority::Unset, 0x1d00_ffff);
        assert!(!log.contains("BLOCK FOUND!"), "{log}");
        let (submitted, blocks) = summary(&log);
        assert!(submitted > 0, "{log}");
        assert_eq!(blocks, 0, "{log}");
    }

    /// `skip` runs the same unverified path, and says on connecting that it
    /// was asked for rather than forgotten.
    #[test]
    fn a_skipped_session_says_it_was_skipped_by_request() {
        let log = one_session(|_| Authority::Skipped, 0x1d00_ffff);
        assert!(
            log.contains(
                "UNVERIFIED — verification was skipped by request, MINER_POOL_AUTHORITY=skip"
            ),
            "{log}"
        );
        let (submitted, _) = summary(&log);
        assert!(submitted > 0, "{log}");
    }

    /// A whole session's capture reads back, frame by frame, through
    /// `messages.rs`.
    ///
    /// The format's own round trip, and nothing more: this pool's frames come
    /// from this repository's codec, so it says the capture holds what the
    /// client decrypted and nothing about whether the parser is right. That
    /// is what a capture from a pool nobody here wrote is for.
    #[test]
    fn a_capture_of_a_session_reads_back_through_messages_rs() {
        let path = std::env::temp_dir().join(format!(
            "puntominer-session-capture-{}.hex",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let log = one_session_capturing(Authority::Pinned, 0x1d00_ffff, path.to_str().unwrap());
        assert!(
            log.contains("recording every frame after the handshake to"),
            "{log}"
        );

        let text = std::fs::read_to_string(&path).expect("the capture reads back");
        let _ = std::fs::remove_file(&path);
        let frames = crate::stratum::fixture::parse_sv2(&text);
        assert!(frames.iter().all(|frame| frame.session == 0), "{text}");

        let names = |send: bool| -> Vec<String> {
            frames
                .iter()
                .filter(|frame| frame.send == send)
                .map(|frame| super::super::frame::name(frame.header))
                .collect()
        };

        let received = names(false);
        assert_eq!(
            received[..4],
            [
                "SetupConnection.Success",
                "OpenExtendedMiningChannel.Success",
                "NewExtendedMiningJob",
                "SetNewPrevHash",
            ],
            "{text}"
        );
        assert!(
            received[4..]
                .iter()
                .all(|name| name == "SubmitShares.Success")
                && received.len() >= 6,
            "two batch acknowledgements and nothing else: {text}"
        );
        for frame in frames.iter().filter(|frame| !frame.send) {
            let parsed = Incoming::parse(frame.header, &frame.payload).expect("a captured frame");
            assert!(!matches!(parsed, Incoming::Unknown { .. }), "{parsed:?}");
        }

        let sent = names(true);
        assert_eq!(
            sent[..3],
            [
                "SetupConnection",
                "OpenExtendedMiningChannel",
                "SubmitSharesExtended"
            ],
            "{text}"
        );
        assert!(sent.iter().any(|name| name == "UpdateChannel"), "{text}");
    }

    /// The shares submitted and the blocks among them, from the run's last line.
    fn summary(log: &str) -> (u64, u64) {
        let line = log
            .lines()
            .find(|line| line.contains(" shares submitted, "))
            .expect("the run's summary line");
        let number = |before: &str| -> u64 {
            let head = &line[..line.find(before).expect("the field")];
            head.rsplit(' ').next().unwrap().parse().expect("a count")
        };
        (number(" shares submitted"), number(" of them blocks"))
    }

    /// An expired certificate is refused identically on every connect, so the
    /// run ends on the first one. Pool B's SV2 port served one a week
    /// stale, correctly signed, and this client reconnected every five
    /// seconds for as long as it was left running.
    #[test]
    fn an_expired_certificate_ends_the_run_rather_than_reconnecting() {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[21u8; 32]).unwrap();
        let pinned = Keypair::from_secret_key(&secp, &secret)
            .x_only_public_key()
            .0;

        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("its address").to_string();
        let stop = Arc::new(AtomicBool::new(false));

        // One handshake whose certificate was issued, and expired, in 1970.
        // A second connection is the bug, and it stops the run so that the
        // test fails below rather than hanging the suite.
        let server = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("the client connects");
                let mut responder = noise_sv2::Responder::from_authority_kp(
                    &pinned.serialize(),
                    &secret.secret_bytes(),
                    Duration::from_secs(3600),
                )
                .expect("the responder takes its keypair");
                let mut first = [0u8; 64];
                stream.read_exact(&mut first).expect("the ephemeral key");
                let (second, _) = responder
                    .step_1_with_now_rng(first, 1_000, &mut rand_08::thread_rng())
                    .expect("the handshake");
                stream.write_all(&second).expect("the answer");

                // Ten reconnect intervals for a second attempt.
                listener
                    .set_nonblocking(true)
                    .expect("a nonblocking listener");
                let until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < until {
                    if listener.accept().is_ok() {
                        stop.store(true, Ordering::SeqCst);
                        return false;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                true
            })
        };

        let pool = Pool {
            address,
            user: "bcrt1qexample.puntominer".into(),
            pass: String::new(),
            difficulty: ASKED,
            agent: "PuntoMiner/0.1".into(),
            reconnect: Duration::from_millis(50),
            version_rolling: VersionRolling::Auto,
            protocol: Protocol::V2,
            authority: Authority::Pinned(pinned),
            hashrate: 0.0,
            capture: String::new(),
        };

        let log = Logger::open("/dev/null").expect("the null logger opens");
        let signals = Signals::new(Arc::clone(&stop));
        let why = run(
            &pool,
            Some(Cpu {
                workers: 1,
                hasher: Hasher::Naive,
                load_percent: 100,
            }),
            None,
            Extranonce::ZERO,
            &signals,
            &log,
        )
        .expect_err("an expired certificate ends the run");
        assert!(why.contains("expired"), "{why}");
        assert!(
            server.join().expect("the pool thread"),
            "the client connected a second time"
        );
    }

    /// Run one session under the given network `bits` and return its log.
    ///
    /// `configured` is handed the pool's key and says what the client is
    /// configured with.
    fn one_session(configured: impl FnOnce(XOnlyPublicKey) -> Authority, bits: u32) -> String {
        one_session_capturing(configured, bits, "")
    }

    /// The same, writing a `MINER_POOL_CAPTURE` to `capture` unless it is
    /// empty.
    fn one_session_capturing(
        configured: impl FnOnce(XOnlyPublicKey) -> Authority,
        bits: u32,
        capture: &str,
    ) -> String {
        use super::super::codec::{Prefix, Writer as Body};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[21u8; 32]).unwrap();
        let authority = Keypair::from_secret_key(&secp, &secret);
        let pinned = authority.x_only_public_key().0;

        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("its address").to_string();

        // How many shares the pool has taken, so the client can be stopped
        // once the thing under test has demonstrably happened rather than
        // after a fixed sleep.
        let accepted = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let server = {
            let accepted = Arc::clone(&accepted);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("the client connects");
                let mut responder = noise_sv2::Responder::from_authority_kp(
                    &pinned.serialize(),
                    &secret.secret_bytes(),
                    Duration::from_secs(3600),
                )
                .expect("the responder takes its keypair");

                let mut first = [0u8; 64];
                stream.read_exact(&mut first).expect("the ephemeral key");
                let (second, engine) = responder.step_1(first).expect("the handshake");
                stream.write_all(&second).expect("the answer");
                let mut pool = FakePool { stream, engine };

                // 1. SetupConnection -> .Success
                let (header, _) = pool.recv();
                assert_eq!(header.msg_type, msg::SETUP_CONNECTION);
                let mut body = Body::new();
                body.u16(2).u32(0);
                pool.send(&FakePool::frame(
                    msg::SETUP_CONNECTION_SUCCESS,
                    body.finish(),
                ));

                // 2. OpenExtendedMiningChannel -> .Success, granting an easy
                //    target and exactly the eight extranonce bytes asked for.
                let (header, _) = pool.recv();
                assert_eq!(header.msg_type, msg::OPEN_EXTENDED_MINING_CHANNEL);
                let granted = ShareTarget::from_difficulty(EASY).unwrap().to_u256();
                let mut body = Body::new();
                body.u32(1).u32(7).u256(&granted).u16(8);
                body.bytes(Prefix::Bytes32, &[0xaa, 0xbb]).unwrap();
                body.u32(0);
                pool.send(&FakePool::frame(
                    msg::OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                    body.finish(),
                ));

                // 3. A *future* job, which must not be mined yet.
                let job = ExtendedJob {
                    channel_id: 7,
                    job_id: 11,
                    min_ntime: None,
                    version: 0x2000_0000,
                    version_rolling_allowed: false,
                    merkle_path: vec![[0x33u8; 32]],
                    coinbase_tx_prefix: vec![0x01, 0x02, 0x03],
                    coinbase_tx_suffix: vec![0x04],
                };
                pool.send(&FakePool::frame(
                    msg::NEW_EXTENDED_MINING_JOB,
                    encode_job(&job),
                ));

                // 4. The prevhash that activates it.
                pool.send(&FakePool::frame(
                    msg::SET_NEW_PREV_HASH,
                    encode_prev_hash(&NewPrevHash {
                        channel_id: 7,
                        job_id: 11,
                        prev_hash: bitcoin::BlockHash::from_byte_array([0x77u8; 32]),
                        min_ntime: 1_700_000_000,
                        bits: bitcoin::CompactTarget::from_consensus(bits),
                    }),
                ));

                // 5. Take shares and acknowledge them in batches of three,
                //    which is the shape V1 has no equivalent for.
                let mut last;
                let mut in_batch = 0u32;
                loop {
                    let (header, payload) = pool.recv();
                    if header.msg_type != msg::SUBMIT_SHARES_EXTENDED {
                        continue;
                    }
                    let mut reader = super::super::codec::Reader::new(&payload);
                    assert_eq!(reader.u32().unwrap(), 7, "the channel it was opened on");
                    last = reader.u32().unwrap();
                    assert_eq!(reader.u32().unwrap(), 11, "the job it was sent for");
                    let _nonce = reader.u32().unwrap();
                    assert_eq!(reader.u32().unwrap(), 1_700_000_000, "min_ntime, unrolled");
                    assert_eq!(
                        reader.u32().unwrap(),
                        0x2000_0000,
                        "the full nVersion, and nothing rolled it"
                    );
                    assert_eq!(
                        reader.bytes(Prefix::Bytes32).unwrap().len(),
                        8,
                        "exactly extranonce_size bytes"
                    );
                    reader.finish().expect("nothing left over");

                    in_batch += 1;
                    if in_batch == 3 {
                        let mut body = Body::new();
                        body.u32(7).u32(last).u32(in_batch).u64(300);
                        pool.send(&FakePool::frame(msg::SUBMIT_SHARES_SUCCESS, body.finish()));
                        accepted.fetch_add(u64::from(in_batch), Ordering::SeqCst);
                        in_batch = 0;
                    }

                    if accepted.load(Ordering::SeqCst) >= 6 {
                        stop.store(true, Ordering::SeqCst);
                        break;
                    }
                }

                // 6. The `UpdateChannel` that the end of a job produces, and
                //    the one field of it a live pool proved this client
                //    could get wrong. `maximum_target` is a ceiling, so the
                //    only thing it can ask for is *harder* work: sending
                //    back the target the pool is already serving replaces
                //    the client's own request with the pool's floor and
                //    forbids it from ever going easier. The two differ here
                //    on purpose — the pool granted EASY and the client asked
                //    for ASKED, which is easier still — so the mistake fails
                //    this assertion instead of costing a session its
                //    difficulty.
                loop {
                    let (header, payload) = pool.recv();
                    if header.msg_type != msg::UPDATE_CHANNEL {
                        continue;
                    }
                    let mut reader = super::super::codec::Reader::new(&payload);
                    assert_eq!(reader.u32().unwrap(), 7, "the channel it was opened on");
                    assert!(
                        reader.f32().unwrap() > 0.0,
                        "a rate this client measured, not the nothing it opened with"
                    );
                    assert_eq!(
                        reader.u256().unwrap(),
                        ShareTarget::from_difficulty(ASKED).unwrap().to_u256(),
                        "the ceiling the channel was opened with, not the target being served"
                    );
                    reader.finish().expect("nothing left over");
                    break;
                }
                last
            })
        };

        let pool = Pool {
            address,
            user: "bcrt1qexample.puntominer".into(),
            pass: String::new(),
            difficulty: ASKED,
            agent: "PuntoMiner/0.1".into(),
            reconnect: Duration::from_millis(50),
            version_rolling: VersionRolling::Auto,
            protocol: Protocol::V2,
            authority: configured(pinned),
            hashrate: 0.0,
            capture: capture.to_string(),
        };

        // Numbered, because two sessions under the same bits run in parallel
        // and would otherwise share, and delete, one file.
        static SESSIONS: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "puntominer-session-{}-{bits:08x}-{}.log",
            std::process::id(),
            SESSIONS.fetch_add(1, Ordering::SeqCst)
        ));
        let log = Logger::open(&path).expect("the session log opens");
        let signals = Signals::new(Arc::clone(&stop));
        run(
            &pool,
            Some(Cpu {
                workers: 1,
                hasher: Hasher::Naive,
                load_percent: 100,
            }),
            None,
            Extranonce::ZERO,
            &signals,
            &log,
        )
        .expect("the session runs and the stop flag ends it");

        let last = server.join().expect("the pool thread");
        assert!(
            accepted.load(Ordering::SeqCst) >= 6,
            "the pool acknowledged two batches of three"
        );
        assert!(last >= 5, "sequence numbers count up from zero, got {last}");

        drop(log);
        let text = std::fs::read_to_string(&path).expect("the session log reads back");
        let _ = std::fs::remove_file(&path);
        text
    }

    /// `NewExtendedMiningJob` on the wire, from the pool's side.
    fn encode_job(job: &ExtendedJob) -> Vec<u8> {
        use super::super::codec::{Prefix, Writer as Body};
        let mut body = Body::new();
        body.u32(job.channel_id).u32(job.job_id);
        match job.min_ntime {
            None => {
                body.u8(0);
            }
            Some(ntime) => {
                body.u8(1).u32(ntime);
            }
        }
        body.u32(job.version).bool(job.version_rolling_allowed);
        body.u8(job.merkle_path.len() as u8);
        for entry in &job.merkle_path {
            body.u256(entry);
        }
        body.bytes(Prefix::Bytes64K, &job.coinbase_tx_prefix)
            .unwrap();
        body.bytes(Prefix::Bytes64K, &job.coinbase_tx_suffix)
            .unwrap();
        body.finish()
    }

    /// `SetNewPrevHash` on the wire, from the pool's side.
    fn encode_prev_hash(prev: &NewPrevHash) -> Vec<u8> {
        use super::super::codec::Writer as Body;
        let mut body = Body::new();
        body.u32(prev.channel_id)
            .u32(prev.job_id)
            .u256(&prev.prev_hash.to_byte_array())
            .u32(prev.min_ntime)
            .u32(prev.bits.to_consensus());
        body.finish()
    }
}
