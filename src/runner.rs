//! What drives a run: the environment configuration, the dispatch to a mode,
//! and the mining and benchmark loops themselves.
//!
//! The modes with enough substance to be worth reading on their own live in
//! their own modules — `lottery`, `rejections`, `reorg`, `validate`. What is
//! left here is everything a run needs before one of those is chosen, plus the
//! two loops that had nowhere else to go.
//!
//! The flow keeps one rule throughout: only a verified result is ever
//! reported. Here the node is the final authority, but a candidate block is
//! checked locally first — the height, the commitment, the merkle root and the
//! target — so a rejection arrives with a reason we already understand.

use std::{
    env,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

use bitcoin::{Address, CompactTarget, ScriptBuf, Target, address::NetworkUnchecked, hex::FromHex};
use serde_json::{Value, json};

use crate::{
    constants::{
        MINER_ADDRESS, MINER_BENCH_SECONDS, MINER_BITCOIND_DATADIR, MINER_BITS, MINER_BLOCKS,
        MINER_CHAIN, MINER_CPU_CORES_USAGE_PERCENT, MINER_CPU_LOAD_PERCENT, MINER_DEVICE,
        MINER_EXTRANONCE_START, MINER_GPU_CAPACITY, MINER_GPU_LANES, MINER_GPU_NONCES,
        MINER_GPU_PERCENT, MINER_GPU_PIPELINE, MINER_HASHER, MINER_LOTTERY_BITS, MINER_MODE,
        MINER_POOL, MINER_POOL_AGENT, MINER_POOL_AUTHORITY, MINER_POOL_CAPTURE,
        MINER_POOL_DIFFICULTY, MINER_POOL_HASHRATE, MINER_POOL_PASS, MINER_POOL_PROTOCOL,
        MINER_POOL_RECONNECT_SECONDS, MINER_POOL_USER, MINER_POOL_WORKER, MINER_PREFETCH,
        MINER_TEMPLATE_SECONDS, MINER_TEMPLATE_VERSION_ROLLING, MINER_VERSION_ROLLING,
    },
    logger::Logger,
    utils::{cpu_model, format_duration, format_scaled},
};

use super::{
    block::{self, Extranonce, check_block, difficulty_of, serialize_block},
    cpu::{self, Cpu, Hasher, Part, search},
    gpu::{self, GpuConfig, GpuMiner},
    hybrid, lottery, rejections, reorg,
    rpc::{Chain, Rpc},
    settings::{Origin, Settings},
    stratum::{
        pool::{self, Authority, Pool, Protocol, VersionRolling},
        run::run as run_stratum,
        v2::run::run as run_stratum_v2,
    },
    template::Template,
    validate,
    watch::{Ending, Signals, Watcher},
};

/// Where the nonce search runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Device {
    Cpu,
    Gpu,
    /// Both at once, on disjoint extranonces — see [`super::hybrid`].
    Hybrid,
}

impl Device {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "cpu" => Ok(Self::Cpu),
            "gpu" => Ok(Self::Gpu),
            // `both` and `cpu+gpu` are what somebody reaches for before knowing
            // this one has a name, and they cost a line to accept.
            "hybrid" | "both" | "cpu+gpu" => Ok(Self::Hybrid),
            _ => Err(format!(
                "MINER_DEVICE must be cpu, gpu or hybrid, got {value}"
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Hybrid => "hybrid",
        }
    }

    /// Whether a run on this device needs a GPU engine opened for it.
    fn uses_gpu(self) -> bool {
        matches!(self, Self::Gpu | Self::Hybrid)
    }

    /// Whether the CPU search runs, and therefore whether `MINER_WORKERS` and
    /// `MINER_HASHER` mean anything to this run.
    fn uses_cpu(self) -> bool {
        matches!(self, Self::Cpu | Self::Hybrid)
    }
}

/// What a run does.
///
/// All of these are modes of one binary rather than separate tools, and for
/// one reason: they share the template fetch, the block builder and the
/// verification. A benchmark or an experiment that reimplemented those would be
/// measuring — or proving — something other than what a production run does.
///
/// What separates them is what they do with a hash that wins, and whether
/// anything reaches the chain. Only [`Mode::Mine`], [`Mode::Rejections`] and
/// [`Mode::Reorg`] write to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Produce blocks: grind the chain's own target and submit what wins.
    ///
    /// The only mode that writes to the chain it is pointed at, and therefore
    /// the only one where a wrong block costs anything — which is why a winner
    /// goes through `rust-bitcoin` and then `check_block` before `submitblock`
    /// sees it, and why the tip is read back afterwards.
    Mine,
    /// Measure the search rate against a target no header can meet.
    ///
    /// `Target::ZERO` is the only thing swapped out, so what is timed is the
    /// production search — template, coinbase, merkle root and extranonce roll
    /// included — rather than a microbenchmark of `sha256d`. Nothing is ever
    /// submitted, because nothing can win; the run ends on its timer or the
    /// user's signal.
    Benchmark,
    /// Verify the GPU shader against `rust-bitcoin`. Submits nothing and
    /// needs no node beyond the template fetch.
    Probe,
    /// Follow the node's work without doing any: fetch a template, hold a
    /// longpoll open, and report every change. Needs no wallet and submits
    /// nothing, which makes it the only way to watch the stale path on a chain
    /// whose difficulty this hardware cannot touch.
    Watch,
    /// Break a block ten different ways and collect what the node says to
    /// each. Writes to the chain — the valid control is accepted — so it is
    /// refused anywhere but regtest.
    Rejections,
    /// Mine two blocks at one height, then extend the one that lost and watch
    /// the chain reorganise. Regtest only, for the same reason.
    Reorg,
    /// Validate a real template and the block built from it, everything except
    /// the proof of work, ending with the node's own verdict through
    /// `getblocktemplate` proposal mode. Submits nothing, so it is the one
    /// experiment that belongs on mainnet.
    Validate,
    /// Hash a real template against a reporting threshold and check what comes
    /// back against the theory. Submits nothing either, and its threshold is
    /// deliberately far easier than the chain's — it is measuring the
    /// distribution of digests, not looking for a block.
    Lottery,
    /// Mine for a Stratum V1 pool: take work from it, submit shares to it, and
    /// contact no node at all.
    ///
    /// The one mode whose payout this miner does not choose — the pool builds
    /// the coinbase — and therefore the one where `MINER_ADDRESS` is a name to
    /// be credited rather than a script in a transaction. It writes no blocks,
    /// so it is not restricted to regtest; it opens a socket to a stranger, so
    /// it refuses to start without `MINER_POOL`. See `stratum/`.
    Stratum,
}

impl Mode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "mine" => Ok(Self::Mine),
            "bench" | "benchmark" => Ok(Self::Benchmark),
            "probe" => Ok(Self::Probe),
            "watch" => Ok(Self::Watch),
            "rejections" => Ok(Self::Rejections),
            "reorg" => Ok(Self::Reorg),
            "validate" => Ok(Self::Validate),
            "lottery" => Ok(Self::Lottery),
            "stratum" | "pool" => Ok(Self::Stratum),
            _ => Err(format!(
                "MINER_MODE must be mine, bench, probe, watch, rejections, reorg, \
                 validate, lottery or stratum, got {value}"
            )),
        }
    }

    /// Whether this mode may put blocks on the chain it is pointed at.
    ///
    /// The two experiments that do are only meaningful on a chain whose
    /// history is disposable, and running them anywhere else would be
    /// vandalism rather than research.
    fn writes_blocks(self) -> bool {
        matches!(self, Self::Rejections | Self::Reorg)
    }
}

#[derive(Debug)]
struct Config {
    chain: Chain,
    mode: Mode,
    datadir: String,
    address: String,
    /// Blocks to mine before stopping; zero mines until the user exits.
    blocks: u64,
    /// Duration of a benchmark run, in seconds.
    bench_seconds: u64,
    /// How long a template may be ground before it is refetched; zero waits for
    /// the longpoll and nothing else.
    template_seconds: u64,
    workers: usize,
    hasher: Hasher,
    /// Duty cycle per worker, 1 to 100 — see `MINER_CPU_LOAD_PERCENT`. The CPU
    /// search only; the GPU is not throttled by it.
    cpu_percent: u8,
    device: Device,
    gpu: GpuConfig,
    /// A target to grind to instead of the template's, given as compact bits.
    ///
    /// It may only be *harder* than the node's, and a block that meets it
    /// meets the node's as well — so the block is still valid and still
    /// accepted. What it buys is a search long enough to observe: at regtest
    /// difficulty a block arrives in milliseconds, which leaves no window in
    /// which a template can go stale.
    bits: Option<CompactTarget>,
    /// Where the extranonce walk begins, already resolved — so an `auto` run
    /// derives its start once, before a node is contacted, rather than once per
    /// template.
    extranonce_start: Extranonce,
    /// Whether the template a longpoll answers with is mined or thrown away.
    ///
    /// Off is the older behaviour, kept so the two can be measured against each
    /// other rather than argued about: the run reports what a fetch costs and
    /// how many it skipped, and with this off it skips none.
    prefetch: bool,
    /// Whether a GPU block search may roll the template's version, inside
    /// [`Template::rollable_bits`], two versions at a time. On by default;
    /// off mines the version the node handed out.
    template_version_rolling: bool,
    /// Where to mine for a pool, and as whom. Read for every run and used by
    /// [`Mode::Stratum`] alone; its address is empty unless `MINER_POOL` says
    /// otherwise, so no other mode can reach a pool even by accident.
    pool: Pool,
}

impl Config {
    /// The CPU as a search device. Kept as separate settings here because that
    /// is what they are, and handed over as one because they are one device.
    fn cpu(&self) -> Cpu {
        Cpu {
            workers: self.workers,
            hasher: self.hasher,
            load_percent: self.cpu_percent,
        }
    }

    /// The version bits a block search on `template` rolls: none unless the
    /// setting is on and the GPU searches, since the CPU search is always
    /// single-version.
    fn version_mask(&self, template: &Template) -> u32 {
        if self.template_version_rolling && self.device.uses_gpu() {
            template.rollable_bits()
        } else {
            0
        }
    }

    /// Resolve a run's configuration from the line, the environment and the
    /// compiled-in defaults, in that order.
    ///
    /// Every rule below is the one that was here when this read the
    /// environment alone: what changed is where a value comes from, not what
    /// is done with it. The messages still name the variables, and
    /// [`Settings::relabel`] rewrites them on the way out for a run that used
    /// flags — which is why nothing here has to know how it was configured.
    fn from_settings(settings: &Settings) -> Result<Self, String> {
        let chain = Chain::parse(&settings.get("MINER_CHAIN", MINER_CHAIN.to_string())?)?;
        let mode = Mode::parse(&settings.get("MINER_MODE", MINER_MODE.to_string())?)?;
        let hasher = Hasher::parse(&settings.get("MINER_HASHER", MINER_HASHER.to_string())?)?;
        let device = Device::parse(&settings.get("MINER_DEVICE", MINER_DEVICE.to_string())?)?;

        let bench_seconds = settings.get("MINER_BENCH_SECONDS", MINER_BENCH_SECONDS)?;
        if bench_seconds == 0 {
            return Err("MINER_BENCH_SECONDS must be greater than zero".into());
        }

        // One worker per logical core by default, on `hybrid` as well as alone —
        // `MINER_CPU_CORES_USAGE_PERCENT` is what asks for fewer.
        //
        // Holding a core back for the GPU's host loop is the obvious thing to
        // do here and it buys nothing: in one 15s-a-side sequence 32 workers and
        // 31 were within noise of each other (702.9 against 702.2), while 30 and
        // 28 gave up 19 and 27 MH/s — the GPU gaining about 4 while the CPU lost
        // 20 to 30. The host loop does almost nothing per dispatch — it stages a
        // uniform block and then blocks in the driver for 155 ms — so it is
        // descheduled rather than competing, and the core it would have been
        // given is a core not hashing.
        let cores = thread::available_parallelism().map_or(1, usize::from);
        // Rounded up, so any non-zero percentage of any core count still leaves
        // a worker to search with.
        let default_workers =
            (cores as f64 * f64::from(MINER_CPU_CORES_USAGE_PERCENT) / 100.0).ceil() as usize;
        let workers = settings.get("MINER_WORKERS", default_workers)?;
        if workers == 0 {
            return Err("MINER_WORKERS must be greater than zero".into());
        }

        let cpu_percent = settings.get("MINER_CPU_PERCENT", MINER_CPU_LOAD_PERCENT)?;
        if !(1..=100).contains(&cpu_percent) {
            return Err("MINER_CPU_PERCENT must be between 1 and 100".into());
        }

        let gpu = GpuConfig {
            lanes: settings.get("MINER_GPU_LANES", MINER_GPU_LANES)?,
            nonces_per_lane: settings.get("MINER_GPU_NONCES", MINER_GPU_NONCES)?,
            capacity: settings.get("MINER_GPU_CAPACITY", MINER_GPU_CAPACITY)?,
            pipeline: settings.get("MINER_GPU_PIPELINE", MINER_GPU_PIPELINE)?,
            load_percent: settings.get("MINER_GPU_PERCENT", MINER_GPU_PERCENT)?,
        }
        .validate()?;

        let bits = match settings.get("MINER_BITS", MINER_BITS.to_string())?.trim() {
            "" => None,
            hex => {
                let bytes = <[u8; 4]>::from_hex(hex).map_err(|error| {
                    format!(
                        "MINER_BITS must be four hex bytes such as 1d00ffff, got {hex}: {error}"
                    )
                })?;
                let bits = CompactTarget::from_consensus(u32::from_be_bytes(bytes));

                // `from_compact` reports nothing for a compact form that
                // overflows 256 bits or sets the mantissa's sign bit: it
                // expands both to zero, which no hash can meet, and the miner
                // would grind until it was killed. Caught here rather than
                // discovered as a search that never ends.
                if Target::from_compact(bits) == Target::ZERO {
                    return Err(format!(
                        "MINER_BITS {hex} expands to a zero target, which no header can meet; \
                         its exponent overflows or its mantissa is negative"
                    ));
                }
                Some(bits)
            }
        };

        Ok(Self {
            bits,
            pool: pool_from_env(settings)?,
            extranonce_start: parse_extranonce_start(
                &settings.get("MINER_EXTRANONCE_START", MINER_EXTRANONCE_START.to_string())?,
            )?,
            template_seconds: settings.get("MINER_TEMPLATE_SECONDS", MINER_TEMPLATE_SECONDS)?,
            prefetch: settings.flag("MINER_PREFETCH", MINER_PREFETCH)?,
            template_version_rolling: settings.flag(
                "MINER_TEMPLATE_VERSION_ROLLING",
                MINER_TEMPLATE_VERSION_ROLLING,
            )?,
            chain,
            mode,
            device,
            gpu,
            bench_seconds,
            datadir: settings.get("MINER_BITCOIND_DATADIR", MINER_BITCOIND_DATADIR.to_string())?,
            address: settings.get("MINER_ADDRESS", MINER_ADDRESS.to_string())?,
            blocks: settings.get("MINER_BLOCKS", MINER_BLOCKS)?,
            workers,
            hasher,
            cpu_percent,
        })
    }
}

/// Read the pool settings, for every run and not only a pooled one.
///
/// Read unconditionally so that a typo in `MINER_POOL_DIFFICULTY` is refused
/// at startup rather than on whichever run first asks for `MINER_MODE=stratum`.
/// The address defaults to empty, which is what keeps a miner from opening a
/// socket to anyone without being told to — a network-visible action taken
/// without being asked would be a property of this binary worth avoiding
/// whatever the mode.
///
/// The user falls back to the payout address plus a worker name. A solo pool
/// credits by address and tells workers apart by the suffix, so a default that
/// names the miner is what makes two of them legible on a dashboard.
fn pool_from_env(settings: &Settings) -> Result<Pool, String> {
    let user = settings.get("MINER_POOL_USER", MINER_POOL_USER.to_string())?;
    let user = if user.is_empty() {
        let address = settings.get("MINER_ADDRESS", MINER_ADDRESS.to_string())?;
        match worker_from_env(settings)? {
            Some(worker) => format!("{address}.{worker}"),
            None => address,
        }
    } else {
        user
    };

    let difficulty = settings.get("MINER_POOL_DIFFICULTY", MINER_POOL_DIFFICULTY)?;
    if !difficulty.is_finite() || difficulty <= 0.0 {
        return Err(format!(
            "MINER_POOL_DIFFICULTY must be a positive number, got {difficulty}"
        ));
    }

    // **The address is taken apart before anything else reads it**, because
    // it may carry two of the settings below. See `pool::parse_address` for
    // the four rules, of which the load-bearing one is that a URL disagreeing
    // with an explicitly set variable is refused rather than ordered.
    // **Empty is the default and means "no pool", not "a malformed one".**
    // `MINER_POOL` unset is what keeps this binary from opening a socket to
    // anyone without being told to, and it is read on every run rather than
    // only a pooled one — so an empty value has to survive the parser that
    // would otherwise refuse it for naming no port.
    let address = settings.get("MINER_POOL", MINER_POOL.to_string())?;
    let located = match address.trim() {
        "" => pool::Address {
            host_port: String::new(),
            protocol: None,
            authority: None,
        },
        text => pool::parse_address(text)?,
    };

    let configured =
        Authority::parse(&settings.get("MINER_POOL_AUTHORITY", MINER_POOL_AUTHORITY.to_string())?)?;

    let (protocol, authority) = Pool::locate(
        &located,
        Protocol::parse(&settings.get("MINER_POOL_PROTOCOL", MINER_POOL_PROTOCOL.to_string())?)?,
        settings.origin("MINER_POOL_PROTOCOL") != Origin::Default,
        configured,
        settings.origin("MINER_POOL_AUTHORITY") != Origin::Default,
    )?;

    let hashrate = settings.get("MINER_POOL_HASHRATE", MINER_POOL_HASHRATE)?;
    if !hashrate.is_finite() || hashrate < 0.0 {
        return Err(format!(
            "MINER_POOL_HASHRATE must be zero or a positive number of hashes a second, \
             got {hashrate}"
        ));
    }

    // **V2 only, and refused under V1 rather than ignored.** A V1 session is
    // plaintext JSON and any logging proxy already records it off the
    // wire; a run that asked for a capture and silently got none would be
    // found out only when the file was wanted.
    let capture = settings.get("MINER_POOL_CAPTURE", MINER_POOL_CAPTURE.to_string())?;
    if !capture.is_empty() && protocol == Protocol::V1 {
        return Err(settings.relabel(
            "MINER_POOL_CAPTURE records Stratum V2 frames, and this run speaks v1. A V1 \
             session is plaintext JSON, so any logging proxy in front of the pool records \
             it off the wire"
                .to_string(),
        ));
    }

    Ok(Pool {
        // The host and port the URL named, so that everything downstream sees
        // one spelling of an address rather than two.
        address: located.host_port.clone(),
        user,
        pass: settings.get("MINER_POOL_PASS", MINER_POOL_PASS.to_string())?,
        difficulty,
        agent: settings.get("MINER_POOL_AGENT", MINER_POOL_AGENT.to_string())?,
        reconnect: Duration::from_secs(
            settings.get("MINER_POOL_RECONNECT_SECONDS", MINER_POOL_RECONNECT_SECONDS)?,
        ),
        version_rolling: VersionRolling::parse(
            &settings.get("MINER_VERSION_ROLLING", MINER_VERSION_ROLLING.to_string())?,
        )?,
        protocol,
        authority,
        hashrate: hashrate as f32,
        capture,
    })
}

/// The suffix the default pool user is built with, from the environment and
/// this machine.
fn worker_from_env(settings: &Settings) -> Result<Option<String>, String> {
    let configured = settings.get("MINER_POOL_WORKER", MINER_POOL_WORKER.to_string())?;
    worker_name(&configured, &hostname())
}

/// The worker half of `<address>.<worker>`, or `None` when there is nothing to
/// name this miner by.
///
/// The two sources are held to different standards on purpose. A configured
/// name is refused rather than sanitised, because a dot in it reaches the pool
/// as another field and credits the shares to a worker nobody asked for — a
/// name that arrives altered is worse than a run that does not start. The
/// hostname behind it is the opposite case: nobody chose it for this, so it is
/// filtered to what a pool will take, capped, and dropped entirely if that
/// leaves nothing. Dropped is not a failure either: the address alone is a
/// perfectly good Stratum username, it just stops telling two machines apart.
fn worker_name(configured: &str, hostname: &str) -> Result<Option<String>, String> {
    if !configured.is_empty() {
        if let Some(character) = configured.chars().find(|character| {
            !(character.is_ascii_alphanumeric() || *character == '-' || *character == '_')
        }) {
            return Err(format!(
                "MINER_POOL_WORKER may hold only letters, digits, dashes and underscores, \
                 got {configured:?}: a pool would read the {character:?} as another field. \
                 Set MINER_POOL_USER to send a name outside that"
            ));
        }
        return Ok(Some(configured.to_string()));
    }

    let host: String = hostname
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(32)
        .collect();
    Ok((!host.is_empty()).then_some(host))
}

/// Resolve `MINER_EXTRANONCE_START`: `auto`, a decimal `u64`, or a hex one.
///
/// Hex is accepted because the derived starts are 64-bit and a log line is
/// easier to copy back in one form than the other; decimal is what gets logged,
/// because that is what the search reports a winner's extranonce as.
///
/// Nothing here improves the odds of a block. The search space is already ours
/// alone — the coinbase pays to our address, so our merkle roots are no other
/// miner's — and every digest is an independent draw wherever it is drawn from.
/// A non-zero start buys exactly one thing: two instances that share a payout
/// address stop walking identical headers.
fn parse_extranonce_start(spec: &str) -> Result<Extranonce, String> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("auto") {
        return Ok(derive_extranonce_start());
    }

    let (digits, radix) = match spec.strip_prefix("0x").or_else(|| spec.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (spec, 10),
    };

    u64::from_str_radix(digits, radix)
        .map(Extranonce)
        .map_err(|error| {
            format!(
                "MINER_EXTRANONCE_START must be `auto`, a decimal u64 or a 0x-prefixed hex u64, \
                 got {spec}: {error}"
            )
        })
}

/// Derive a start no other instance is likely to be walking from.
///
/// The clock separates two runs on this machine; the hostname and the pid
/// separate two machines that started in the same nanosecond. Hashing them
/// rather than concatenating them means a start that is spread across the space
/// instead of clustered wherever the clock happens to sit — which matters only
/// because two instances a millisecond apart should not land adjacent.
///
/// The result is logged, and that is what keeps `auto` reproducible: the run can
/// be repeated exactly by passing the logged number back in.
fn derive_extranonce_start() -> Extranonce {
    use sha2::Digest;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Calls so far in this process. The clock is the entropy, but relying on it
    /// alone would mean trusting its resolution — two calls inside one tick
    /// would derive the same start. A counter costs nothing and removes the
    /// assumption.
    static CALLS: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());

    let mut hasher = sha2::Sha256::new();
    hasher.update(hostname().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(nanos.to_le_bytes());
    hasher.update(CALLS.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let digest = hasher.finalize();

    Extranonce(u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("a sha256 digest is 32 bytes, so its first 8 exist"),
    ))
}

/// This machine's name, for the sole purpose of telling it apart from another
/// running the same configuration.
///
/// Best-effort on purpose: an empty name costs only the separation the pid and
/// the clock already provide, which is why a missing `/etc/hostname` is not an
/// error worth ending a run over.
fn hostname() -> String {
    env::var("HOSTNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Install the Ctrl-C and SIGTERM handlers and hand back the flags every search
/// checks between batches.
///
/// Its own function because `MINER_MODE=stratum` returns before the node is
/// contacted and still has to be interruptible — a pool session is the longest
/// running thing this binary does.
fn install_signal_handlers() -> Result<Signals, String> {
    let signals = Signals::new(Arc::new(AtomicBool::new(false)));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(signals.stop_flag()))
        .map_err(|error| format!("could not install the SIGINT handler: {error}"))?;
    signal_hook::flag::register(
        signal_hook::consts::SIGTERM,
        Arc::clone(signals.stop_flag()),
    )
    .map_err(|error| format!("could not install the SIGTERM handler: {error}"))?;
    Ok(signals)
}

/// Mine blocks against a local node until the requested count is reached or
/// the user exits.
pub fn run(settings: &Settings, log: &Logger) -> Result<(), String> {
    let config = Config::from_settings(settings)?;

    if config.mode == Mode::Probe {
        return run_probe(&config, log);
    }

    // Before the RPC client, deliberately, the way the probe is. A pool client
    // has no use for a local node: the pool decides what is mined, owns the
    // coinbase, and is the only thing this mode ever talks to. Requiring
    // `bitcoind` here would make it untestable on a machine without one, and
    // would contact a node for a run that has nothing to ask it.
    if config.mode == Mode::Stratum {
        let signals = install_signal_handlers()?;
        // **The protocol is a setting rather than a discovery.** The two
        // clients are separate programs sharing a share search and a
        // configuration; see `stratum/pool.rs` for why neither can find out
        // which the far end speaks.
        let run = match config.pool.protocol {
            Protocol::V1 => run_stratum,
            Protocol::V2 => run_stratum_v2,
        };

        // **`MINER_POOL_PASS` has no SV2 counterpart.** There is no password
        // field in `SetupConnection` or `OpenExtendedMiningChannel`, and the
        // difficulty request V1 smuggles through `d=` is `max_target` there.
        // Said once rather than ignored silently, because a run that set it is
        // a run expecting it to do something — and said here rather than in
        // `v2/run.rs`, which has no way to name the spelling the run used.
        if config.pool.protocol == Protocol::V2
            && !config.pool.pass.is_empty()
            && config.pool.pass != MINER_POOL_PASS
        {
            log.log(settings.relabel(format!(
                "MINER_POOL_PASS is set to {:?} and Stratum V2 has no field for it; \
                 the difficulty request goes in the channel's max_target instead",
                config.pool.pass
            )));
        }
        return run(
            &config.pool,
            config.device.uses_cpu().then(|| config.cpu()),
            config.device.uses_gpu().then_some(config.gpu),
            config.extranonce_start,
            &signals,
            log,
        );
    }

    let rpc = Rpc::new(config.chain, &config.datadir)?;

    // Refusing to grind against a syncing node saves a run that could never
    // produce an accepted block. Regtest is exempt: a fresh regtest chain is
    // one genesis block of no work, so the node reports initial block download
    // until the first block is mined — which is what this is here to do.
    let info = rpc.call("getblockchaininfo", json!([]))?;
    if config.chain != Chain::Regtest
        && info
            .get("initialblockdownload")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(format!(
            "the {} node is still in initial block download",
            config.chain.name()
        ));
    }

    let signals = install_signal_handlers()?;

    if config.mode == Mode::Watch {
        return run_watch(&rpc, &signals, log);
    }

    // The two experiments that put blocks on a chain are refused anywhere the
    // history is not disposable. Regtest is private and rebuildable; every
    // other chain has other people's blocks in it.
    if config.mode.writes_blocks() && config.chain != Chain::Regtest {
        return Err(format!(
            "this mode writes blocks and is only allowed on regtest, not {}",
            config.chain.name()
        ));
    }

    let payout = payout_script(&config)?;

    // Said out loud whenever it is not the default, because a derived start is
    // the one piece of a run's configuration that the configuration does not
    // record. Without this line an `auto` run cannot be repeated.
    if config.extranonce_start != Extranonce::ZERO {
        log.log(format!(
            "the extranonce walk starts at {start} rather than zero; \
             {label}={start} repeats this run exactly",
            label = settings.label("MINER_EXTRANONCE_START"),
            start = config.extranonce_start,
        ));
    }

    // The tag is permanent in a way nothing else about a run is: a won block
    // carries it for as long as the chain exists. Worth reading the whole
    // rotation back once at startup, while it can still be corrected — the
    // per-height line below says only which entry is in play right now.
    // if !MINER_COINBASE_TAGS.is_empty() {
    //     log.log(format!(
    //         "the coinbase rotates one tag per height through {}",
    //         MINER_COINBASE_TAGS
    //             .iter()
    //             // Wrapped, because the delimiters are what a block explorer will
    //             // show and the point of reading this back is comparing it with
    //             // one.
    //             .map(|name| format!("{:?}", block::wrap_coinbase_tag(name)))
    //             .collect::<Vec<_>>()
    //             .join(", ")
    //     ));
    // }

    match config.mode {
        Mode::Rejections => return rejections::run(&rpc, &payout, log),
        Mode::Reorg => return reorg::run(&rpc, &payout, log),
        Mode::Validate => {
            return validate::run(&rpc, &payout, config.template_version_rolling, log);
        }
        Mode::Lottery => return run_lottery(&rpc, &config, &payout, &signals, log),
        _ => (),
    }

    log.log(format!(
        "miner started on {} against the local node with the {} device",
        config.chain.name(),
        config.device.name(),
    ));

    if config.device.uses_cpu() {
        log.log(format!(
            "cpu model {}, {} workers on the {} hasher",
            cpu_model(),
            config.workers,
            config.hasher.name()
        ));
    }

    let mut gpu = if config.device.uses_gpu() {
        let miner = GpuMiner::new(config.gpu)?;
        log.log(format!(
            "gpu model {} ({}), {} lanes x {} nonces, {} in flight",
            miner.adapter().name,
            miner.adapter().backend,
            config.gpu.lanes,
            config.gpu.nonces_per_lane,
            config.gpu.pipeline,
        ));
        Some(miner)
    } else {
        None
    };
    log.log(format!("paying to {}", config.address));

    if config.mode == Mode::Benchmark {
        return benchmark(&rpc, &config, &payout, gpu.as_mut(), &signals, log);
    }

    log.log(format!(
        "target blocks: {}",
        if config.blocks == 0 {
            "until exit".to_string()
        } else {
            config.blocks.to_string()
        }
    ));

    // The watcher is started before the first template so that no template is
    // ever ground without one held open on it.
    let watcher = Watcher::start(&rpc, &signals, config.prefetch);

    let mut mined = 0u64;
    let mut total_hashes = 0u64;
    let mut total_seconds = 0.0f64;
    // The hardest hash the run has seen, across every template it ground. The
    // one measurement a block search can otherwise not make: below the target
    // it reports nothing at all, so a run that wins nothing — which is every
    // mainnet run this hardware will ever do — has no other evidence of how
    // close it came.
    let mut best = 0.0f64;
    // What each device walked, for a run that used more than one; empty
    // otherwise, since a single device's total is the run's.
    let mut total_parts: Vec<Part> = Vec::new();
    let mut abandoned_hashes = 0u64;
    let mut abandoned_templates = 0u64;
    // The last version mask reported, so it is said once and again on change.
    let mut rolling_said: Option<u32> = None;

    // What the prefetch is worth, measured rather than assumed. Both paths to a
    // template are timed, because the saving is the difference between them
    // rather than the cost of a fetch: taking one from the watcher is a channel
    // read, which is cheap but not free.
    let mut prefetched_templates = 0u64;
    let mut prefetch_seconds = 0.0f64;
    let mut fetches = 0u64;
    let mut fetch_seconds = 0.0f64;
    // Whether the last search ended because the longpoll answered. That is the
    // one ending whose answer carried a template worth grinding next.
    let mut answered = false;
    // The height last ground, so a template offered by the watcher can be
    // checked against it without asking the node anything.
    let mut last_height: Option<i64> = None;
    // How many templates this run has already ground at that height, which is
    // what moves the coinbase tag along within one height. Reset by the height
    // changing, so the first template of every block starts the rotation where
    // the height alone puts it.
    let mut attempt = 0u64;

    // Whether a min-difficulty window is open, and how many have opened. The
    // chain's own difficulty is the last one it asked for outside a window,
    // which needs no extra call to the node — outside a window the template's
    // difficulty *is* the chain's.
    let mut window_open = false;
    let mut windows = 0u64;
    let mut chain_difficulty: Option<f64> = None;

    while !signals.stopped() && (config.blocks == 0 || mined < config.blocks) {
        watcher.report(log);

        // The longpoll answer that ended the last search *was* a full template,
        // parsed on the watcher thread while the GPU was still hashing. Taking
        // it here is the whole prefetch: stopping a search now costs a channel
        // read rather than a round trip to the node.
        //
        // Drained unconditionally, even when the result is thrown away, so an
        // answer this run has moved past does not go on holding a mainnet
        // transaction set.
        // Timed from here, before the channel is drained, so both paths are
        // measured from the same starting line: everything between a search
        // ending and the next one having a template to grind.
        let started = Instant::now();
        let carried = watcher
            .prefetched()
            .filter(|offered| accept_prefetched(answered, last_height, offered.height));
        answered = false;

        let (mut template, prefetched) = match carried {
            Some(carried) => (carried, true),
            None => (Template::fetch(&rpc)?, false),
        };
        if prefetched {
            prefetched_templates += 1;
            prefetch_seconds += started.elapsed().as_secs_f64();
        } else {
            fetches += 1;
            fetch_seconds += started.elapsed().as_secs_f64();
        }
        // The tag rotates per template, not only per height. A mainnet height
        // is dozens of templates abandoned for better work — the log above
        // this loop is one height and four of them — and a tag that only moved
        // with the height would spend all of that on one name. The height
        // still chooses where the rotation starts; this walks it from there,
        // and is fixed now so that every coinbase built from this template,
        // one per extranonce, carries the same tag.
        attempt = if last_height == Some(template.height) {
            attempt + 1
        } else {
            0
        };
        template.attempt = attempt;

        last_height = Some(template.height);
        let watching = watcher.watch(&template, &signals);
        // A template also expires on the clock, because the one thing worth
        // waiting for on testnet4 — the min-difficulty window — arrives
        // without any event a longpoll could carry.
        signals.renew(config.template_seconds);
        let node_target = template.target;
        if let Some(bits) = config.bits {
            template.target = harder_target(bits, node_target)?;
        }

        // Testnet4's twenty-minute exception, which is the only circumstance in
        // which this hardware can win a block on a public network. The template
        // carries the eased `bits` itself, so nothing here has to implement the
        // rule — but it is worth saying out loud when it happens, because
        // otherwise the window is only visible afterwards, in the difficulty
        // column of a block that was already won or lost.
        let eased = config.chain.min_difficulty_bits() == Some(template.bits);
        let difficulty = difficulty_of(template.bits);
        if eased && !window_open {
            windows += 1;
            let expected = difficulty * 4_294_967_296.0;
            let rate = if total_seconds > 0.0 {
                total_hashes as f64 / total_seconds
            } else {
                0.0
            };
            log.log(format!(
                "MIN-DIFFICULTY WINDOW OPEN at height {}: difficulty {} against the chain's {}, \
                 {expected:.3e} expected hashes{}",
                template.height,
                format_difficulty(difficulty),
                chain_difficulty.map_or("unknown".to_string(), format_difficulty),
                if rate > 0.0 {
                    format!(
                        " — about {} at the rate so far",
                        format_duration(expected / rate)
                    )
                } else {
                    String::new()
                },
            ));
        } else if !eased && window_open {
            log.log(format!(
                "the min-difficulty window closed: back to difficulty {}",
                format_difficulty(difficulty)
            ));
        }
        window_open = eased;
        if !eased {
            chain_difficulty = Some(difficulty);
        }

        log.log(format!(
            "height {}, tag {}, transactions {}, fee {} sats, difficulty {}{}{}{}",
            template.height,
            // The name rather than the wrapped tag: the delimiters and the
            // prefix are the same on every line, and what changes here is
            // which entry of the rotation this template would put in a block.
            block::coinbase_tag_name_for(template.height, template.attempt),
            template.transactions.len(),
            template.fees,
            format_difficulty(difficulty_of(template.bits)),
            if prefetched {
                ", prefetched" // carried by the longpoll that ended the last search
            } else {
                ""
            },
            match config.bits {
                Some(bits) => format!(
                    ", grinding to {:08x} instead (difficulty {})",
                    bits.to_consensus(),
                    format_difficulty(difficulty_of(bits))
                ),
                None => String::new(),
            },
            if watching {
                ""
            } else {
                ", with no longpoll: the node offered no longpollid"
            },
        ));

        // Said when it changes rather than per template: once for a run whose
        // templates all agree, and again when a deployment starts or ends.
        if config.template_version_rolling {
            let mask = config.version_mask(&template);
            if rolling_said != Some(mask) {
                log.log(version_rolling_note(&config, &template, mask));
                rolling_said = Some(mask);
            }
        }

        let found = run_search(&config, &template, &payout, gpu.as_mut(), &signals)?;
        total_hashes += found.hashes;
        total_seconds += found.seconds;
        add_parts(&mut total_parts, &found.parts);

        // Said when it moves and not once per template, for the reason the
        // pool client says the same thing: it is the only number that changes
        // while nothing is being found, and a line that repeated an unchanged
        // one every thirty seconds would be noise around the times it did move.
        // The share of the height's own difficulty is what gives it a scale —
        // 4.51K sounds like something until it is read against 142.30T.
        if found.best > best {
            best = found.best;
            let needed = difficulty_of(template.bits);
            let ratio = best / needed;
            log.log(format!(
                "best difficulty so far: {}, {:.2e} {} the {}",
                format_difficulty(best),
                ratio,
                // A regtest chain asks for 4.66e-10, so the best hash of a
                // search is routinely worth billions of times it — and reading
                // "7.79e9 of" a number it is larger than is how a log makes a
                // reader distrust the rest of it.
                if ratio < 1.0 { "of" } else { "times" },
                format_difficulty(needed),
            ));
        }

        let Some(winner) = found.winner else {
            // A stale template is not the end of the run, only of this
            // search: the node has better work and everything under the old
            // template would have been thrown away by it anyway.
            if found.ending == Ending::Stale || found.ending == Ending::Expired {
                abandoned_templates += 1;
                abandoned_hashes += found.hashes;
                // A stale ending means the longpoll answered, and its answer is
                // the next template. An expiry means the clock ran out, which no
                // longpoll reported and no answer is waiting for.
                answered = found.ending == Ending::Stale;
                log.log(format!(
                    "height {}, {}, {} hashes in {} ({}H/s){}",
                    template.height,
                    match found.ending {
                        Ending::Expired => "template is older than its lifetime",
                        _ => "template update",
                    },
                    format_scaled(found.hashes as f64, false),
                    format_duration(found.seconds),
                    format_scaled(found.hashes as f64 / found.seconds.max(1.0), true),
                    // This template's own best, which the record line above
                    // stops saying anything about the moment the record stops
                    // moving: a mainnet height is a tag a minute, and every one
                    // after the first would otherwise finish without reporting
                    // what it did. Zero is a search that hashed nothing and has
                    // nothing to report.
                    if found.best > 0.0 {
                        format!(" with difficulty {}", format_difficulty(found.best))
                    } else {
                        String::new()
                    },
                ));
                continue;
            }
            log.log(format!("search stopped ({})", found.ending.name()));
            break;
        };

        // Local checks first: a failure here is our bug, and its message says
        // which rule was broken. The node's rejection reason is the fallback,
        // not the first line of defence.
        check_block(&winner.block, &template)?;

        let hash = winner.block.header.block_hash();
        let tag = block::coinbase_tag_for(template.height, template.attempt);
        log.log("******* FOUND ********");
        // The version is named, and a rolled one is said to be rolled: a block
        // on an explorer under a version the template never announced should
        // not be a surprise to the person who mined it.
        let version = winner.block.header.version.to_consensus() as u32;
        log.log(format!(
            "******* MINED tag {}, height {}, version {version:08x}{}, nonce {}, extranonce {}, \
             after {} hashes {}",
            tag,
            template.height,
            if version == template.version as u32 {
                String::new()
            } else {
                format!(" (rolled from {:08x})", template.version as u32)
            },
            winner.block.header.nonce,
            winner.extranonce,
            found.hashes,
            hash
        ));
        log.log("**********************");

        submit(&rpc, &winner.block, log)?;
        confirm(&rpc, &hash, template.height, log)?;

        mined += 1;
    }

    watcher.report(log);

    log.log(format!(
        "mined {} blocks, {} hashes in {} at {}H/s{}",
        mined,
        format_scaled(total_hashes as f64, false),
        format_duration(total_seconds),
        format_scaled(total_hashes as f64 / total_seconds.max(1.0), true),
        if best > 0.0 {
            format!(", best hash difficulty {}", format_difficulty(best))
        } else {
            String::new()
        },
    ));

    if !total_parts.is_empty() {
        log.log(share_report(&total_parts, total_hashes));
    }
    if abandoned_templates > 0 {
        log.log(format!(
            "{abandoned_templates} templates went stale mid-search, costing {abandoned_hashes} \
             hashes ({:.1}% of the run)",
            abandoned_hashes as f64 / total_hashes.max(1) as f64 * 100.0,
        ));
    }
    if prefetched_templates > 0 || fetches > 0 {
        // The abandoned-hashes line above overstates what a stale template
        // costs, because those hashes were losing draws either way — a nonce
        // carries no progress into the next one. This line is the part that is
        // really lost: wall-clock time with the device idle, waiting on a node.
        let mean_fetch = fetch_seconds / fetches.max(1) as f64;
        let mean_carried = prefetch_seconds / prefetched_templates.max(1) as f64;
        log.log(if config.prefetch {
            format!(
                "templates: {prefetched_templates} carried by a longpoll answer at {} each, \
                 {fetches} fetched at {} each{}",
                format_span(mean_carried),
                format_span(mean_fetch),
                if prefetched_templates > 0 && fetches > 0 {
                    format!(
                        " — {} of idle device saved",
                        format_span(
                            (mean_fetch - mean_carried).max(0.0) * prefetched_templates as f64
                        ),
                    )
                } else {
                    String::new()
                },
            )
        } else {
            settings.relabel(format!(
                "templates: {fetches} fetched at {} each, with MINER_PREFETCH off",
                format_span(mean_fetch),
            ))
        });
    }
    if config.chain.min_difficulty_bits().is_some() {
        // The measurement worth having on such a chain: not whether a block
        // was won, but how often the chance appeared.
        log.log(format!(
            "{windows} min-difficulty windows opened during the run, {mined} blocks won"
        ));
    }

    Ok(())
}

/// Measure the distribution of digests against a reporting threshold.
///
/// The threshold is deliberately *easier* than the chain's — on mainnet by a
/// factor of 10^14 — so it is met often enough to have a sample. That is the
/// opposite of what `MINER_BITS` means everywhere else, and it is safe here
/// only because this mode submits nothing: it never builds a block it intends
/// anyone to accept.
fn run_lottery(
    rpc: &Rpc,
    config: &Config,
    payout: &ScriptBuf,
    signals: &Signals,
    log: &Logger,
) -> Result<(), String> {
    if config.device != Device::Gpu {
        return Err(
            "MINER_MODE=lottery needs MINER_DEVICE=gpu: the CPU search reports the \
                    first winner rather than every one, which is the wrong shape for a \
                    distribution — and `hybrid` would mix the two shapes into one sample"
                .into(),
        );
    }

    let sweep = lottery::Sweep {
        threshold: match config.bits {
            Some(bits) => Target::from_compact(bits),
            None => Target::from_compact(CompactTarget::from_consensus(MINER_LOTTERY_BITS)),
        },
        seconds: config.bench_seconds,
        extranonce_start: config.extranonce_start,
    }
    .validate()?;

    let template = Template::fetch(rpc)?;
    let mut miner = GpuMiner::new(config.gpu)?;
    log.log(format!(
        "gpu model {} ({})",
        miner.adapter().name,
        miner.adapter().backend
    ));

    lottery::run(&template, payout, sweep, &mut miner, signals, log)
}

/// Accept a compact target only if it is at least as hard as the node's.
///
/// Grinding to a harder target than required is a valid thing to do — the block
/// still meets the consensus target — but grinding to an easier one produces
/// headers the node rejects, so the mistake is caught here rather than by
/// `submitblock`.
fn harder_target(bits: CompactTarget, node_target: Target) -> Result<Target, String> {
    let target = Target::from_compact(bits);
    if target == Target::ZERO {
        return Err(format!(
            "MINER_BITS {:08x} expands to a zero target, which no header can meet",
            bits.to_consensus()
        ));
    }
    if target > node_target {
        return Err(format!(
            "MINER_BITS {:08x} is easier than the chain's target, so its blocks would be \
             rejected; it may only be harder",
            bits.to_consensus()
        ));
    }
    Ok(target)
}

/// Follow the node's work without doing any.
///
/// This is the longpoll on its own: fetch a template, hold the call open, and
/// report what changed when it answers. It exists because the interesting
/// version of the stale path needs a chain whose blocks take minutes, and on
/// such a chain this machine will not be mining any of them.
fn run_watch(rpc: &Rpc, signals: &Signals, log: &Logger) -> Result<(), String> {
    // No prefetch here on purpose. This mode exists to report what each fetch
    // says about the node's work, so it fetches every template itself and
    // compares it with the last — taking one from the watcher would leave the
    // fetch path, which is the thing being observed, untravelled.
    let watcher = Watcher::start(rpc, signals, false);
    log.log("watching the node's template; Ctrl-C to stop");

    let mut previous: Option<Template> = None;
    let mut updates = 0u64;
    let started = Instant::now();

    while !signals.stopped() {
        watcher.report(log);
        let template = Template::fetch(rpc)?;

        let change = match &previous {
            None => "first template".to_string(),
            Some(last) if last.previous_block_hash != template.previous_block_hash => {
                format!("new tip, height {} to {}", last.height, template.height)
            }
            Some(last) => format!(
                "same tip, {} transactions to {}, {} sat fees to {}",
                last.transactions.len(),
                template.transactions.len(),
                last.fees,
                template.fees,
            ),
        };
        log.log(format!(
            "template {updates} after {}: {change}",
            format_duration(started.elapsed().as_secs_f64()),
        ));

        if !watcher.watch(&template, signals) {
            return Err("the node offered no longpollid, so there is nothing to watch".into());
        }
        previous = Some(template);
        updates += 1;

        // Polling a flag rather than blocking on the watcher keeps Ctrl-C as
        // responsive here as it is inside a search.
        while !signals.stale() && !signals.stopped() {
            thread::sleep(Duration::from_millis(100));
        }
    }

    log.log(format!(
        "watched {updates} templates over {}",
        format_duration(started.elapsed().as_secs_f64())
    ));
    Ok(())
}

/// Verify the GPU shader against `rust-bitcoin`.
///
/// Deliberately needs no node: it hashes fixed headers, including the mainnet
/// genesis header whose hash is a published constant, so a failure here is
/// never confused with a template or RPC problem.
fn run_probe(config: &Config, log: &Logger) -> Result<(), String> {
    let mut miner = GpuMiner::new(config.gpu)?;
    log.log(format!(
        "probing {} ({}) at {} lanes x {} nonces, {} dispatches in flight",
        miner.adapter().name,
        miner.adapter().backend,
        config.gpu.lanes,
        config.gpu.nonces_per_lane,
        config.gpu.pipeline,
    ));

    gpu::probe(&mut miner, log)?;
    log.log("probe: every check passed");
    Ok(())
}

/// Measure the search rate against a real template and an unreachable target.
///
/// The target is the only thing replaced. Everything else — the template, the
/// coinbase, the merkle root, the header serialization, the extranonce roll —
/// is what a production run does, so the number this prints is the number the
/// GPU has to beat rather than a microbenchmark of `sha256d`.
///
/// Nothing is ever submitted: `Target::ZERO` cannot be met, so the run always
/// ends on the timer or the user's signal.
fn run_search(
    config: &Config,
    template: &Template,
    payout: &ScriptBuf,
    gpu: Option<&mut GpuMiner>,
    signals: &Signals,
) -> Result<cpu::Search, String> {
    match config.device {
        Device::Cpu => search(
            template,
            payout,
            config.cpu(),
            signals,
            config.extranonce_start,
        ),
        Device::Gpu => gpu::search(
            template,
            payout,
            require_gpu(gpu, config.device)?,
            signals,
            config.extranonce_start,
            config.version_mask(template),
        ),
        Device::Hybrid => hybrid::search(
            template,
            payout,
            config.cpu(),
            require_gpu(gpu, config.device)?,
            signals,
            config.extranonce_start,
            config.version_mask(template),
        ),
    }
}

/// What `MINER_TEMPLATE_VERSION_ROLLING=on` does with this template, and why
/// when the answer is nothing.
fn version_rolling_note(config: &Config, template: &Template, mask: u32) -> String {
    let version = template.version as u32;
    if !config.device.uses_gpu() {
        "template version rolling is on, but the CPU search is single-version: nothing rolls"
            .to_string()
    } else if template.vbavailable.is_none() {
        format!(
            "template version rolling is on, but the template has no vbavailable, so the \
             deployments the node knows of are unknown: version {version:08x} is not rolled"
        )
    } else if mask == 0 {
        format!(
            "template version rolling is on, but version {version:08x} leaves no bit of \
             {:08x} free: nothing rolls",
            block::BIP320_MASK
        )
    } else {
        format!(
            "rolling version bits {mask:08x} of template version {version:08x}, two versions \
             per nonce"
        )
    }
}

/// The engine a device that searches on the GPU must have been given.
///
/// Its absence is this file's mistake rather than the user's — both places that
/// open a miner ask [`Device::uses_gpu`] — so it is named as one, instead of
/// falling back to the CPU and reporting a rate nobody asked for.
fn require_gpu(gpu: Option<&mut GpuMiner>, device: Device) -> Result<&mut GpuMiner, String> {
    gpu.ok_or_else(|| {
        format!(
            "the {} device searches on the GPU and no engine was opened for it",
            device.name()
        )
    })
}

fn benchmark(
    rpc: &Rpc,
    config: &Config,
    payout: &ScriptBuf,
    gpu: Option<&mut GpuMiner>,
    signals: &Signals,
    log: &Logger,
) -> Result<(), String> {
    let mut template = Template::fetch(rpc)?;
    match config.device {
        Device::Cpu => log.log(format!(
            "benchmarking the {} hasher, {} workers for {}s, against the height {} template",
            config.hasher.name(),
            config.workers,
            config.bench_seconds,
            template.height,
        )),
        Device::Gpu => log.log(format!(
            "benchmarking the GPU, {} lanes x {} nonces, {} in flight, for {}s against the \
             height {} template",
            config.gpu.lanes,
            config.gpu.nonces_per_lane,
            config.gpu.pipeline,
            config.bench_seconds,
            template.height,
        )),
        Device::Hybrid => log.log(format!(
            "benchmarking both devices at once for {}s against the height {} template: \
             the GPU at {} lanes x {} nonces, {} in flight, and {} workers on the {} hasher",
            config.bench_seconds,
            template.height,
            config.gpu.lanes,
            config.gpu.nonces_per_lane,
            config.gpu.pipeline,
            config.workers,
            config.hasher.name(),
        )),
    }
    if config.template_version_rolling {
        log.log(version_rolling_note(
            config,
            &template,
            config.version_mask(&template),
        ));
    }

    template.target = bitcoin::Target::ZERO;

    // No watcher here, deliberately: a benchmark measures a fixed span of work,
    // and a template going stale halfway through would end it early and report
    // a duration nobody asked for.
    let deadline = Signals::new(Arc::clone(signals.stop_flag()));
    let timer_signals = deadline.clone();
    let seconds = config.bench_seconds;
    let timer = thread::spawn(move || {
        let started = Instant::now();
        // Polling keeps the timer responsive to Ctrl-C instead of holding the
        // process open for the whole duration.
        while started.elapsed() < Duration::from_secs(seconds) && !timer_signals.stopped() {
            thread::sleep(Duration::from_millis(50));
        }
        timer_signals.stop();
    });

    let measured = run_search(config, &template, payout, gpu, &deadline)?;
    timer.join().map_err(|_| "the benchmark timer panicked")?;

    if measured.winner.is_some() {
        return Err("the benchmark met an unreachable target, which cannot happen".into());
    }

    let rate = measured.hash_rate();
    match config.device {
        Device::Cpu => log.log(format!(
            "{} hashes in {:.2}s: {:.2} MH/s total, {:.2} MH/s per worker",
            measured.hashes,
            measured.seconds,
            rate / 1e6,
            rate / config.workers as f64 / 1e6,
        )),
        Device::Gpu => log.log(format!(
            "{} hashes in {:.2}s: {:.2} MH/s",
            measured.hashes,
            measured.seconds,
            rate / 1e6,
        )),
        // The combined rate on its own says nothing about whether running both
        // was worth it: what answers that is each half's own rate, compared
        // with what the same half measures alone. The share is printed because
        // it is the number that decides — a CPU worth 3% of the total is a
        // rounding error against the risk of slowing the GPU's host loop down.
        Device::Hybrid => {
            log.log(format!(
                "{} hashes in {:.2}s: {:.2} MH/s from both devices",
                measured.hashes,
                measured.seconds,
                rate / 1e6,
            ));
            log.log(share_report(&measured.parts, measured.hashes));
        }
    }

    // A benchmark walks a fixed span of hashes, which makes the best of them
    // something with a known distribution rather than an anecdote: the median
    // best over `n` draws is `n / (2^32 ln 2)`, the same arithmetic
    // `MINER_MODE=lottery` measures at length. Printed beside it so a number
    // that looks impressive can be read against the number to expect.
    if measured.best > 0.0 {
        let median = measured.hashes as f64 / (4_294_967_296.0 * std::f64::consts::LN_2);
        log.log(format!(
            "best hash: difficulty {}, against a median of {} for {} hashes",
            format_difficulty(measured.best),
            format_difficulty(median),
            format_scaled(measured.hashes as f64, false),
        ));
    }

    // The lottery arithmetic this project exists to make concrete: what that
    // rate would mean against the chain the node is actually following. A
    // private chain has no competition to speak of — regtest reports a
    // hashrate of around 1e-7 — so the comparison is only drawn against a
    // network that has one.
    let network = rpc
        .call("getmininginfo", json!([]))?
        .get("networkhashps")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    if network > 1e12 && rate > 0.0 {
        let share = rate / network;
        let seconds_per_block = 600.0 / share;
        log.log(format!(
            "that is {share:.3e} of the {:.2} EH/s network: one block every {:.3e} years",
            network / 1e18,
            seconds_per_block / 31_557_600.0,
        ));
    }

    Ok(())
}

/// One line naming what each device of a multi-device search contributed: the
/// hashes, its own rate, and the share of the total it was.
///
/// The combined rate cannot say whether running both was worth it, because the
/// thing to be afraid of — one device slowing the other down — is invisible in a
/// sum. Each half against what it measures alone is what says: on this hardware
/// the GPU holds 431 MH/s either way and the CPU walks 256 where it walks 354
/// alone, which is the package power budget rather than contention, and still
/// worth 1.59x. Compare the halves only against a run made in the same thermal
/// state; a cold cpu-only run reads 19% above a warm one.
fn share_report(parts: &[Part], total: u64) -> String {
    parts
        .iter()
        .map(|part| {
            format!(
                "{}: {} hashes {}H/s, {:.1}% of the total",
                part.device,
                format_scaled(part.hashes as f64, false),
                format_scaled(part.hash_rate(), true),
                part.hashes as f64 / total.max(1) as f64 * 100.0,
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Add one search's per-device work to a run's running totals.
///
/// Each device's seconds accumulate separately from the run's wall clock,
/// because the halves of a hybrid search overlap: adding their spans would
/// double-count the time and halve every rate reported from it.
fn add_parts(totals: &mut Vec<Part>, parts: &[Part]) {
    for part in parts {
        match totals.iter_mut().find(|total| total.device == part.device) {
            Some(total) => {
                total.hashes += part.hashes;
                total.seconds += part.seconds;
            }
            None => totals.push(*part),
        }
    }
}

/// Format a span that is usually milliseconds and occasionally minutes.
///
/// `format_duration` cannot: it rounds to whole seconds, and one round trip to a
/// node — the thing this exists to report — rounds to zero. A long run's total
/// still needs the other form, so the threshold is where the units change.
fn format_span(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.1} ms", seconds * 1e3)
    } else {
        format_duration(seconds)
    }
}

/// Whether a template a longpoll answered with should be ground next, given how
/// the last search ended and what height it was grinding.
///
/// The watcher has already refused to offer an answer from a longpoll the run
/// has moved past. This is the stricter half, and it is stricter because the two
/// mistakes are not the same size: refusing a good template costs one round
/// trip, while accepting one for work the chain has left behind costs the whole
/// search that follows.
///
/// `answered` is the load-bearing condition. A longpoll answers on a new tip or
/// a changed mempool, and only a search that *ended* stale is one where the
/// answer describes what the run should do next:
///
/// - a search that found a block changed the tip itself, by submitting one, and
///   an answer built before that landed is for the height just mined;
/// - a search that expired ran out of clock, which is the one thing no longpoll
///   reports — on testnet4 the whole point of the expiry is that the eased
///   target appears without any event, so an answer from before the window
///   opened carries the hard target.
fn accept_prefetched(answered: bool, last_height: Option<i64>, offered_height: i64) -> bool {
    answered && last_height.is_none_or(|height| offered_height >= height)
}

fn format_difficulty(difficulty: f64) -> String {
    format_scaled(difficulty, false)
}

/// Resolve the script the coinbase pays to.
///
/// `MINER_ADDRESS` is the only source, and it must decode on the chain in use.
/// There is no fallback to the node's wallet: a run off mainnet passes an
/// address for its own chain, which on regtest comes from
/// `bitcoin-cli -regtest getnewaddress`.
fn payout_script(config: &Config) -> Result<ScriptBuf, String> {
    let address = &config.address;
    let address = address
        .parse::<Address<NetworkUnchecked>>()
        .map_err(|error| format!("invalid payout address {address}: {error}"))?
        .require_network(config.chain.network())
        .map_err(|error| {
            format!(
                "the payout address is not a {} address: {error}",
                config.chain.name()
            )
        })?;

    Ok(address.script_pubkey())
}

/// Submit a block and insist the node said nothing.
///
/// `submitblock` returns null on acceptance and a reason otherwise —
/// `duplicate`, `inconclusive`, or a consensus rule name. Anything but null is
/// a failure worth stopping for, since it means the builder is wrong.
fn submit(rpc: &Rpc, block: &bitcoin::Block, log: &Logger) -> Result<(), String> {
    let hex = serialize_block(block);
    log.log(format!("submitting {} bytes", hex.len() / 2));

    match rpc.call("submitblock", json!([hex]))? {
        Value::Null => Ok(()),
        reason => Err(format!("the node rejected the block: {reason}")),
    }
}

/// Confirm the node actually extended its chain with the block we submitted.
///
/// A null `submitblock` means accepted, not necessarily best chain, so the tip
/// is read back rather than assumed.
fn confirm(rpc: &Rpc, hash: &bitcoin::BlockHash, height: i64, log: &Logger) -> Result<(), String> {
    let tip = rpc.call("getbestblockhash", json!([]))?;
    let tip = tip
        .as_str()
        .ok_or("getbestblockhash did not return a string")?;

    if tip != hash.to_string() {
        return Err(format!(
            "the block was accepted but the tip is {tip}, not {hash}"
        ));
    }

    let count = rpc
        .call("getblockcount", json!([]))?
        .as_u64()
        .ok_or("getblockcount did not return a number")?;

    if count as i64 != height {
        return Err(format!("the tip is at height {count}, expected {height}"));
    }

    log.log(format!("accepted at height {height}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(hex: &str) -> CompactTarget {
        CompactTarget::from_consensus(u32::from_str_radix(hex, 16).expect("valid hex"))
    }

    #[test]
    fn difficulty_uses_compact_si_suffixes() {
        assert_eq!(format_difficulty(1.262_315e14), "126.23T");
        assert_eq!(format_difficulty(1_748_362_838.564_64), "1.75G");
        assert_eq!(format_difficulty(1.0), "1.00");
        // A regtest difficulty rounds away to nothing, deliberately.
        assert_eq!(format_difficulty(4.656_542e-10), "0.00");
    }

    #[test]
    fn a_harder_target_is_accepted_and_an_easier_one_is_not() {
        let regtest = Target::from_compact(bits("207fffff"));

        // Difficulty 1 against regtest's 4.7e-10: far harder, and the blocks
        // it produces are still valid.
        assert!(harder_target(bits("1d00ffff"), regtest).is_ok());
        // Equal is allowed; it is what the miner would have used anyway.
        assert!(harder_target(bits("207fffff"), regtest).is_ok());

        // The easier direction has to be tested against a chain that leaves
        // room to be easier than. Nothing valid is easier than regtest's
        // limit: one exponent higher overflows 256 bits and expands to zero,
        // so it fails the other check instead and proves nothing about this
        // one. Difficulty 1 against difficulty 1/256 does.
        let difficulty_one = Target::from_compact(bits("1d00ffff"));
        let error = harder_target(bits("1e00ffff"), difficulty_one)
            .expect_err("an easier target must be refused");
        assert!(error.contains("easier"), "wrong reason: {error}");
    }

    #[test]
    fn the_registry_and_the_settings_a_run_reads_are_one_list() {
        // Both directions, which is the point of it. A name `Config` reads
        // that nobody registered is already an error from `get`; a name in
        // `--help` that nothing behind it reads is what this side catches, and
        // it is the failure that would otherwise ship a flag doing nothing.
        //
        // Building a whole `Config` from an empty line is what exercises every
        // call: with no flag and no variable set, nothing returns early, so
        // every `get` in it runs.
        let _guard = crate::settings::test_env_lock();
        let settings = Settings::parse(["puntominer"]).expect("an empty line parses");
        Config::from_settings(&settings)
            .expect("the compiled-in defaults are a valid configuration");

        let mut registered: std::collections::BTreeSet<String> = crate::settings::registry()
            .iter()
            .map(|setting| setting.env.to_string())
            .collect();
        // The one setting `Config` does not read: `main` needs the log before
        // there is anything to log a configuration error to.
        assert!(registered.remove("MINER_LOG"));
        // And the one `Settings` reads itself, before any `Config` exists.
        assert!(registered.remove("MINER_CONFIG"));

        assert_eq!(settings.queried(), registered);
    }

    #[test]
    fn a_capture_is_refused_under_v1_and_taken_under_v2() {
        // Refused rather than ignored: a V1 run that asked for a capture and
        // wrote nothing would be found out only when the file was wanted.
        let _guard = crate::settings::test_env_lock();
        let v1 = Settings::parse(["puntominer", "--pool-capture", "/tmp/frames.hex"])
            .expect("the line parses");
        let why = pool_from_env(&v1).expect_err("a capture under v1");
        assert!(
            why.contains("--pool-capture"),
            "names the spelling used: {why}"
        );
        assert!(why.contains("logging proxy"), "{why}");

        let v2 = Settings::parse([
            "puntominer",
            "--pool-protocol",
            "v2",
            "--pool-capture",
            "/tmp/frames.hex",
        ])
        .expect("the line parses");
        assert_eq!(
            pool_from_env(&v2).expect("a capture under v2").capture,
            "/tmp/frames.hex"
        );
    }

    #[test]
    fn an_extranonce_start_is_read_as_decimal_hex_or_derived() {
        assert_eq!(parse_extranonce_start("0").unwrap(), Extranonce::ZERO);
        assert_eq!(parse_extranonce_start(" 42 ").unwrap(), Extranonce(42));
        assert_eq!(
            parse_extranonce_start("18446744073709551615").unwrap(),
            Extranonce(u64::MAX)
        );
        // Hex, because a derived start is a 64-bit number and that is the form
        // it is easiest to recognise as one.
        assert_eq!(
            parse_extranonce_start("0xdeadbeef").unwrap(),
            Extranonce(0xdead_beef)
        );
        assert_eq!(parse_extranonce_start("0XFF").unwrap(), Extranonce(255));

        // The messages name the variable, because this is only ever reached
        // from the environment.
        for bad in ["", "-1", "1.5", "0x", "twelve", "18446744073709551616"] {
            let error =
                parse_extranonce_start(bad).expect_err("an unparseable start must be refused");
            assert!(
                error.contains("MINER_EXTRANONCE_START"),
                "wrong message for {bad:?}: {error}"
            );
        }
    }

    #[test]
    fn auto_derives_a_start_that_differs_between_runs() {
        // `auto` exists so two instances do not walk the same headers, which it
        // can only deliver if it does not keep returning the same number.
        // Consecutive calls are the weakest case and therefore the one to test.
        assert!(
            parse_extranonce_start("AUTO").is_ok(),
            "auto is case-insensitive"
        );

        let starts: Vec<Extranonce> = (0..8)
            .map(|_| parse_extranonce_start("auto").expect("auto always resolves"))
            .collect();
        let distinct: std::collections::HashSet<u64> = starts.iter().map(|s| s.0).collect();
        assert_eq!(
            distinct.len(),
            starts.len(),
            "auto repeated a start: {starts:?}"
        );
        // Spread across the space rather than clustered near the clock's value,
        // which is what hashing the inputs is for.
        assert!(
            starts.iter().any(|s| s.0 > u64::MAX / 4),
            "every derived start landed in the bottom quarter: {starts:?}"
        );
    }

    #[test]
    fn a_prefetched_template_is_taken_only_after_the_longpoll_ended_the_search() {
        // The case this exists for: the search stopped because the longpoll
        // answered, and the answer is the next template.
        assert!(accept_prefetched(true, Some(961_092), 961_092));
        assert!(accept_prefetched(true, Some(961_092), 961_093));
        // The first template of a run has no height behind it.
        assert!(accept_prefetched(true, None, 961_092));

        // Every other ending refuses, whatever the answer says. A block we
        // mined moved the tip ourselves; an expiry is the clock, which no
        // longpoll answered about.
        assert!(!accept_prefetched(false, Some(961_092), 961_093));
        assert!(!accept_prefetched(false, None, 961_092));

        // And never backwards, which is the shape of the race worth refusing:
        // the longpoll answered for a mempool update on the old tip at the same
        // moment the search won the block, so the answer describes a height that
        // is now mined.
        assert!(!accept_prefetched(true, Some(961_092), 961_091));
    }

    #[test]
    fn a_span_shorter_than_a_second_is_reported_in_milliseconds() {
        // The case that made this exist: `format_duration` renders a round trip
        // to the node as "0s", which says nothing about what the prefetch saved.
        assert_eq!(format_span(0.059), "59.0 ms");
        assert_eq!(format_span(0.0002), "0.2 ms");
        assert_eq!(format_span(0.0), "0.0 ms");
        // And a whole run's total is still a duration.
        assert_eq!(format_span(1.0), "1s");
        assert_eq!(format_span(125.0), "2m05s");
    }

    #[test]
    fn a_worker_name_is_configured_first_and_derived_from_the_machine_second() {
        // The configured name is passed through untouched: it is what a pool
        // dashboard is keyed on, and every live measurement was taken under it.
        assert_eq!(
            worker_name("puntominer", "ubuntu"),
            Ok(Some("puntominer".to_string()))
        );

        // Empty is the older behaviour, which is the thing to want when one
        // configuration runs on several machines.
        assert_eq!(worker_name("", "ubuntu"), Ok(Some("ubuntu".to_string())));

        // A hostname nobody chose for this is filtered rather than refused —
        // the dots in a fully qualified name would each be a field separator —
        // and capped, because a pool need not take an unbounded one.
        assert_eq!(
            worker_name("", "miner-01.lan\n"),
            Ok(Some("miner-01lan".to_string()))
        );
        assert_eq!(
            worker_name("", &"h".repeat(64)),
            Ok(Some("h".repeat(32))),
            "a long hostname is capped rather than sent whole"
        );

        // Nothing left to name the machine by is not a failure: the address on
        // its own is a valid username, and a solo pool credits by it anyway.
        assert_eq!(worker_name("", ""), Ok(None));
        assert_eq!(worker_name("", "!!!"), Ok(None));

        // A configured name is the case that must not be sanitised. Silently
        // dropping the dot would send `bc1q....worker.extra` as two fields and
        // credit the shares somewhere nobody asked for.
        let refused = worker_name("worker.extra", "ubuntu")
            .expect_err("a dot in a configured worker name is a field separator");
        assert!(
            refused.contains("MINER_POOL_USER"),
            "the refusal should name the way to send it anyway, got {refused}"
        );
        assert!(worker_name("worker 1", "ubuntu").is_err());
    }

    #[test]
    fn compact_targets_that_expand_to_zero_are_refused() {
        // Neither of these is a "wrong number" — `Target::from_compact`
        // expands both to zero and says nothing, so a miner handed one grinds
        // until it is killed. That is the failure this check exists for, and
        // it is how it was found.
        let regtest = Target::from_compact(bits("207fffff"));
        // `20ffffff` belongs here rather than with the easier-than-chain case:
        // one exponent above regtest's limit is not an easier target, it is a
        // 257-bit number that expands to zero.
        for hex in ["21ffffff", "20ffffff", "1d80ffff", "00000000"] {
            assert_eq!(Target::from_compact(bits(hex)), Target::ZERO);
            let error =
                harder_target(bits(hex), regtest).expect_err("a zero target must be refused");
            assert!(error.contains("zero target"), "wrong reason: {error}");
        }
    }
}
