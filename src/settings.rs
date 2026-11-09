//! Where a run's configuration comes from: the command line, the environment,
//! a file named by either of them, and the compiled-in defaults — each beating
//! the one after it.
//!
//! A setting has **one name and two spellings**. `MINER_GPU_LANES` is
//! `--gpu-lanes` by [`Setting::long`] rather than by a second list, so a setting
//! added to [`registry`] gets its flag for free and the two spellings cannot
//! disagree about which settings exist. A config file is a third *source* for
//! those same settings and not a third spelling: its keys are the variable
//! names, exactly.
//!
//! `clap` parses the line and renders the help; it does not own the list.
//! [`command`] is *built from* [`registry`] and never writes a flag out by hand,
//! which is the whole reason the registry is here rather than spread through
//! `runner.rs` as it used to be. What `clap` is given is a name, a variable and
//! a description; what it hands back is a string. Every type, every range and
//! every refusal stays where it was — so `clap` speaks only for structural
//! failures, an unknown flag or a missing value, and everything about a *value*
//! is still said in this project's own voice.
//!
//! Two deliberate omissions. `clap` is given no `Arg::default_value`: an absent
//! argument means absent, and the typed constant passed to [`Settings::get`] at
//! the call site fills it, which keeps `constants.rs` the one place a default
//! lives. And the boolean settings are not given `Arg::env` either — reading
//! `MINER_PREFETCH=0` through `clap` would take a custom value parser to keep
//! the `yes/no/on/off` spellings, where [`read_env_flag`] already does it.

use std::{collections::BTreeMap, env, fs, io, str::FromStr, sync::OnceLock};

use clap::{Arg, ArgAction, ArgMatches, Command, parser::ValueSource};

use crate::constants::{
    MINER_ADDRESS, MINER_BENCH_SECONDS, MINER_BITCOIND_DATADIR, MINER_BITS, MINER_BLOCKS,
    MINER_CHAIN, MINER_CPU_LOAD_PERCENT, MINER_DEVICE, MINER_EXTRANONCE_START, MINER_GPU_CAPACITY,
    MINER_GPU_LANES, MINER_GPU_NONCES, MINER_GPU_PERCENT, MINER_GPU_PIPELINE, MINER_HASHER,
    MINER_MODE, MINER_POOL, MINER_POOL_AGENT, MINER_POOL_AUTHORITY, MINER_POOL_CAPTURE,
    MINER_POOL_DIFFICULTY, MINER_POOL_HASHRATE, MINER_POOL_PASS, MINER_POOL_PROTOCOL,
    MINER_POOL_RECONNECT_SECONDS, MINER_POOL_USER, MINER_POOL_WORKER, MINER_PREFETCH,
    MINER_TEMPLATE_SECONDS, MINER_TEMPLATE_VERSION_ROLLING, MINER_VERSION_ROLLING, RESULTS_DIR,
};

/// Whether a setting takes a value or is a bare flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Value,
    Flag,
}

/// What a setting falls back to when neither spelling is used.
///
/// Held only so `--help` can print it. The value itself is passed to
/// [`Settings::get`] by the caller, typed, which is what stops this from
/// becoming a second place a default is written down.
#[derive(Clone, Debug)]
pub enum Fallback {
    /// A compiled-in default, rendered from the constant in `constants.rs`
    /// itself rather than restated here.
    Value(String),
    /// Not a compiled-in value: worked out at startup from the machine.
    Derived(&'static str),
}

impl Fallback {
    /// How `--help` says it. An empty default is spelled rather than shown,
    /// since a blank after `default:` reads as a missing line.
    fn display(&self) -> &str {
        match self {
            Self::Value(value) if value.is_empty() => "empty",
            Self::Value(value) => value,
            Self::Derived(description) => description,
        }
    }
}

/// One setting, under its one name.
#[derive(Clone, Debug)]
pub struct Setting {
    /// The name. Everything else about how it is spelled derives from this.
    pub env: &'static str,
    pub kind: Kind,
    pub fallback: Fallback,
    pub help: &'static str,
}

impl Setting {
    /// The long flag, without its dashes: `MINER_GPU_LANES` is `gpu-lanes`.
    ///
    /// Mechanical and injective, which is what makes it safe to derive rather
    /// than list: two distinct variables cannot produce one flag.
    pub fn long(&self) -> String {
        self.env
            .strip_prefix("MINER_")
            .unwrap_or(self.env)
            .to_ascii_lowercase()
            .replace('_', "-")
    }

    /// The negative half of a boolean pair: `--no-prefetch`.
    fn negative_long(&self) -> String {
        format!("no-{}", self.long())
    }

    /// The id `clap` knows the negative half by. Not a flag name, and never
    /// displayed.
    fn negative_id(&self) -> String {
        format!("no_{}", self.env)
    }

    fn value_name(&self) -> String {
        self.long().to_ascii_uppercase().replace('-', "_")
    }

    fn help_line(&self) -> String {
        match self.kind {
            Kind::Value => format!("{} [default: {}]", self.help, self.fallback.display()),
            // `clap` renders `[env: ...]` from `Arg::env`, which a boolean is
            // deliberately not given — see the module docs — so the variable is
            // named here instead of going unmentioned.
            Kind::Flag => format!(
                "{} [env: {}] [default: {}]",
                self.help,
                self.env,
                self.fallback.display()
            ),
        }
    }
}

/// Where a setting's value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The command line, which wins.
    Flag,
    /// The environment, which beats a file and the default.
    Environment,
    /// A file named by `--config`, which beats the default. Deliberately not
    /// [`Self::Default`]: a protocol written into a file was set on purpose,
    /// and a URL that disagrees with it should be refused.
    File,
    /// Neither, so the compiled-in value stands.
    Default,
}

/// Every setting this binary has.
///
/// The order is the order `--help` prints, which is roughly the order a run
/// uses them in: what to do, where, with what, and then the pool.
pub fn registry() -> &'static [Setting] {
    static REGISTRY: OnceLock<Vec<Setting>> = OnceLock::new();
    REGISTRY.get_or_init(build_registry)
}

fn build_registry() -> Vec<Setting> {
    /// A setting that takes a value, whose default is a constant.
    fn value(env: &'static str, fallback: String, help: &'static str) -> Setting {
        Setting {
            env,
            kind: Kind::Value,
            fallback: Fallback::Value(fallback),
            help,
        }
    }

    /// A setting whose default this machine decides.
    fn derived(env: &'static str, fallback: &'static str, help: &'static str) -> Setting {
        Setting {
            env,
            kind: Kind::Value,
            fallback: Fallback::Derived(fallback),
            help,
        }
    }

    vec![
        value(
            "MINER_CONFIG",
            String::new(),
            "A file of MINER_ settings, one KEY=VALUE per line, which the environment and \
             flags override. Empty reads none.",
        ),
        value(
            "MINER_CHAIN",
            MINER_CHAIN.to_string(),
            "Chain to work against: main, testnet4, signet or regtest",
        ),
        value(
            "MINER_MODE",
            MINER_MODE.to_string(),
            "What the run does: mine, bench, probe, watch, rejections, reorg, validate, \
             lottery or stratum",
        ),
        value(
            "MINER_BLOCKS",
            MINER_BLOCKS.to_string(),
            "Blocks to mine before stopping; 0 runs until Ctrl-C",
        ),
        value(
            "MINER_ADDRESS",
            MINER_ADDRESS.to_string(),
            "Where the coinbase pays; must decode on the chain in use",
        ),
        value(
            "MINER_DEVICE",
            MINER_DEVICE.to_string(),
            "Where the nonce search runs: cpu, gpu or hybrid (both at once)",
        ),
        derived(
            "MINER_WORKERS",
            "MINER_CPU_CORES_USAGE_PERCENT of the logical cores",
            "CPU search threads",
        ),
        value(
            "MINER_CPU_PERCENT",
            MINER_CPU_LOAD_PERCENT.to_string(),
            "Duty cycle per search thread, 1 to 100; the CPU search only",
        ),
        value(
            "MINER_HASHER",
            MINER_HASHER.to_string(),
            "Which implementation walks the nonce space: auto, naive, portable, sha-ni, \
             rustcrypto or rustcrypto-naive",
        ),
        value(
            "MINER_GPU_LANES",
            MINER_GPU_LANES.to_string(),
            "GPU invocations per dispatch",
        ),
        value(
            "MINER_GPU_NONCES",
            MINER_GPU_NONCES.to_string(),
            "Nonces each GPU lane walks per dispatch",
        ),
        value(
            "MINER_GPU_PIPELINE",
            MINER_GPU_PIPELINE.to_string(),
            "Dispatches in flight; 1 submits and waits",
        ),
        value(
            "MINER_GPU_PERCENT",
            MINER_GPU_PERCENT.to_string(),
            "Duty cycle of the GPU, 1 to 100, resting between dispatches; the block and share \
             searches only",
        ),
        value(
            "MINER_GPU_CAPACITY",
            MINER_GPU_CAPACITY.to_string(),
            "Winners one GPU dispatch may record",
        ),
        value(
            "MINER_BITS",
            MINER_BITS.to_string(),
            "Compact target to grind to instead of the template's, which may only be harder; \
             empty uses the template's",
        ),
        value(
            "MINER_EXTRANONCE_START",
            MINER_EXTRANONCE_START.to_string(),
            "Where the extranonce walk begins: auto, a decimal u64, or a 0x-prefixed hex one",
        ),
        value(
            "MINER_TEMPLATE_SECONDS",
            MINER_TEMPLATE_SECONDS.to_string(),
            "Seconds a template may be ground before it is refetched; 0 waits for the longpoll",
        ),
        Setting {
            env: "MINER_PREFETCH",
            kind: Kind::Flag,
            fallback: Fallback::Value(MINER_PREFETCH.to_string()),
            help: "Mine the template a longpoll answers with, rather than refetching it",
        },
        Setting {
            env: "MINER_TEMPLATE_VERSION_ROLLING",
            kind: Kind::Flag,
            fallback: Fallback::Value(MINER_TEMPLATE_VERSION_ROLLING.to_string()),
            help: "Roll the template's free version bits on the GPU, two versions per nonce \
                   (AsicBoost); the solo block search only",
        },
        value(
            "MINER_BENCH_SECONDS",
            MINER_BENCH_SECONDS.to_string(),
            "Duration of a benchmark run, in seconds",
        ),
        value(
            "MINER_BITCOIND_DATADIR",
            MINER_BITCOIND_DATADIR.to_string(),
            "Bitcoin Core's datadir, which is where the RPC cookie is read from",
        ),
        value(
            "MINER_LOG",
            format!("{RESULTS_DIR}/log"),
            "Append-only log destination",
        ),
        value(
            "MINER_POOL",
            MINER_POOL.to_string(),
            "host:port of a Stratum pool, or a stratum+tcp:// or stratum2+tcp:// URL. \
             Empty means off, and there is no default pool",
        ),
        value(
            "MINER_POOL_USER",
            MINER_POOL_USER.to_string(),
            "The whole worker name to authorize as; empty builds it from MINER_ADDRESS and \
             MINER_POOL_WORKER",
        ),
        value(
            "MINER_POOL_WORKER",
            MINER_POOL_WORKER.to_string(),
            "The <worker> in <address>.<worker>; letters, digits, dashes and underscores only. \
             Empty falls back to this machine's hostname",
        ),
        value(
            "MINER_POOL_PASS",
            MINER_POOL_PASS.to_string(),
            "The password field, which on a solo pool is a difficulty request rather than a \
             credential",
        ),
        value(
            "MINER_POOL_DIFFICULTY",
            MINER_POOL_DIFFICULTY.to_string(),
            "Share difficulty to ask for: a request under v1, a floor under v2",
        ),
        value(
            "MINER_POOL_AGENT",
            MINER_POOL_AGENT.to_string(),
            "User agent announced in mining.subscribe",
        ),
        value(
            "MINER_POOL_RECONNECT_SECONDS",
            MINER_POOL_RECONNECT_SECONDS.to_string(),
            "Pause before reconnecting; a dropped socket is normal, not fatal",
        ),
        value(
            "MINER_POOL_PROTOCOL",
            MINER_POOL_PROTOCOL.to_string(),
            "Which protocol the pool speaks: v1 or v2. Cannot be discovered, so a wrong \
             guess is a hang; a stratum2+tcp:// URL in MINER_POOL says it instead",
        ),
        value(
            "MINER_POOL_AUTHORITY",
            MINER_POOL_AUTHORITY.to_string(),
            "The Stratum V2 pool authority key to pin, as base58check or 64 hex characters. \
             Empty refuses any pool that is not on the loopback; skip connects without \
             verifying the certificate",
        ),
        value(
            "MINER_POOL_HASHRATE",
            MINER_POOL_HASHRATE.to_string(),
            "Hash rate to claim in the Stratum V2 channel open, in h/s; 0 claims nothing and \
             takes the pool's default difficulty",
        ),
        value(
            "MINER_POOL_CAPTURE",
            MINER_POOL_CAPTURE.to_string(),
            "File to record every Stratum V2 frame to, in plaintext hex; empty records \
             nothing. V2 only",
        ),
        value(
            "MINER_VERSION_ROLLING",
            MINER_VERSION_ROLLING.to_string(),
            "BIP310 version rolling: auto, off, or force (loopback pools only)",
        ),
    ]
}

/// What `--help` says above the list.
const ABOUT: &str = "A Bitcoin block miner: build a block from a node's template and grind its \
                     header, on the CPU, on the GPU, or on both at once — or take work from a \
                     Stratum V1 or V2 pool and send back shares.";

/// And below it. The derivation rule is stated rather than the flags listed,
/// because the rule is what stays true when a setting is added.
const AFTER_HELP: &str = "Every setting has two spellings: the flag above and the environment \
                          variable beside it, which is the flag's name uppercased with dashes \
                          as underscores and MINER_ in front. A flag beats the variable, which \
                          beats the config file, which beats the compiled-in default.\n\n\
                          Examples:\n  \
                          puntominer --chain regtest --blocks 1\n  \
                          MINER_CHAIN=regtest MINER_BLOCKS=1 puntominer\n  \
                          puntominer --mode probe                      # no node needed\n  \
                          puntominer --mode stratum --pool host:port   # mine for a pool";

/// The `clap` command, assembled from [`registry`] and nothing else.
pub fn command() -> Command {
    let mut command = Command::new("puntominer")
        .version(env!("CARGO_PKG_VERSION"))
        .about(ABOUT)
        .after_help(AFTER_HELP);

    for setting in registry() {
        command = match setting.kind {
            Kind::Value => command.arg(
                Arg::new(setting.env)
                    .long(setting.long())
                    .env(setting.env)
                    // The value is not printed back. `MINER_POOL_PASS` is not a
                    // credential — it is `d=1`, a difficulty request — but
                    // `--help` is not the place to read anyone's environment
                    // out loud.
                    .hide_env_values(true)
                    .value_name(setting.value_name())
                    .action(ArgAction::Set)
                    // Last wins. `clap` refuses a repeated argument otherwise,
                    // and repeating one is what makes a wrapper script
                    // composable: `./v1` puts its defaults first and anything
                    // typed after overrides them.
                    .overrides_with(setting.env)
                    .help(setting.help_line()),
            ),
            // A pair rather than `--prefetch=false`, which is what someone
            // reaches for and also what reads best. The variable is left to
            // `read_env_flag`, which already knows the spellings a shell user
            // types.
            //
            // Each half overrides itself as well as the other, for the same
            // reason a value does: `SetTrue` refuses a repeat just as `Set`
            // does, so `--no-prefetch --no-prefetch` would otherwise be an
            // error rather than the last spelling winning.
            Kind::Flag => command
                .arg(
                    Arg::new(setting.env)
                        .long(setting.long())
                        .action(ArgAction::SetTrue)
                        .overrides_with(setting.env)
                        .overrides_with(setting.negative_id())
                        .help(setting.help_line()),
                )
                .arg(
                    Arg::new(setting.negative_id())
                        .long(setting.negative_long())
                        .action(ArgAction::SetTrue)
                        .overrides_with(setting.negative_id())
                        .overrides_with(setting.env)
                        .help(format!("The other half of --{}", setting.long())),
                ),
        };
    }

    command
}

/// A file named by `--config` or `MINER_CONFIG`, holding settings as
/// `KEY=VALUE`.
///
/// **The keys are the variable names.** A file holds exactly what
/// `MINER_CHAIN=regtest MINER_BLOCKS=20 ./m` would say if you saved it, and
/// `set -a; . rig.env` reads it the same way. A third *source* for the same
/// settings, not a third *spelling* of them.
///
/// Where this reader and a shell sourcing the same file would disagree, the
/// line is refused rather than guessed at, so a file this accepts means the
/// same thing under `set -a; .`.
#[derive(Debug)]
struct ConfigFile {
    path: String,
    /// Registry name -> the value, and the 1-based line it was on.
    entries: BTreeMap<&'static str, (String, usize)>,
}

impl ConfigFile {
    /// Pure: text in, entries out, or the first refusal, naming `path:line`
    /// and the key it was about.
    fn parse(path: &str, text: &str) -> Result<Self, String> {
        let mut entries: BTreeMap<&'static str, (String, usize)> = BTreeMap::new();

        for (index, raw) in text.lines().enumerate() {
            let number = index + 1;
            // Whitespace at the ends of a line is the file's rather than the
            // setting's, which is what a shell does with an assignment too —
            // and which is also what makes a CRLF file read like an LF one.
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // `export MINER_X=…` is how the same file is written for a shell
            // to source, and the prefix says nothing this reader needs. A key
            // that merely *starts* with `export` is still a key.
            let line = match line.strip_prefix("export") {
                Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
                _ => line,
            };

            // Split at the first `=`, so `MINER_POOL_PASS=d=1` works.
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!(
                    "{path}:{number}: {line} has no = in it, and every line is KEY=VALUE"
                ));
            };

            // Refused under its own name rather than as an unknown setting:
            // the reason is one file per run, and not that the name is wrong.
            if key == "MINER_CONFIG" {
                return Err(format!(
                    "{path}:{number}: MINER_CONFIG is refused in a config file, \
                     because one run reads one file"
                ));
            }

            // A key is exactly a registry name: `MINER_GPU_LANES=65536`, never
            // `gpu-lanes = 65536`. A key with whitespace around it is not a
            // name this binary knows, which is how `KEY = value` — a command
            // to a shell, not an assignment — is refused without a rule of its
            // own.
            let Some(setting) = registry().iter().find(|setting| setting.env == key) else {
                return Err(format!(
                    "{path}:{number}: {key} is not a setting this binary has; \
                     ./m --help lists the ones that are"
                ));
            };

            // A repeat is a mistake. On the line, repeats are how a wrapper
            // composes; in one file, the second one is simply the one that
            // would have run, and neither is worth being quiet about.
            if let Some((_, first)) = entries.get(setting.env) {
                return Err(format!(
                    "{path}:{number}: {key} is already set on line {first}"
                ));
            }

            entries.insert(
                setting.env,
                (config_value(path, number, key, value)?, number),
            );
        }

        Ok(Self {
            path: path.to_string(),
            entries,
        })
    }
}

/// One assignment's value: the quotes stripped, and none of what a shell would
/// have read differently.
fn config_value(path: &str, number: usize, key: &str, value: &str) -> Result<String, String> {
    let value = match value.chars().next() {
        // A value wrapped in matching quotes has them stripped. The closing
        // one is the last character and appears nowhere inside, since
        // `a'b'` is two shell words concatenated and not a shape worth
        // reproducing.
        Some(quote @ ('\'' | '"')) => value
            .strip_prefix(quote)
            .filter(|_| value.ends_with(quote))
            .and_then(|inner| inner.strip_suffix(quote))
            .filter(|inner| !inner.contains(quote))
            .ok_or_else(|| format!("{path}:{number}: {key} has an unmatched quote"))?,
        _ => {
            if value.contains(['\'', '"']) {
                return Err(format!("{path}:{number}: {key} has an unmatched quote"));
            }
            // An unquoted space would run a command under `set -a; .`.
            if value.contains(char::is_whitespace) {
                return Err(format!(
                    "{path}:{number}: {key} has an unquoted space in its value; \
                     a value containing a space has to be quoted"
                ));
            }
            value
        }
    };

    // `$`, a backtick and a backslash are how a shell reaches outside the
    // text, and this reader does not follow it there. Refused rather than
    // passed through, which is the one rule that keeps the two readings apart.
    for reached_outside in ['$', '`', '\\'] {
        if value.contains(reached_outside) {
            return Err(format!(
                "{path}:{number}: {key} contains {reached_outside}, which a shell reads \
                 differently and this reader refuses"
            ));
        }
    }

    Ok(value.to_string())
}

/// A refusal about a file, carried the way `clap` carries one.
///
/// Unformatted, so it prints as `error: <message>` with no usage block and no
/// `--help` hint, which is what a bad flag looks like. The trailing newline is
/// the message's own, as `clap`'s own messages are.
fn config_error(message: String) -> clap::Error {
    clap::Error::raw(
        clap::error::ErrorKind::ValueValidation,
        format!("{message}\n"),
    )
}

/// A run's configuration, resolved from the line, the environment and a file
/// named by either of them.
#[derive(Debug)]
pub struct Settings {
    matches: ArgMatches,
    /// The file `--config` named, if one was named and read.
    config: Option<ConfigFile>,
    /// Which settings a run has actually asked for.
    ///
    /// Only under test, and for one assertion: that [`registry`] and the
    /// settings `Config` reads are the same list. A name read but not
    /// registered is already an error; this is what catches the other
    /// direction, a flag offered in `--help` that nothing behind it reads.
    #[cfg(test)]
    queried: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl Settings {
    /// Parse an argument list, the first element being the binary's own name.
    ///
    /// `--help` and `--version` come back as [`clap::Error`]s of their own
    /// kinds rather than as values, which is what lets `main` print them and
    /// leave with a zero status before the log is opened. Both are answered
    /// before any file is read, so `./m --help` still works while
    /// `MINER_CONFIG` points at a broken one.
    pub fn parse<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::parse_with(args, |path| fs::read_to_string(path))
    }

    /// The same, with the read injected, so tests never touch the disk.
    ///
    /// A file is read only when it is named, by `--config` or `MINER_CONFIG`.
    /// Nothing looks in the working directory or the home one: a file picked
    /// up on its own could supply `MINER_POOL`, and then a bare `./m` would
    /// open a socket to a pool nobody named for that run.
    ///
    /// A refusal is a [`clap::Error`] of `ValueValidation`, unformatted, so it
    /// prints as `error: <message>` with no usage block and no `--help` hint —
    /// the same as a bad flag. `main` already prints that and leaves 1 before
    /// the log opens.
    fn parse_with<I, T>(
        args: I,
        read: impl FnOnce(&str) -> io::Result<String>,
    ) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let matches = command().try_get_matches_from(args)?;

        let config = match matches.get_one::<String>("MINER_CONFIG") {
            // Empty means off, as it does for `MINER_POOL`. This is how to drop
            // a wrapper's file.
            Some(path) if !path.is_empty() => {
                let text = read(path)
                    .map_err(|error| config_error(format!("could not read {path}: {error}")))?;
                Some(ConfigFile::parse(path, &text).map_err(config_error)?)
            }
            _ => None,
        };

        Ok(Self {
            matches,
            config,
            #[cfg(test)]
            queried: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        })
    }

    /// The file's value for a setting, and the line it was on.
    fn file_entry(&self, name: &str) -> Option<(&str, &str, usize)> {
        let file = self.config.as_ref()?;
        let (value, number) = file.entries.get(name)?;
        Some((value, &file.path, *number))
    }

    /// The line `main` logs once the log is open, or `None` when no file was
    /// read.
    ///
    /// A third source makes it more likely that a value was beaten from
    /// somewhere the reader is not looking, so the file is named and so is
    /// every key it lost. Listing every key would only repeat the file.
    pub fn config_summary(&self) -> Option<String> {
        let file = self.config.as_ref()?;
        let mut summary = format!("config: {} settings from {}", file.entries.len(), file.path);

        for name in file.entries.keys() {
            let beaten_by = match self.origin(name) {
                Origin::Flag => self.label(name),
                Origin::Environment => "the environment".to_string(),
                // The file's own value, so nothing needs saying about it.
                Origin::File | Origin::Default => continue,
            };
            summary.push_str(&format!("; {name} overridden by {beaten_by}"));
        }

        Some(summary)
    }

    /// The value of a setting, parsed, or the caller's default.
    ///
    /// The default is passed in typed rather than read from [`registry`]: a
    /// default belongs in `constants.rs`, and rendering one to a string for
    /// `clap` only to parse it back would be a second place for it to live.
    pub fn get<T: FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        let setting = self.setting(name)?;
        self.record(name);
        if setting.kind != Kind::Value {
            return Err(format!("{name} is a flag and must be read as one"));
        }

        match self.matches.get_one::<String>(name) {
            Some(value) => value
                .parse()
                .map_err(|_| format!("{} has an invalid value: {value}", self.label(name))),
            // Only the source that wins is asked to make sense, so a file
            // beaten by a flag is not also asked to hold a valid value.
            None => match self.file_entry(name) {
                Some((value, path, line)) => value.parse().map_err(|_| {
                    format!(
                        "{} has an invalid value in {path}:{line}: {value}",
                        self.label(name)
                    )
                }),
                None => Ok(default),
            },
        }
    }

    /// The value of a boolean setting: the line first, then the variable, then
    /// the file's entry, then the caller's default.
    pub fn flag(&self, name: &str, default: bool) -> Result<bool, String> {
        let setting = self.setting(name)?;
        self.record(name);
        if setting.kind != Kind::Flag {
            return Err(format!("{name} takes a value and must be read as one"));
        }

        // `overrides_with` means at most one of the pair survives, so the last
        // one typed is the one asked about here.
        if self.matches.get_flag(&setting.negative_id()) {
            return Ok(false);
        }
        if self.matches.get_flag(setting.env) {
            return Ok(true);
        }

        // Then the variable, then the file. Both go through `parse_flag`, and
        // only the one that wins is asked to make sense.
        if env::var_os(name).is_some() {
            return read_env_flag(&self.label(name), name, default);
        }
        match self.file_entry(name) {
            Some((value, path, line)) => parse_flag(&self.label(name), value)
                .map_err(|error| format!("{error} in {path}:{line}")),
            None => Ok(default),
        }
    }

    /// Where this run's value for a setting came from.
    ///
    /// A name outside the registry panics rather than answering `Default`.
    /// `pool_from_env` asks this whether a protocol was set explicitly, and a
    /// misspelled name answering "not set" would quietly let a disagreeing URL
    /// win where it should be refused. `Config` is built from an empty line in
    /// the suite, so a misspelling fails there rather than in a run.
    pub fn origin(&self, name: &str) -> Origin {
        let setting = self.registered(name);

        match setting.kind {
            Kind::Value => match self.matches.value_source(name) {
                Some(ValueSource::CommandLine) => Origin::Flag,
                Some(ValueSource::EnvVariable) => Origin::Environment,
                _ if self.file_entry(name).is_some() => Origin::File,
                _ => Origin::Default,
            },
            // `SetTrue` carries a default of its own, so presence is what is
            // asked rather than the value source alone.
            Kind::Flag => {
                if self.matches.get_flag(setting.env)
                    || self.matches.get_flag(&setting.negative_id())
                {
                    Origin::Flag
                } else if env::var(setting.env).is_ok() {
                    Origin::Environment
                } else if self.file_entry(setting.env).is_some() {
                    Origin::File
                } else {
                    Origin::Default
                }
            }
        }
    }

    /// How to spell a setting back to whoever configured it: `--workers` when
    /// that is what they typed, `MINER_WORKERS` otherwise.
    ///
    /// A message that names a variable the reader never set sends them to look
    /// in the wrong place, which is the whole reason this exists.
    pub fn label(&self, name: &str) -> String {
        let setting = self.registered(name);

        if self.origin(name) != Origin::Flag {
            return name.to_string();
        }
        match setting.kind {
            Kind::Value => format!("--{}", setting.long()),
            Kind::Flag if self.matches.get_flag(&setting.negative_id()) => {
                format!("--{}", setting.negative_long())
            }
            Kind::Flag => format!("--{}", setting.long()),
        }
    }

    /// Rewrite a message so every setting in it is named the way this run
    /// spelled it.
    ///
    /// The alternative was threading a label through every validation in the
    /// tree — including `GpuConfig::validate` and the four `parse` functions,
    /// none of which have any other reason to know how they were configured.
    /// One pass over the finished message keeps that knowledge here.
    ///
    /// Longest name first, so `MINER_POOL` cannot eat the front of
    /// `MINER_POOL_USER`.
    pub fn relabel(&self, message: String) -> String {
        /// A stand-in no message can contain, since a `String` holding a NUL
        /// would not have come from any of these.
        fn placeholder(index: usize) -> String {
            format!("\u{0}{index}\u{0}")
        }

        let mut names: Vec<&Setting> = registry().iter().collect();
        names.sort_by_key(|setting| std::cmp::Reverse(setting.env.len()));

        // A message often names a setting the reader has *not* set — the advice
        // half of a refusal, `... needs MINER_POOL set to a pool's host:port`.
        // There is no spelling that run used for it, so it is offered in the
        // one the run is being typed in: somebody working in flags should not
        // be sent to look for a variable.
        //
        // A boolean is named by its positive half here even when the negative
        // one was typed, unlike in `label`. A message names the *setting* —
        // "with MINER_PREFETCH off" — and `--no-prefetch off` would say the
        // opposite of what happened.
        let prevailing = |setting: &Setting| match self.origin(setting.env) {
            Origin::Flag | Origin::Default if self.any_flag() => {
                format!("--{}", setting.long())
            }
            // A value that did come from the environment keeps its variable,
            // whatever else the line looks like: that is where the reader put
            // it and where they would go to change it.
            _ => self.label(setting.env),
        };

        // Two passes rather than one. Skipping a name that is spelled the same
        // either way would leave its text in the message for a shorter name to
        // rewrite the inside of — `MINER_POOL` eating the front of
        // `MINER_POOL_USER` — so every name is taken out of the way first and
        // put back as its label second.
        let staged = names
            .iter()
            .enumerate()
            .fold(message, |message, (index, setting)| {
                message.replace(setting.env, &placeholder(index))
            });

        names
            .iter()
            .enumerate()
            .fold(staged, |message, (index, setting)| {
                message.replace(&placeholder(index), &prevailing(setting))
            })
    }

    /// Note that a run asked for this setting. Nothing under a release build.
    #[cfg(test)]
    fn record(&self, name: &str) {
        if let Ok(mut queried) = self.queried.lock() {
            queried.insert(name.to_string());
        }
    }

    #[cfg(not(test))]
    fn record(&self, _name: &str) {}

    /// Every setting a run has read, for the test that holds [`registry`] to
    /// what is behind it.
    #[cfg(test)]
    pub(crate) fn queried(&self) -> std::collections::BTreeSet<String> {
        self.queried
            .lock()
            .map(|queried| queried.clone())
            .unwrap_or_default()
    }

    /// Whether this run was configured on the command line at all.
    ///
    /// `--log` and `--config` do not count. Neither says anything about the
    /// run's settings: `MINER_MODE=stratum ./m --log /tmp/x` is configured in
    /// the environment, and `./m --config rig.env` in a file whose keys are
    /// the variables. Advice to either should name a variable.
    fn any_flag(&self) -> bool {
        registry()
            .iter()
            .filter(|setting| !matches!(setting.env, "MINER_LOG" | "MINER_CONFIG"))
            .any(|setting| self.origin(setting.env) == Origin::Flag)
    }

    fn setting(&self, name: &str) -> Result<&'static Setting, String> {
        registry()
            .iter()
            .find(|setting| setting.env == name)
            .ok_or_else(|| format!("{name} is not a registered setting"))
    }

    /// The same, for the two questions that have no error to return one in.
    /// Only a programming mistake reaches the panic.
    fn registered(&self, name: &str) -> &'static Setting {
        self.setting(name).unwrap_or_else(|error| panic!("{error}"))
    }
}

/// The boolean spellings, separated from where the text came from.
///
/// `MINER_PREFETCH=0` is the obvious way to turn one of these off, and
/// `bool::from_str` would call it an invalid value. So would a file's entry,
/// which is why both go through here.
fn parse_flag(label: &str, text: &str) -> Result<bool, String> {
    match text.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(format!(
            "{label} must be 1/0, true/false, yes/no or on/off, got {other}"
        )),
    }
}

/// Read a boolean setting from the environment.
fn read_env_flag(label: &str, name: &str, default: bool) -> Result<bool, String> {
    match env::var(name) {
        Ok(value) => parse_flag(label, &value),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("could not read {name}: {error}")),
    }
}

/// Serialises every test that parses a line or sets a `MINER_` variable.
///
/// `Arg::env` reads `std::env::var` inside `clap`, so the environment leg of
/// the precedence rule cannot be injected the way a closure could be: a test
/// that sets one of these variables is visible to every other test in the
/// process, and the suite runs them in parallel. This is the one thing the
/// dependency costs, and one lock around both halves is what keeps it honest.
///
/// The environment the suite starts in is also the developer's, and a
/// `MINER_CHAIN` exported in a shell profile is exactly the case the flags
/// exist for. So every registered variable is hidden for as long as the lock
/// is held and put back when it is released; without that, an assertion about
/// a default would be an assertion about whoever ran `cargo test`.
#[cfg(test)]
pub(crate) fn test_env_lock() -> TestEnv {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // A panicking test poisons the lock, and the tests after it still have to
    // run: what is being guarded is the environment, not any state the panic
    // could have left half-written.
    let lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut shell = Vec::new();
    for setting in registry() {
        if let Some(value) = env::var_os(setting.env) {
            shell.push((setting.env, value));
            // SAFETY: held under the lock above, which every test that reads
            // or writes a registered variable takes first.
            unsafe { env::remove_var(setting.env) };
        }
    }
    TestEnv { shell, _lock: lock }
}

/// The held [`test_env_lock`], and the variables it hid.
#[cfg(test)]
pub(crate) struct TestEnv {
    shell: Vec<(&'static str, std::ffi::OsString)>,
    // Declared last, so it is released after `drop` has restored the rest.
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TestEnv {
    fn drop(&mut self) {
        // Whatever the test left set goes, and what the shell had comes back.
        for setting in registry() {
            if env::var_os(setting.env).is_some() {
                // SAFETY: the lock is still held; it is released after this.
                unsafe { env::remove_var(setting.env) };
            }
        }
        for (name, value) in &self.shell {
            unsafe { env::set_var(name, value) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a line, with the binary's own name in front the way a shell hands
    /// it over.
    ///
    /// Every caller holds [`test_env_lock`] for the whole of its own body
    /// rather than for each call: `clap` reads the environment at parse time,
    /// so a test that parses twice would otherwise be asserting across a
    /// window another test can set a variable in.
    fn parse_line(args: &[&str]) -> Settings {
        let mut line = vec!["puntominer"];
        line.extend_from_slice(args);
        Settings::parse(line).expect("the line should parse")
    }

    /// Parse a line with its files supplied from strings, so a test touches
    /// neither the disk nor anything outside [`test_env_lock`].
    fn parse_with_files(args: &[&str], files: &[(&str, &str)]) -> Result<Settings, clap::Error> {
        let mut line = vec!["puntominer"];
        line.extend_from_slice(args);
        Settings::parse_with(line, |path| {
            match files.iter().find(|(name, _)| *name == path) {
                Some((_, text)) => Ok((*text).to_string()),
                // The same reason `open` gives, which is what the refusal prints.
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "No such file or directory (os error 2)",
                )),
            }
        })
    }

    #[test]
    fn a_flag_name_is_derived_from_its_variable_and_never_written_twice() {
        // The rule, on the two shapes it has to cover: one word and several.
        let chain = registry()
            .iter()
            .find(|setting| setting.env == "MINER_CHAIN")
            .expect("MINER_CHAIN is a setting");
        assert_eq!(chain.long(), "chain");

        let reconnect = registry()
            .iter()
            .find(|setting| setting.env == "MINER_POOL_RECONNECT_SECONDS")
            .expect("MINER_POOL_RECONNECT_SECONDS is a setting");
        assert_eq!(reconnect.long(), "pool-reconnect-seconds");
        assert_eq!(reconnect.value_name(), "POOL_RECONNECT_SECONDS");

        // Injective, which is what makes deriving safe: two variables cannot
        // land on one flag, and `clap` would panic at startup if they did.
        let mut longs: Vec<String> = registry().iter().map(Setting::long).collect();
        longs.sort();
        let count = longs.len();
        longs.dedup();
        assert_eq!(longs.len(), count, "two settings derived the same flag");

        // Every setting carries a variable of the right family, since the flag
        // is derived by stripping exactly this prefix.
        for setting in registry() {
            assert!(
                setting.env.starts_with("MINER_"),
                "{} is not a MINER_ variable",
                setting.env
            );
        }
    }

    #[test]
    fn the_command_is_built_and_is_internally_consistent() {
        // `debug_assert` walks the whole command and panics on a conflict — a
        // duplicate id, a flag defined twice — which is the check that makes
        // building from the registry safe rather than merely tidy.
        command().debug_assert();
    }

    #[test]
    fn a_value_arrives_either_way_round() {
        let _guard = test_env_lock();
        assert_eq!(
            parse_line(&["--chain", "regtest"]).get("MINER_CHAIN", "main".to_string()),
            Ok("regtest".to_string())
        );
        assert_eq!(
            parse_line(&["--chain=regtest"]).get("MINER_CHAIN", "main".to_string()),
            Ok("regtest".to_string())
        );
        // Nothing given is the caller's default, not an empty string.
        assert_eq!(
            parse_line(&[]).get("MINER_BLOCKS", 7_u64),
            Ok(7),
            "an absent setting keeps the constant the caller passed"
        );
        // Typed on the way out, and the failure names the flag rather than the
        // variable nobody set.
        let error = parse_line(&["--blocks", "lots"])
            .get("MINER_BLOCKS", 0_u64)
            .expect_err("`lots` is not a number");
        assert!(error.contains("--blocks"), "wrong spelling: {error}");
        assert!(error.contains("lots"), "the value should be quoted back");
    }

    #[test]
    fn the_last_spelling_of_a_setting_wins() {
        let _guard = test_env_lock();
        // What makes a wrapper script composable: `./v1` puts its defaults
        // first and anything typed after overrides them.
        assert_eq!(
            parse_line(&["--device", "cpu", "--device", "gpu"]).get("MINER_DEVICE", String::new()),
            Ok("gpu".to_string())
        );
    }

    #[test]
    fn a_boolean_is_a_pair_of_flags_and_the_later_one_wins() {
        let _guard = test_env_lock();
        assert_eq!(parse_line(&[]).flag("MINER_PREFETCH", true), Ok(true));
        assert_eq!(parse_line(&[]).flag("MINER_PREFETCH", false), Ok(false));
        assert_eq!(
            parse_line(&["--prefetch"]).flag("MINER_PREFETCH", false),
            Ok(true)
        );
        assert_eq!(
            parse_line(&["--no-prefetch"]).flag("MINER_PREFETCH", true),
            Ok(false)
        );
        assert_eq!(
            parse_line(&["--prefetch", "--no-prefetch"]).flag("MINER_PREFETCH", true),
            Ok(false),
            "the pair overrides, so the last one typed is the answer"
        );
        assert_eq!(
            parse_line(&["--no-prefetch", "--prefetch"]).flag("MINER_PREFETCH", false),
            Ok(true)
        );

        // A repeat of either half is last-wins too, as it is for a value, so
        // a wrapper that puts one first does not turn the same flag typed
        // after it into an error.
        assert_eq!(
            parse_line(&["--prefetch", "--prefetch"]).flag("MINER_PREFETCH", false),
            Ok(true)
        );
        let repeated = parse_line(&["--no-prefetch", "--prefetch", "--no-prefetch"]);
        assert_eq!(repeated.flag("MINER_PREFETCH", true), Ok(false));
        assert_eq!(repeated.label("MINER_PREFETCH"), "--no-prefetch");
    }

    #[test]
    fn a_setting_read_as_the_wrong_shape_is_refused() {
        let _guard = test_env_lock();
        // Both are programming mistakes rather than user ones, and both would
        // otherwise be a silent default.
        assert!(
            parse_line(&[])
                .get("MINER_PREFETCH", String::new())
                .is_err()
        );
        assert!(parse_line(&[]).flag("MINER_CHAIN", true).is_err());
        assert!(parse_line(&[]).get("MINER_NOT_A_SETTING", 1_u64).is_err());
    }

    #[test]
    #[should_panic(expected = "MINER_NOT_A_SETTING is not a registered setting")]
    fn asking_where_an_unregistered_name_came_from_is_a_mistake() {
        // Not `Origin::Default`, which is what it used to answer, and which
        // reads as "not set" to every caller that compares against it.
        let _guard = test_env_lock();
        parse_line(&[]).origin("MINER_NOT_A_SETTING");
    }

    #[test]
    fn a_line_that_is_not_a_configuration_is_refused() {
        let _guard = test_env_lock();
        // An unknown flag is refused rather than ignored: ignoring it would
        // run a configuration nobody asked for.
        let error = Settings::parse(["puntominer", "--chian", "regtest"])
            .expect_err("a misspelled flag is not a setting");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        // `suggestions` is in the feature list for this line.
        assert!(
            error.to_string().contains("--chain"),
            "the near miss should be offered: {error}"
        );

        // A bare word has nothing to mean here, since no positional is defined.
        assert!(Settings::parse(["puntominer", "regtest"]).is_err());

        // A value-taking flag with nothing after it.
        let error = Settings::parse(["puntominer", "--bits"]).expect_err("--bits takes a value");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn help_and_version_are_answers_rather_than_failures() {
        let _guard = test_env_lock();
        for line in [["puntominer", "--help"], ["puntominer", "-h"]] {
            let error = Settings::parse(line).expect_err("help is returned as an error kind");
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
            // Which is how `main` tells it from a real failure.
            assert!(!error.use_stderr(), "help belongs on stdout");
        }

        let error = Settings::parse(["puntominer", "--version"]).expect_err("same for version");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn help_names_every_setting_in_both_spellings() {
        let help = command().render_long_help().to_string();
        for setting in registry() {
            assert!(
                help.contains(&format!("--{}", setting.long())),
                "{} is missing its flag from --help",
                setting.env
            );
            assert!(
                help.contains(setting.env),
                "{} is missing its variable from --help",
                setting.env
            );
        }
        // The default is shown, and an empty one is spelled rather than blank.
        assert!(help.contains("[default: empty]"), "{help}");
        // And no value of anyone's environment is read back out.
        assert!(!help.contains("[env: MINER_CHAIN=main"), "{help}");
    }

    #[test]
    fn a_message_names_the_spelling_the_run_used() {
        let _guard = test_env_lock();
        let flagged = parse_line(&["--workers", "4", "--pool", "127.0.0.1:3333"]);
        assert_eq!(flagged.label("MINER_WORKERS"), "--workers");
        assert_eq!(flagged.origin("MINER_WORKERS"), Origin::Flag);
        // Untouched settings keep their variable: the reader never set a flag
        // for them, so naming one would be the same mistake in reverse.
        assert_eq!(flagged.label("MINER_CHAIN"), "MINER_CHAIN");
        assert_eq!(flagged.origin("MINER_CHAIN"), Origin::Default);

        // A message from anywhere in the tree, rewritten once on its way out.
        assert_eq!(
            flagged.relabel("MINER_WORKERS must be greater than zero".to_string()),
            "--workers must be greater than zero"
        );
        // Advice about a setting nobody has set follows the spelling the run
        // is being typed in, since there is no spelling it *was* given in.
        assert_eq!(
            flagged.relabel("MINER_MODE=stratum needs MINER_POOL set".to_string()),
            "--mode=stratum needs --pool set"
        );
        // And a run with no flag in it keeps every variable, advice included.
        assert_eq!(
            parse_line(&[]).relabel("MINER_MODE=stratum needs MINER_POOL set".to_string()),
            "MINER_MODE=stratum needs MINER_POOL set"
        );
        // Nor does a run whose only flags say where the log goes or which
        // file to read: that run is configured in variables, not flags.
        assert_eq!(
            parse_line(&["--log", "/tmp/x"])
                .relabel("MINER_MODE=stratum needs MINER_POOL set".to_string()),
            "MINER_MODE=stratum needs MINER_POOL set"
        );
        let from_file = parse_with_files(
            &["--config", "rig.env"],
            &[("rig.env", "MINER_MODE=stratum\n")],
        )
        .expect("the file is read");
        assert_eq!(
            from_file.relabel("MINER_MODE=stratum needs MINER_POOL set".to_string()),
            "MINER_MODE=stratum needs MINER_POOL set"
        );

        // A message names a boolean by its setting, so the positive half is
        // what it says even when the negative one was typed.
        assert_eq!(
            parse_line(&["--no-prefetch"]).relabel("with MINER_PREFETCH off".to_string()),
            "with --prefetch off"
        );

        // The longest name first, so the prefix does not eat the suffix: one
        // pass would leave `--pool_USER` here, which is neither spelling of
        // anything.
        assert_eq!(
            flagged.relabel("MINER_POOL_USER is built from MINER_POOL".to_string()),
            "--pool-user is built from --pool",
            "MINER_POOL must not match inside MINER_POOL_USER"
        );

        // Both halves of a boolean say which half was typed.
        assert_eq!(
            parse_line(&["--no-prefetch"]).label("MINER_PREFETCH"),
            "--no-prefetch"
        );
        assert_eq!(
            parse_line(&["--prefetch"]).label("MINER_PREFETCH"),
            "--prefetch"
        );
    }

    #[test]
    fn the_readme_table_and_the_registry_are_one_list() {
        // The table had already drifted by four settings before this existed,
        // which is the argument for checking it rather than re-reading it.
        //
        // Read at run time rather than through `include_str!`, which Cargo
        // tracks by timestamp: an edit that preserves the mtime would leave a
        // stale copy compiled in and this test passing on it.
        let readme = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
            .expect("the README is beside Cargo.toml");

        let mut documented = std::collections::BTreeSet::new();
        for line in readme.lines().filter(|line| line.starts_with("| `--")) {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let [flag, name, fallback, ..] = cells.as_slice() else {
                panic!("a table row should have four cells: {line}");
            };
            let name = name.trim_matches('`');

            let setting = registry()
                .iter()
                .find(|setting| setting.env == name)
                .unwrap_or_else(|| panic!("{name} is in the README and not in the registry"));

            assert!(
                flag.contains(&format!("--{}", setting.long())),
                "{name} is documented as {flag} rather than --{}",
                setting.long()
            );

            // A backticked default is a value and is checked. A default this
            // machine decides — a datadir, a core count — is written as prose
            // instead, so that the README does not carry one host around.
            let quoted = fallback.trim_matches('`');
            if fallback.starts_with('`') || *fallback == "empty" {
                assert_eq!(
                    quoted,
                    setting.fallback.display(),
                    "{name} documents a default that is not the one compiled in"
                );
            }

            documented.insert(name.to_string());
        }

        let registered: std::collections::BTreeSet<String> = registry()
            .iter()
            .map(|setting| setting.env.to_string())
            .collect();
        assert_eq!(
            documented, registered,
            "the README table and the registry hold different settings"
        );
    }

    /// The one test that sets a registered variable.
    ///
    /// `Arg::env` reads `std::env::var` inside `clap`, so the environment leg
    /// cannot be injected — which makes every assertion about it racy with any
    /// other test that parses a line. They are gathered here, in one function
    /// under [`test_env_lock`], for that reason.
    #[test]
    fn a_flag_beats_the_environment_beats_the_default() {
        // Held across the mutation and every parse under it, which is what
        // keeps these variables invisible to the rest of the suite.
        let _guard = test_env_lock();

        // SAFETY: the lock above is held by every test that parses a line or
        // reads these, so nothing else in the process observes them.
        unsafe {
            env::set_var("MINER_BLOCKS", "5");
            env::set_var("MINER_PREFETCH", "0");
        }

        // The environment over the compiled-in default.
        let bare = parse_line(&[]);
        assert_eq!(bare.get("MINER_BLOCKS", 0_u64), Ok(5));
        assert_eq!(bare.origin("MINER_BLOCKS"), Origin::Environment);
        assert_eq!(bare.label("MINER_BLOCKS"), "MINER_BLOCKS");
        assert_eq!(bare.flag("MINER_PREFETCH", true), Ok(false));
        assert_eq!(bare.origin("MINER_PREFETCH"), Origin::Environment);

        // The line over the environment, for both shapes of setting.
        let flagged = parse_line(&["--blocks", "9", "--prefetch"]);
        assert_eq!(flagged.get("MINER_BLOCKS", 0_u64), Ok(9));
        assert_eq!(flagged.origin("MINER_BLOCKS"), Origin::Flag);
        assert_eq!(flagged.flag("MINER_PREFETCH", false), Ok(true));
        assert_eq!(flagged.origin("MINER_PREFETCH"), Origin::Flag);

        // `MINER_CONFIG` is a variable like any other, so the file can be named
        // that way as well as by a flag — and the environment still beats what
        // the file says.
        unsafe { env::set_var("MINER_CONFIG", "rig.env") };
        let file = "MINER_BLOCKS=2\nMINER_PREFETCH=1\n";
        let named =
            parse_with_files(&[], &[("rig.env", file)]).expect("MINER_CONFIG names the file");
        assert_eq!(named.get("MINER_BLOCKS", 0_u64), Ok(5));
        assert_eq!(named.flag("MINER_PREFETCH", true), Ok(false));
        assert_eq!(named.origin("MINER_BLOCKS"), Origin::Environment);
        // The summary names where the win came from, not only which key lost.
        assert_eq!(
            named.config_summary().as_deref(),
            Some(
                "config: 2 settings from rig.env; MINER_BLOCKS overridden by the environment; \
                  MINER_PREFETCH overridden by the environment"
            )
        );

        // And the line beats the variable beats the file.
        let all = parse_with_files(&["--blocks", "9", "--prefetch"], &[("rig.env", file)])
            .expect("MINER_CONFIG names the file");
        assert_eq!(all.get("MINER_BLOCKS", 0_u64), Ok(9));
        assert_eq!(all.flag("MINER_PREFETCH", false), Ok(true));
        assert_eq!(all.origin("MINER_BLOCKS"), Origin::Flag);
        unsafe { env::remove_var("MINER_CONFIG") };

        // A variable that is not a spelling anyone recognises, named the way
        // it was set.
        unsafe { env::set_var("MINER_PREFETCH", "maybe") };
        let error = parse_line(&[])
            .flag("MINER_PREFETCH", true)
            .expect_err("`maybe` is not a boolean");
        assert!(error.contains("MINER_PREFETCH"), "{error}");

        // The compiled-in default, once neither spelling is present.
        unsafe {
            env::remove_var("MINER_BLOCKS");
            env::remove_var("MINER_PREFETCH");
        }
        let bare = parse_line(&[]);
        assert_eq!(bare.get("MINER_BLOCKS", 3_u64), Ok(3));
        assert_eq!(bare.origin("MINER_BLOCKS"), Origin::Default);
        assert_eq!(bare.flag("MINER_PREFETCH", true), Ok(true));
        assert_eq!(bare.origin("MINER_PREFETCH"), Origin::Default);
    }

    #[test]
    fn boolean_spellings_are_the_ones_a_shell_user_reaches_for() {
        // `MINER_PREFETCH=0` is how someone turns this off, and
        // `bool::from_str` would call it an invalid value. Read through a name
        // of its own so this stays independent of the environment test above.
        let _guard = test_env_lock();
        for (value, expected) in [
            ("1", true),
            ("0", false),
            ("true", true),
            ("FALSE", false),
            ("yes", true),
            ("off", false),
            (" on ", true),
        ] {
            // SAFETY: under the lock, and the name is this test's alone: it is
            // not registered, so no parse reads it.
            unsafe { env::set_var("MINER_FLAG_TEST_VALUE", value) };
            assert_eq!(
                read_env_flag("MINER_FLAG_TEST_VALUE", "MINER_FLAG_TEST_VALUE", !expected),
                Ok(expected),
                "{value} should read as {expected}"
            );
        }

        unsafe { env::set_var("MINER_FLAG_TEST_VALUE", "maybe") };
        assert!(read_env_flag("MINER_FLAG_TEST_VALUE", "MINER_FLAG_TEST_VALUE", true).is_err());

        unsafe { env::remove_var("MINER_FLAG_TEST_VALUE") };
        assert_eq!(
            read_env_flag("MINER_FLAG_TEST_VALUE", "MINER_FLAG_TEST_VALUE", true),
            Ok(true)
        );
    }

    #[test]
    fn a_config_file_takes_the_shapes_a_shell_would_source() {
        // Every line here is something `set -a; . rig.env` reads the same way,
        // and nothing this reader would have to guess about. The whole test is
        // from a string: no disk, and no environment.
        let text = "\
# a comment, and a blank line under it

  MINER_CHAIN=regtest
export MINER_BLOCKS=20\r
MINER_POOL_PASS=d=1
MINER_LOG='a path/with spaces'
MINER_ADDRESS=\"a double-quoted value\"
MINER_POOL=
";
        let file = ConfigFile::parse("rig.env", text).expect("a shell sources every line here");

        // The value, and the 1-based line it was on.
        let at = |name: &str| {
            file.entries
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("{name} should be in the file"))
        };
        // Indentation is the file's, and a comment is a whole line.
        assert_eq!(at("MINER_CHAIN"), ("regtest".to_string(), 3));
        // `export ` is ignored and CRLF reads as a plain line ending.
        assert_eq!(at("MINER_BLOCKS"), ("20".to_string(), 4));
        // Split at the first `=`, so a value keeps the `=` in it.
        assert_eq!(at("MINER_POOL_PASS"), ("d=1".to_string(), 5));
        // Both quote kinds, with the quotes gone.
        assert_eq!(at("MINER_LOG"), ("a path/with spaces".to_string(), 6));
        assert_eq!(
            at("MINER_ADDRESS"),
            ("a double-quoted value".to_string(), 7)
        );
        // An empty value is a value: the empty string, not a missing one.
        assert_eq!(at("MINER_POOL"), ("".to_string(), 8));
    }

    #[test]
    fn a_config_file_refuses_every_shape_a_shell_would_read_differently() {
        // Every refusal names the line it was on and the key it was about,
        // which is what makes a misspelling findable in a file of thirty lines.
        let refused = |text: &str| ConfigFile::parse("rig.env", text).expect_err("this is refused");
        let on_line = |text: &str, number: usize| {
            let error = refused(text);
            assert!(
                error.starts_with(&format!("rig.env:{number}: ")),
                "wrong place for: {error}"
            );
            error
        };

        // No `=`, so there is nothing to assign.
        let error = on_line("MINER_BLOCKS\n", 1);
        assert!(error.contains("MINER_BLOCKS"), "{error}");

        // Whitespace around `=` is a command to a shell rather than an
        // assignment, and its key is not a name this binary knows.
        let error = on_line("MINER_CHAIN = regtest\n", 1);
        assert!(error.contains("MINER_CHAIN"), "{error}");

        // A misspelling, refused exactly as `--chian` is on the line.
        let error = on_line("MINER_CHIAN=regtest\n", 1);
        assert!(error.contains("MINER_CHIAN"), "{error}");

        // A repeat, naming the line the first one was on.
        let error = on_line("MINER_CHAIN=regtest\nMINER_CHAIN=signet\n", 2);
        assert!(
            error.contains("MINER_CHAIN") && error.contains("line 1"),
            "{error}"
        );

        // One file per run, so a file cannot name another.
        let error = on_line("MINER_CONFIG=other.env\n", 1);
        assert!(error.contains("MINER_CONFIG"), "{error}");

        // `$`, a backtick and a backslash are how a shell reaches outside the
        // text, and this reader does not follow it there.
        for reached_outside in ["a$b", "a`b", "a\\b"] {
            let error = on_line(&format!("MINER_CHAIN={reached_outside}\n"), 1);
            assert!(error.contains("MINER_CHAIN"), "{error}");
        }

        // An unquoted space would run a command under `set -a; .`.
        let error = on_line("MINER_CHAIN=a b\n", 1);
        assert!(error.contains("MINER_CHAIN"), "{error}");

        // Both halves of the quote rule: one that never closes, and one that
        // is not a single quoted word.
        for unmatched in ["'regtest", "regtest'", "'reg'test'", "a'b'"] {
            let error = on_line(&format!("MINER_CHAIN={unmatched}\n"), 1);
            assert!(error.contains("MINER_CHAIN"), "{error}");
        }
    }

    #[test]
    fn a_config_file_beats_the_default_and_is_beaten_by_the_line() {
        let _guard = test_env_lock();
        let file = "MINER_BLOCKS=5\nMINER_DEVICE=gpu\nMINER_PREFETCH=0\n";

        // The file over the compiled-in default, for a value and for a boolean.
        let from_file = parse_with_files(&["--config", "rig.env"], &[("rig.env", file)])
            .expect("the file is read");
        assert_eq!(from_file.get("MINER_BLOCKS", 0_u64), Ok(5));
        assert_eq!(from_file.flag("MINER_PREFETCH", true), Ok(false));
        assert_eq!(from_file.origin("MINER_BLOCKS"), Origin::File);
        assert_eq!(from_file.origin("MINER_PREFETCH"), Origin::File);
        // A value from a file keeps its variable name, because that is how it
        // is written in the file and where the reader would go to change it.
        assert_eq!(from_file.label("MINER_BLOCKS"), "MINER_BLOCKS");

        // The line over the file, for both shapes of setting.
        let flagged = parse_with_files(
            &["--config", "rig.env", "--blocks", "9", "--prefetch"],
            &[("rig.env", file)],
        )
        .expect("the file is read");
        assert_eq!(flagged.get("MINER_BLOCKS", 0_u64), Ok(9));
        assert_eq!(flagged.flag("MINER_PREFETCH", false), Ok(true));
        assert_eq!(flagged.origin("MINER_BLOCKS"), Origin::Flag);
        assert_eq!(flagged.origin("MINER_PREFETCH"), Origin::Flag);
    }

    #[test]
    fn a_file_value_is_named_where_it_came_from() {
        let _guard = test_env_lock();

        // An invalid value names the file and the line, which is what makes a
        // bad one findable in a file of thirty.
        let file = "# a comment\n\nMINER_GPU_LANES=lots\n";
        let settings =
            parse_with_files(&["--config", "rig.env"], &[("rig.env", file)]).expect("it parses");
        let error = settings
            .get("MINER_GPU_LANES", 0_u64)
            .expect_err("`lots` is not a number");
        assert!(
            error.contains("MINER_GPU_LANES has an invalid value in rig.env:3: lots"),
            "{error}"
        );

        // An empty value is the empty string rather than the default, since
        // that is what an empty variable already means.
        let settings = parse_with_files(&["--config", "rig.env"], &[("rig.env", "MINER_POOL=\n")])
            .expect("it parses");
        assert_eq!(
            settings.get("MINER_POOL", "default".to_string()),
            Ok(String::new())
        );
    }

    #[test]
    fn one_config_file_per_run() {
        let _guard = test_env_lock();

        // A second `--config` replaces the first rather than being merged with
        // it, so a key only the first file set falls back to its default.
        let settings = parse_with_files(
            &["--config", "first.env", "--config", "second.env"],
            &[
                ("first.env", "MINER_BLOCKS=5\nMINER_DEVICE=gpu\n"),
                ("second.env", "MINER_BLOCKS=9\n"),
            ],
        )
        .expect("the second file is read");
        assert_eq!(settings.get("MINER_BLOCKS", 0_u64), Ok(9));
        assert_eq!(
            settings.get("MINER_DEVICE", "cpu".to_string()),
            Ok("cpu".to_string())
        );

        // Empty means off, as it does for `MINER_POOL`. This is how to drop a
        // wrapper's file.
        let settings = parse_with_files(&["--config", ""], &[("v1.env", "MINER_BLOCKS=5\n")])
            .expect("no file");
        assert_eq!(settings.get("MINER_BLOCKS", 0_u64), Ok(0));
        assert_eq!(settings.origin("MINER_BLOCKS"), Origin::Default);
    }

    #[test]
    fn a_named_config_file_that_cannot_be_read_is_refused() {
        let _guard = test_env_lock();

        // A file that was asked for and silently skipped would run a
        // configuration nobody asked for.
        let error = parse_with_files(&["--config", "missing.env"], &[])
            .expect_err("a named file that is missing is refused");
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(
            error.to_string().contains("missing.env"),
            "the path should be named: {error}"
        );

        // And one that is there but broken is refused the same way, naming the
        // line rather than being read as though it were not in the file.
        let error = parse_with_files(&["--config", "bad.env"], &[("bad.env", "MINER_CHIAN=x\n")])
            .expect_err("a misspelled key is not a setting");
        assert!(
            error.to_string().contains("bad.env:1"),
            "the line should be named: {error}"
        );
    }

    #[test]
    fn help_is_answered_before_any_file_is_read() {
        let _guard = test_env_lock();

        // `./m --help` has to work while MINER_CONFIG points at a broken file,
        // because answering is what it is for.
        let error = parse_with_files(&["--help"], &[]).expect_err("help is an answer");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("--config"), "{error}");

        let error = parse_with_files(&["--config", "missing.env", "--help"], &[])
            .expect_err("help is still an answer");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn a_config_file_is_summarised_with_the_keys_that_beat_it() {
        let _guard = test_env_lock();

        // The file is named, and so is every key something else won — the
        // listing of every key would only repeat the file.
        let file = "MINER_BLOCKS=5\nMINER_DEVICE=gpu\nMINER_WORKERS=8\n";
        let settings = parse_with_files(
            &["--config", "v2.env", "--device", "cpu"],
            &[("v2.env", file)],
        )
        .expect("the file is read");
        assert_eq!(
            settings.config_summary().as_deref(),
            Some("config: 3 settings from v2.env; MINER_DEVICE overridden by --device")
        );

        // And nothing at all is said when no file was read.
        assert_eq!(parse_line(&[]).config_summary(), None);
    }

    #[test]
    fn sample_env_and_the_registry_are_one_list() {
        // The sample is the third of the three that hold the registry to what
        // is beside it. Read at run time rather than through `include_str!`,
        // which Cargo tracks by timestamp: an edit that preserves the mtime
        // would leave a stale copy compiled in and this test passing on it.
        let sample = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/sample.env"))
            .expect("sample.env is beside Cargo.toml");

        // As it stands the sample changes nothing, which is what every line
        // being commented out is for — and what makes it safe to leave lying
        // in the directory `./m` runs from.
        assert!(
            ConfigFile::parse("sample.env", &sample)
                .expect("the sample parses")
                .entries
                .is_empty(),
            "the sample should set nothing"
        );

        let lines: Vec<&str> = sample.lines().collect();
        let mut documented: Vec<(&str, String, &str)> = Vec::new();

        for (index, line) in lines.iter().enumerate() {
            // An assignment is `# MINER_X=value`. A help line that happens to
            // begin `# MINER_` carries no `=` of its own and is not one.
            let Some(assignment) = line.strip_prefix("# ") else {
                continue;
            };
            let Some((name, value)) = assignment.split_once('=') else {
                continue;
            };
            if !name.starts_with("MINER_") {
                continue;
            }

            // Each assignment, uncommented on its own, is a line a file may
            // hold. That catches a default a file cannot express — one with a
            // space or a `$` in it, say.
            let one = ConfigFile::parse("sample.env", &format!("{assignment}\n"))
                .unwrap_or_else(|error| panic!("{assignment} is not a line a file holds: {error}"));
            let keys: Vec<String> = one.entries.keys().map(|key| key.to_string()).collect();
            assert_eq!(keys, [name], "{assignment} should set exactly one thing");

            // The comment block directly above, joined with spaces, is exactly
            // that setting's help. Wrapping lines is free; rewording is not.
            let mut block: Vec<&str> = Vec::new();
            for above in lines[..index].iter().rev() {
                let Some(text) = above.strip_prefix('#') else {
                    break;
                };
                block.push(text.trim());
            }
            block.reverse();

            documented.push((name, block.join(" "), value));
        }

        // The names, in order, are the registry's minus MINER_CONFIG, which a
        // file cannot hold.
        let names: Vec<String> = documented
            .iter()
            .map(|(name, _, _)| name.to_string())
            .collect();
        let registered: Vec<String> = registry()
            .iter()
            .map(|setting| setting.env.to_string())
            .filter(|env| env != "MINER_CONFIG")
            .collect();
        assert_eq!(names, registered, "sample.env and the registry differ");

        // Three settings are left blank rather than filled in: one the machine
        // decides at startup, and two that would put one person's address and
        // one machine's path into a file meant to be copied. A default that is
        // itself empty is blank for free.
        let left_blank = ["MINER_ADDRESS", "MINER_BITCOIND_DATADIR"];

        for (name, help, value) in documented {
            let setting = registry()
                .iter()
                .find(|setting| setting.env == name)
                .unwrap_or_else(|| panic!("{name} is in sample.env and not in the registry"));
            assert_eq!(help, setting.help, "{name} documents the wrong help");

            let expected = match &setting.fallback {
                Fallback::Derived(_) => String::new(),
                Fallback::Value(_) if left_blank.contains(&name) => String::new(),
                Fallback::Value(compiled_in) => compiled_in.clone(),
            };
            assert_eq!(
                value, expected,
                "{name} documents a default that is not the one compiled in"
            );
        }
    }
}
