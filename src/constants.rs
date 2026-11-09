//! Compiled-in defaults for a run. Nearly every one of these is overridable
//! twice over: by the environment variable of the same name, and by the flag
//! derived from it — `MINER_GPU_LANES` is `--gpu-lanes`, and `./m --help` or
//! `README.md` prints the whole table. A flag beats the variable, which beats a
//! config file named by `--config`, which beats the value here, so this file is
//! where a default is *explained* rather than where a one-off run is configured.
//! It is also the only place a default lives: `settings.rs` names these for the
//! help text and never restates them.

/// Where the append-only log and any result files are written.
pub const RESULTS_DIR: &str = "results";

// --- Mining Parameters ---

/// Bitcoin Core's datadir, which is where the RPC cookie is read from. No
/// password is ever configured: the cookie is the only credential path this
/// miner has.
///
/// `~/.bitcoin` is Bitcoin Core's own default on Linux. A leading `~` is
/// expanded to the home directory wherever this is set from, so a config file
/// can say `~/.bitcoin` too.
pub const MINER_BITCOIND_DATADIR: &str = "~/.bitcoin";

/// Mining payout address. The miner sends every block's coinbase to this
/// address.
///
/// testnet4: tb1qh8gqvwfyvmtuul7t2c0qdrfemrtwq4l6hgqy8n
pub const MINER_ADDRESS: &str = "bc1qa0wd8gy8vtgj3vs2e5emzv7lnmfdf9e8nfq8ug";

/// The messages this miner writes into the coinbase scriptSig, after the BIP34
/// height and the extranonce. One is chosen per template, rotating through the
/// list in order; an empty list, or an empty entry, writes nothing.
///
/// These messages are added by [`crate::block::wrap_coinbase_tag`] when
/// the coinbase is built.
///
/// Everything past the height is free-form — the coinbase input is never
/// executed as a script, so the node treats these bytes as opaque data. That is
/// what the genesis block's headline and every pool's `/Slush/` tag are, and if
/// this miner ever wins a block the bytes are in the chain permanently, readable
/// as ASCII in any explorer.
///
/// The rotation is [`crate::block::coinbase_tag_name_for`], which
/// indexes this by the height plus the number of templates the run has already
/// ground at that height. The height alone was the index once, which made the
/// tag reproducible from the chain — but a mainnet height is dozens of
/// templates abandoned for better work, and one tag would have covered all of
/// them. A won block still says which entry it carried; the height no longer
/// predicts it.
///
/// Each entry has [`crate::block::COINBASE_TAG_MAX`] bytes to spend,
/// less the two delimiters, checked at compile time: the whole scriptSig is
/// capped at 100 bytes by consensus and the height and extranonce spend some of
/// it.
pub const MINER_COINBASE_TAGS: [&str; 6] = ["SZ", "MA", "MU", "HA", "YF", "AO"];

/// The prefix that is prepended to every tag, which is what makes the coinbase
/// say who mined the block rather than only which name the rotation was on.
/// [`crate::block::wrap_coinbase_tag`] writes it between the delimiters, so
/// this and the tag together have to fit the budget described above.
pub const MINER_COINBASE_TAG_PREFIX: &str = "Mined by PuntoMiner. Hit by ";

/// Chain the reference miner works against: `main`, `testnet4`, `signet` or
/// `regtest`.
///
/// Regtest is the chain to develop against — it is the only one where a wrong
/// coinbase comes back as a named rejection in milliseconds — but the default
/// is `main`, because the modes that submit nothing and ask a real chain a
/// question (`validate`, `lottery`) are what a default run is usually pointed
/// at. Note what that makes a bare `MINER_MODE=mine`: mainnet, until Ctrl-C.
/// Only `rejections` and `reorg` are refused off regtest; mining is not,
/// because a mainnet block is the point of it.
pub const MINER_CHAIN: &str = "main";

/// Blocks to mine before stopping; zero mines until the user exits.
pub const MINER_BLOCKS: u64 = 0;

/// What a run does: `mine` produces blocks, `bench` measures the search rate
/// against an unreachable target and submits nothing, `probe` checks the shader
/// against `rust-bitcoin` without a node, and `watch` follows the node's
/// template through its longpoll without mining at all.
pub const MINER_MODE: &str = "mine";

/// A compact target to grind to instead of the template's, as four hex bytes.
/// Empty means the node's own target.
///
/// It may only be harder than the chain's, which keeps every block it produces
/// valid — a header that meets a harder target meets the easier one too. What
/// it buys is a search long enough to watch: at regtest difficulty a block
/// arrives in milliseconds, and nothing about stale templates, longpolls or
/// abandoned work can be observed in that time. `1d00ffff` is difficulty 1,
/// about ten seconds of the GPU.
pub const MINER_BITS: &str = "";

/// Duration of a benchmark run, in seconds.
pub const MINER_BENCH_SECONDS: u64 = 10;

/// Which implementation walks the nonce space: `auto` picks the fastest this
/// CPU can run, `naive` is `rust-bitcoin`'s per-nonce `block_hash()` with no
/// midstate, and `portable` and `sha-ni` are the two compression functions
/// behind the midstate hasher. The three exist so a speedup can say which
/// baseline it beat.
pub const MINER_HASHER: &str = "auto";

/// How much of the machine the CPU search takes, as two percentages: how many
/// cores it spreads over, and how hard it works each one.
///
/// The first sets the default `MINER_WORKERS` — 50 puts a worker on half the
/// logical cores — and the second is a duty cycle: each worker hashes for that
/// share of every
/// [`MINER_CPU_THROTTLE_WINDOW_MILLISECONDS`] window and sleeps the rest, which
/// is what keeps a laptop usable while a search runs. `MINER_CPU_PERCENT`
/// overrides the duty cycle for one run.
///
/// Both are the CPU search only. The GPU has its own, [`MINER_GPU_PERCENT`],
/// and is not throttled by either, so on `MINER_DEVICE=hybrid` these govern the CPU half alone — and there they buy
/// nothing but quiet. Measured on a laptop, the two devices share one package
/// power budget, which invites the idea that
/// giving the CPU's share back would speed the card up; measured, it does not.
/// Across 100/75/50/25% the GPU half moves 430.7 to 433.8 MH/s — 0.7%, inside
/// the noise — while the total falls from 712 to 530, because the card is
/// already at its own ceiling at 2490 MHz rather than short of power. The trade
/// runs one way.
///
/// The cost of asking is honest either way: a throttled worker's sleep is inside
/// the wall clock a run divides by, so a run at 50% reports about half the rate
/// rather than the same rate over fewer hashes. Measured on the CPU alone,
/// 100/50/25% gives 370, 207 and 113 MH/s — a little above each nominal share,
/// since a core that idles part of every window boosts higher for the rest of
/// it.
pub const MINER_CPU_CORES_USAGE_PERCENT: u8 = 80;
pub const MINER_CPU_LOAD_PERCENT: u8 = 75;

/// The window a duty cycle is spread over. A worker checks the clock every
/// 65,536 nonces — about 6 ms at this hardware's per-worker rate — so a window
/// this size divides into fine enough slices to hit the requested percentage,
/// while bounding how long a sleeping worker takes to notice a Ctrl-C.
pub const MINER_CPU_THROTTLE_WINDOW_MILLISECONDS: u64 = 100;

/// Where the nonce search runs: `cpu`, `gpu`, or `hybrid` — both at once.
///
/// **`gpu` by default since the shader's rounds were written out.** Writing
/// them out instead of looping took the card from 431 to about 2,393 MH/s, and
/// `hybrid` now adds +5.9%: 2,536 MH/s, of which the CPU's 197 is 7.8%. It also
/// holds the CPU package at 97–100 °C, where `gpu` alone leaves it at 63–67 °C.
/// A default that breaks AGENTS.md's temperature rule for 6% is the wrong
/// trade. `hybrid` is one flag away for anyone who wants every hash.
///
/// The rest of this note is the measurement that made `hybrid` the default
/// before then, kept because it is why the device exists at all.
///
/// `hybrid` grinds one template on the two devices simultaneously, half the
/// extranonce space apart so that neither re-hashes the other's headers, and
/// stops the loser the moment either wins. It was worth having here only because
/// this machine's two devices were the same size: 431 MH/s of RTX 4070 against
/// 354 of a 32-thread i9 with SHA-NI, where the usual mining rig's CPU is a
/// rounding error against its cards.
///
/// Measured by interleaving the two arms, which this has to be — a cold cpu-only
/// run reads 19% above a warm one: **686 MH/s together against the GPU's 431**,
/// or 1.59x.
///
/// The cost falls entirely on the CPU, and it is clock rather than contention.
/// The GPU keeps all 431; the CPU walks 256 where it walks 354 alone, at the same
/// ~0.100 MH/s per MHz in both cases — it is running at 2.5 GHz instead of 3.5
/// because the two devices share one package power budget. Cutting
/// `MINER_GPU_LANES` eightfold gives none of it back, which is what says the
/// shader's memory traffic is not what is taking it.
pub const MINER_DEVICE: &str = "gpu";

/// Lanes the GPU search runs in parallel, and nonces each lane walks per
/// dispatch. One dispatch is `lanes * nonces` of the 32-bit nonce space, so the
/// two together cannot exceed it. Lanes is the knob that matters here: 4,096 to
/// 262,144 lanes moves the rate from 214 to 434 MH/s, while nonces per lane
/// past a few hundred buys nothing. Mining is memory-trivial — a midstate, a
/// block and a target — so the card is short of parallelism rather than of
/// anything else. One dispatch at these defaults is 67 million nonces. That was
/// about 155 ms when this was tuned; since the rounds were written out it is
/// about 28 ms, below the 100–500 ms band a GPU search usually aims for. The
/// sweep was redone for that shader rather than assumed: 1,024 nonces per lane
/// or up to four times the lanes reach 2,406–2,409 MH/s against 2,388–2,404
/// here, inside the spread between repeated runs, so the defaults stand. A
/// larger dispatch would also quadruple the probe's single-threaded CPU pass
/// and put its expected winners at the edge of `MINER_GPU_CAPACITY`. Measured
/// on an RTX 4070 Laptop over Vulkan, NVIDIA driver 595.
pub const MINER_GPU_LANES: u32 = 262_144;
pub const MINER_GPU_NONCES: u32 = 256;

/// The GPU's duty cycle: the share of the time the card
/// spends walking nonces, the rest spent idle. 100 is the card flat out, which
/// is what every GPU rate quoted during development was measured at.
///
/// A dispatch cannot be paused, so the card rests between dispatches and only
/// once nothing is queued: it works until it has used its share of a
/// [`MINER_GPU_THROTTLE_WINDOW_MILLISECONDS`] window and then sleeps in
/// proportion to what it did. Like the CPU's, the sleep is inside the wall
/// clock a run divides by, so a run at 50% reports about half the rate.
/// It throttles the block and share searches, on `gpu` and on the GPU half of
/// `hybrid`; the probe and the lottery run flat out.
pub const MINER_GPU_PERCENT: u8 = 100;

/// The window the GPU's duty cycle is spread over. Longer than the CPU's
/// because the unit of work is a whole dispatch, about 28 ms at the default
/// size, and every rest costs the pipeline a drain: this is about 27
/// dispatches of work between rests at 75%.
pub const MINER_GPU_THROTTLE_WINDOW_MILLISECONDS: u64 = 1_000;

/// Dispatches allowed in flight at once. Two lets the host read one dispatch's
/// winners back while the card is already walking the next span, through
/// alternating dispatch slots; one submits and waits, and exists so the
/// difference between them can be measured rather than assumed.
pub const MINER_GPU_PIPELINE: u32 = 2;

/// Winners one dispatch may record.
///
/// Overflowing this is not an error for a block search: every winner is equally
/// a block and only one can be submitted. At regtest difficulty roughly half of
/// all nonces win, so a full dispatch overflows this immediately and correctly.
/// The probe, which compares whole winner sets, is the caller that treats
/// overflow as fatal.
pub const MINER_GPU_CAPACITY: u32 = 4_096;

/// Timeout for every RPC call, in seconds. `getblocktemplate` on a busy
/// mainnet node is the slow one and still answers well inside this.
pub const RPC_TIMEOUT_SECONDS: u64 = 30;

/// Timeout for a longpoll, which the node is expected to hold open. Core
/// answers within a minute — immediately on a new tip, otherwise on its own
/// timer once the mempool has changed — so anything past this is the node
/// having gone away rather than the chain being quiet.
pub const MINER_LONGPOLL_SECONDS: u64 = 120;

/// How long to wait before retrying a longpoll that failed. A failure costs
/// only the early warning: the miner keeps working, it just stops being told
/// when its template is superseded.
pub const MINER_LONGPOLL_RETRY_SECONDS: u64 = 5;

/// Whether a longpoll's own answer is mined, rather than discarded and
/// refetched.
///
/// The answer to a longpoll *is* a full `getblocktemplate` response, so the
/// template that replaces a stale one is already in hand the moment the search
/// is told to stop. Refetching it costs a second round trip while nothing is
/// hashing — 54 to 55 ms on this host against a 60 s longpoll cycle, or 0.09% of
/// the hashrate.
///
/// That is worth having but it is not worth much, and the honest reason to keep
/// the switch is the other direction: off restores the discard-and-refetch path,
/// which is what makes the difference measurable rather than asserted.
pub const MINER_PREFETCH: bool = true;

/// Whether a GPU block search may roll the template's version, inside the bits
/// [`Template::rollable_bits`](crate::template::Template::rollable_bits) leaves
/// free, and hash two versions per nonce through `search_pair` — AsicBoost on
/// the solo search.
///
/// **On, although it changes the version the node handed out.** It was
/// opt-in until the evidence was in, and was turned on by default on
/// 2026-11-06. By then 95% of mainnet's blocks already rolled these bits, and
/// Core v31.1 had accepted a rolled block in proposal mode. A solo miner's
/// blocks are also far too few to move any bit towards Core's unknown-rules
/// warning. See `docs/architecture.md`.
/// `--no-template-version-rolling` mines the template's own version.
///
/// It stays a separate name from `MINER_VERSION_ROLLING`, which is BIP310's
/// negotiation with a pool and a different decision.
pub const MINER_TEMPLATE_VERSION_ROLLING: bool = true;

/// The reporting threshold `MINER_MODE=lottery` counts digests against, as
/// compact bits. It is not a target anything is mined to: at difficulty 1/256
/// a digest beats it roughly every 17 million hashes, which is what gives a
/// short run enough samples to say anything about the distribution. Mainnet's
/// real target is around 10^14 times harder.
pub const MINER_LOTTERY_BITS: u32 = 0x1e00_ffff;

/// How long a template may be ground before it is refetched, in seconds; zero
/// waits for the longpoll and nothing else.
/// This exists for testnet4, where the only winnable blocks appear when the
/// min-difficulty window opens twenty minutes after the previous one. That is
/// the clock advancing, not an event: no longpoll fires for it, so a miner that
/// refetches only when told to would grind the 1.7-billion-difficulty target
/// straight through the window it could have won.
pub const MINER_TEMPLATE_SECONDS: u64 = 0;

/// Where the extranonce walk begins: `auto`, a decimal `u64`, or a `0x`-prefixed
/// hex one. Zero is the default, and every development figure was measured
/// with it.
///
/// This does not change the odds of a block, and nothing can. Every digest is an
/// independent draw, and this miner's headers are already disjoint from every
/// other miner's — the coinbase pays to our address, so our merkle root is ours
/// alone and extranonce 0 here collides with no pool's extranonce 0.
///
/// What a non-zero start avoids is duplicating *our own* work: two instances
/// sharing one `MINER_ADDRESS` on the same template walk byte-identical headers
/// from zero, and half the hashing is wasted. `auto` derives a start no other
/// instance is likely to share and logs it, so a run stays repeatable by passing
/// the logged number back in.
pub const MINER_EXTRANONCE_START: &str = "0"; // "0", "auto"

// The Stratum V1 pool client, `MINER_MODE=stratum`. Every one of these is inert
// unless that mode is asked for, and `MINER_POOL` is empty so that a miner
// never opens a socket to a stranger without being told to.

/// The pool to mine for, as `host:port`. Empty means off, and there is no
/// default pool: asking for `MINER_MODE=stratum` without saying where is a
/// configuration mistake rather than an invitation to pick one.
pub const MINER_POOL: &str = "";

/// The whole worker name to authorize as, conventionally `<address>.<worker>`.
///
/// Empty, which builds it instead from [`MINER_ADDRESS`] and
/// [`MINER_POOL_WORKER`]: the address is where a found block pays and the
/// suffix is which machine found it, and both of those are already configured.
/// Setting this takes the name over entirely — for a pool whose username is not
/// an address, or a payout that is not the one blocks are mined to.
///
/// It is not a credential. A Stratum username is a payout address and a label,
/// both public by construction — the pool has to know where to credit, and an
/// address on its own is what a block explorer shows anyway.
///
/// **[`MINER_ADDRESS`] is a mainnet address**, so a run against a pool on
/// another chain has to override one of the two or the pool will refuse to
/// authorize: a regtest pool wants a `bcrt1` one.
pub const MINER_POOL_USER: &str = "";

/// The worker half of that default name: the `<worker>` in `<address>.<worker>`,
/// which is how a pool dashboard tells two machines apart.
///
/// `puntominer` because the name is measured under. Every live pool figure
/// taken during development was taken under it, and
/// Pool A's dashboard still reports it as `worker: puntominer`,
/// so a run that reproduces those numbers reproduces them under the same name.
/// That is why it stayed lowercase when the rest of the name became
/// `PuntoMiner`: a pool's history is keyed on this string, and renaming it
/// starts a second worker beside the one holding every measurement.
///
/// Empty falls back to this machine's hostname, which is what to want when one
/// configuration runs on several machines — a name compiled into the binary
/// cannot tell those apart, and a hostname can.
///
/// A dot is a field separator to a pool, so this may hold only letters, digits,
/// dashes and underscores, and anything else is refused at startup rather than
/// quietly mangled on the way out. [`MINER_POOL_USER`] is where a name outside
/// that belongs. The hostname is filtered rather than refused, since nobody
/// chose it for this.
pub const MINER_POOL_WORKER: &str = "puntominer";

/// The password field, which on a solo pool is not a password.
///
/// `d=1` rather than the customary `x` because it is measured: Pool A's
/// default share difficulty is 512, which at this hardware's rate is one share
/// every 49 minutes — indistinguishable from a hung socket. One pool in three
/// reads a difficulty out of this field, so it is one of the two levers sent.
pub const MINER_POOL_PASS: &str = "d=1";

/// The share difficulty to ask for, sent by `mining.suggest_difficulty` **and**
/// in [`MINER_POOL_PASS`].
///
/// Both, because neither lever works everywhere: of the three pools measured,
/// `suggest_difficulty` moved two and `d=` moved one. A share every few seconds
/// is what makes a reject rate mean anything within a run.
///
/// **Under Stratum V2 the same number points the other way.** It becomes the
/// channel's `max_target`, which is a ceiling on the *target* and therefore a
/// floor under the *difficulty*: it says "nothing easier than this", which
/// every harder target already satisfies. A V2 pool can honour a request for
/// difficulty 1 by serving 512 and Pool A does. Lowering a V2 difficulty
/// is [`MINER_POOL_HASHRATE`]'s job, not this one's.
pub const MINER_POOL_DIFFICULTY: f64 = 1.0;

/// The user agent announced in `mining.subscribe`.
///
/// Honest, and not an imitation of a miner this is not. A pool that wants to
/// treat an unknown client differently is entitled to, and a client that lies
/// about what it is makes every measurement taken through it unreliable.
///
/// The development measurements were taken before the rename and are recorded
/// under `puntominer/0.1`, which is the same client under the same behaviour
/// and differs only in how it spells its name. [`MINER_POOL_USER`] was
/// deliberately *not* renamed with it — see there.
pub const MINER_POOL_AGENT: &str = "puntominer/0.1";

/// How long to wait before reconnecting after the pool drops the connection.
///
/// Reconnect is normal rather than exceptional — pools drop idle sockets and
/// restart — so this is a pause, not a retry budget. A reconnect refetches
/// everything, because the new `extranonce1` invalidates every job in flight.
pub const MINER_POOL_RECONNECT_SECONDS: u64 = 5;

/// Which protocol the pool speaks: `v1` or `v2`.
///
/// **This cannot be discovered and a wrong guess is a hang.** Pool A
/// serves both on one port and tells them apart from the first bytes a
/// client sends — a V1 session opens with `{`, an SV2 session with 64 bytes
/// of ElligatorSwift-encoded public key — so a client that guessed wrongly
/// sits waiting for the other side to say something it would recognise, and
/// so does the other side.
///
/// `v1` because that is what every development measurement was taken under and
/// what every pool serves. The easier way to ask for the other one is to
/// paste the URL the pool publishes into [`MINER_POOL`]: a
/// `stratum2+tcp://host:port/<key>` names the protocol, the host, the port
/// and the authority key at once.
pub const MINER_POOL_PROTOCOL: &str = "v1"; // "v1", "v2"

/// The pool authority key an SV2 server's certificate must verify under,
/// as base58check or as 64 hex characters.
///
/// **Empty refuses to connect to anything that is not on the loopback**,
/// checked before a socket is opened, beside the regtest gate and the
/// `MINER_VERSION_ROLLING=force` gate and for the same reason those are
/// there. A pool that publishes its key and a client that ignores it is the
/// whole authentication story thrown away for one line of convenience, and
/// there is deliberately no trust-on-first-use path.
///
/// **Not a credential**, so unlike [`MINER_POOL_PASS`] it may be a flag: a
/// pool publishes this precisely so that miners pin it, usually as both 64
/// hex characters and the base58check string in its `stratum2+tcp://` URL.
pub const MINER_POOL_AUTHORITY: &str = "";

/// The hash rate to claim in `OpenExtendedMiningChannel`, in hashes a second.
///
/// SV2's `nominal_hash_rate`, which V1 has no field for. **It is the only
/// lever that can lower a V2 share difficulty**, because the other field in
/// that message is a ceiling: [`MINER_POOL_DIFFICULTY`] becomes `max_target`,
/// which can only ask for harder work. The server sizes the target from this
/// number instead, so a client that claims nothing gets whatever default the
/// pool has — 512 from Pool A, which at this hardware's rate is one share
/// an hour.
///
/// Zero claims nothing, which is the honest default for a client that has not
/// measured itself yet — and after one job it has, which is what the single
/// `UpdateChannel` a session sends is for. This hardware's measured hybrid
/// rate is about 6.9e8, and a run that wants to say so up front can.
pub const MINER_POOL_HASHRATE: f64 = 0.0;

/// A file to record every Stratum V2 frame of a session to, in plaintext.
///
/// Empty records nothing. Under Noise there is no wire capture to take, so
/// this is the plaintext one: each frame the pool sends, after its tag has
/// verified and before anything parses it, and each frame this client sends,
/// one hex line apiece. It holds nothing from the handshake and nothing
/// secret, which is what lets a capture become a committed fixture.
/// Refused under V1, whose wire is already readable.
pub const MINER_POOL_CAPTURE: &str = "";

/// Whether to use BIP310 version rolling: `auto`, `off` or `force`.
///
/// `auto` rolls the bits the pool's `mining.configure` reply agreed to, and
/// rolls nothing if it agreed to none. `off` never rolls and never sends the
/// sixth `mining.submit` parameter, which is what every client did before 2018.
///
/// **`force` rolls bits the pool did not agree to, and is refused against any
/// pool that is not on the loopback.** It exists for one purpose: a pool should
/// reject a share whose version bits fall outside the negotiated mask, and an
/// assertion nothing can violate is an assertion nothing has tested. Pointing
/// that at a stranger's production pool is not a test, it is sending
/// deliberately bad shares to somebody else's server.
pub const MINER_VERSION_ROLLING: &str = "auto";
