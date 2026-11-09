# PuntoMiner contributor guide

## Behavioral guidelines

Guidelines to reduce common LLM coding mistakes. They bias toward caution over speed — for trivial tasks, use judgment.

- **Think before coding.** State assumptions; if uncertain or something is unclear, ask. Present competing interpretations instead of picking one silently; if a simpler approach exists, say so.
- **Simplicity first.** Minimum code that solves the problem — no unrequested features, no abstractions for single-use code, no speculative "flexibility". If a senior engineer would call it overcomplicated, simplify.
- **Surgical changes.** Small, focused changes; every changed line traces to the request. Don't "improve" or refactor adjacent code; match existing style. Remove orphans *your* change created; mention — don't delete — pre-existing dead code.
- **Goal-driven execution.** Turn tasks into verifiable goals ("fix the bug" → a test that reproduces it, then make it pass; "refactor X" → tests pass before and after); for multi-step work, state a brief step→verify plan.
- **Never commit without an explicit request.** `git commit`, `git push`, and anything else that rewrites history or publishes need the user's say-so in the current request. Stage edits freely and say what is ready; approval for one commit is not approval for the next.

## Layout

PuntoMiner is a Bitcoin miner. Solo, it builds a block from a node's
`getblocktemplate` and grinds the header on the CPU, the GPU, or both. For a
pool, the Stratum V1 and V2 clients take work over a socket and submit shares
instead of blocks.

`docs/README.md` indexes `user-guide.md` (running it), `architecture.md` (how it
is built) and `developer-guide.md` (changing it); `tests/fixtures/README.md`
gives each capture's provenance. The docs describe the software as it is: plans,
roadmaps and measurement logs are not kept here. A new document goes in `docs/`
with a row in the index.

`src/`:

- `constants.rs` — every compiled-in default. `settings.rs` — the registry of
  settings and the `clap` command built from it. `runner.rs` — configuration,
  mode dispatch, and the mining and benchmark loops.
- `rpc.rs` — hand-rolled HTTP/1.1 JSON-RPC to the loopback, cookie-authenticated,
  adding no dependency. `Chain` owns each network's RPC port and datadir
  subdirectory.
- `template.rs` — `getblocktemplate` parsed. `block.rs` — coinbase, merkle
  root, header, `check_block`, and `VersionRoll`, the version walk the solo and
  share searches share.
- `sha256.rs` — the midstate header hasher, portable and x86 SHA-NI. `cpu.rs` —
  the threaded search, `Hasher` selection, and the `Search` result.
- `gpu.rs`, `miner.wgsl` — the GPU search and its probe. The shader needs no
  `SHADER_INT64`; `gpu::unrolled_rounds` writes its rounds and appends them
  before compiling. `hybrid.rs` —
  both devices on one template, on disjoint extranonces.
- `watch.rs` — the longpoll watcher thread, and `Signals`/`Ending`.
- `rejections.rs`, `reorg.rs` — experiments that write blocks, regtest only.
  `validate.rs`, `lottery.rs` — experiments that submit nothing, for mainnet.
- `logger.rs`, `utils.rs` — the console/file log and its formatting helpers.
- `stratum/` — `MINER_MODE=stratum`, which contacts no node. Always compiled,
  inert until asked for. Shared by both protocols: `pool.rs` (configuration and
  the `MINER_POOL` URL parser), `search.rs` (the share searches, over
  `&dyn ShareJob`), `payout.rs` (who a job's coinbase pays). V1: `wire.rs` byte
  order, `messages.rs` JSON shapes, `conn.rs` socket and handshake, `job.rs`
  coinbase splice and share target, `run.rs` loop, and `fixture.rs`, which
  reads `tests/fixtures/` — real frames kept as strings, so parsers are checked
  against the wire.
- `stratum/v2/` — `MINER_POOL_PROTOCOL=v2`: `codec.rs` types, `frame.rs` header
  and message table, `noise.rs` `Noise_NX` and the certificate check, `conn.rs`
  socket and cipher states, `messages.rs` (twelve in, four out), `job.rs` job
  and prevhash to header, `run.rs` loop. `scripted.rs` is test-only: a pool that
  plays the cases no live server sends.

## Build and verification

Run from the repository root; paths resolve from the working directory. Every
setting is a `MINER_*` variable and a flag (drop `MINER_`, lowercase, dashes for
underscores); `./m --help` lists them.

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test          # no node, GPU or network; the wire against tests/fixtures/

# The miner on regtest. The default chain is main and the default address is a
# mainnet one, so name both.
bitcoind -regtest -daemon
bitcoin-cli -regtest createwallet dev   # once; `loadwallet dev` after a restart
ADDRESS=$(bitcoin-cli -regtest getnewaddress)
cargo run --release -- --chain regtest --address "$ADDRESS" --blocks 1 --log /tmp/miner.log

# The GPU shader and the longpoll, which the tests do not cover. probe needs no node.
cargo run --release -- --mode probe --log /tmp/miner.log
cargo run --release -- --chain regtest --mode watch --log /tmp/miner.log

# The pool clients, which need no node. V2 must pin the pool's authority key (the
# URL's path) for any pool that is not on the loopback.
cargo run --release -- --mode stratum --pool stratum.puntohunter.com:3333 --log /tmp/miner.log
cargo run --release -- --mode stratum --log /tmp/miner.log \
  --pool stratum2+tcp://stratum.puntohunter.com:3334/9bXjRXap8aHiDek6TrGe6mYqLiwMzpwmfbsy41yY9c5ED91Pza8

# Kept out of the suite: a live pool's first set_difficulty (needs the network),
# and the share search's rate against the block search's (timed, full CPU load).
cargo test --release stratum::conn::tests::a_live -- --ignored --nocapture
cargo test --release stratum::search::tests::the_share_search -- --ignored --nocapture

# The wrappers read m.env, v1.env and v2.env; ./v1 and ./v2 take an optional pool
# and address, then anything else. The last spelling of a setting wins.
./v1 127.0.0.1:3333 bcrt1q... --device cpu
./m --config sample.env --mode probe --log /tmp/miner.log   # the sample changes nothing
```

`cargo test` cannot cover what only a second pool disagrees about. Run the
client against a local pool on regtest (`docs/developer-guide.md`) before
believing a green mainnet run: that is what found the fatal cases.

**Keep the CPU's temperature in check.** Mining, benchmarks, timed measurements
and long sweeps can overheat the machine; on a laptop the CPU and GPU share one
power and thermal budget.

- Check `sensors` before starting and watch it during the run (plus
  `nvidia-smi` when the card is busy). Stop or lower the load if the package
  stays within 10 °C of its `high` limit.
- Start light and raise the load in steps: `--workers`, `--cpu-percent`,
  `--gpu-percent`, `--device cpu`. The default `gpu` leaves the CPU near idle;
  the CPU defaults (80% of the cores at a 75% duty cycle) still reach `high` on
  the reference laptop, so `--device cpu` or `hybrid` is full load. `probe` and
  `lottery` run the GPU flat out whatever `--gpu-percent` says.
- Ask before anything that holds full load for more than a few minutes, and let
  the machine cool to near idle between long runs.
- Heat costs clock, and clock is hash rate. Record the CPU clock beside any
  rate, and interleave compared runs instead of running them back to back.

## Rules that must survive any change

### Blocks

- **Check locally before submitting.** `check_block` states the height,
  commitment, merkle root, coinbase value, mintime and version rules, so a
  failure names the rule instead of arriving as `bad-cb-height`. The node stays
  the authority.
- **Read the tip back after `submitblock`.** Null means accepted, not best
  chain, and `inconclusive` is not a rejection: it is the answer for a valid
  block off the best chain. Trusting null and failing on any non-null are the
  same mistake.
- **The coinbase witness is the 32-byte reserved value, and the commitment is
  the template's `default_witness_commitment`.** Both are valid only for the
  template's transaction set; dropping or reordering a transaction means
  computing the witness merkle root.
  `validate.rs` alone recomputes the commitment from the block's own wtxids —
  the only check that it is right rather than merely present — so do not
  "simplify" it into reusing the template's.
- **Timestamps are honest:** `curtime.max(mintime)`. Stamping the parent's time
  plus 1201 to open testnet4's min-difficulty window is consensus-valid, makes
  ~89% of that chain's blocks, and is what Bitcoin Core is trying to soft-fork
  away. Declined; do not add it as a convenience.
- **A deliberately invalid block still needs valid proof of work.** Core checks
  the hash first, so an unsolved broken block only says `high-hash`.
  `rejections.rs` solves every case but the one whose defect is the header,
  including cases that never touch it, since a new block starts unsolved.
- Regtest is exempt from the initial-block-download guard: a fresh regtest chain
  reports IBD until its first block.

### Targets, chains and version rolling

- **`MINER_BITS` may only make the target harder.** A harder target still
  produces valid blocks; an easier one is refused up front. The exception is
  `lottery`, which submits nothing.
- **`ShareTarget` is a newtype, not a `Target`.** A share target is easier than
  the network's by construction, so routing one through the other's validation
  is a compile error.
- **`rejections` and `reorg` write blocks and are refused off regtest.** Keep
  that check in `run`, and keep new modes on the right side of it: a mode that
  submits needs a disposable chain, and one that does not may point at mainnet.
  `stratum` writes no block, so it is not in `writes_blocks`.
- **A solo search rolls the template's version only inside
  `Template::rollable_bits`:** BIP320's bits 13–28, minus every bit the
  template's version sets, minus every bit `vbavailable` assigns. No
  `vbavailable`, no rolling. Not "the BIP320 bits are free": Core v31.1 counts
  them towards its unknown-rules warning. A rolled version keeps the top bits
  `001`, never clears a template bit, and moves nothing outside the rollable
  bits; `check_block`'s version rule enforces it. `MINER_TEMPLATE_VERSION_ROLLING`
  is on by default (`--no-template-version-rolling` mines the template's own
  version) and stays separate from `MINER_VERSION_ROLLING`, BIP310 with a
  pool. The CPU half stays single-version. `gpu.rs`'s `claim` takes the first
  listed nonce under the first header that verifies it, which at regtest
  difficulty is almost always the template's version (lanes record in
  lockstep), so a test of rolled blocks needs a sparse target, as
  `the_block_search_finds_blocks_under_both_versions_of_a_pair` uses.

### Verification and hashers

- **Only a `rust-bitcoin`-verified header may be reported** — blocks and shares
  alike, and every GPU winner, not only the one submitted. A fast hasher finds a
  winner and never certifies one; `search` fails loudly, naming the hasher, if
  the two disagree.
- **A hash-rate claim names its hasher.** `naive` and `sha-ni` differ by 2.2x;
  `portable` is a correctness reference, slower than either, and never a
  performance result.
- **Benchmarks replace the target and nothing else, and run without a
  watcher,** so they measure the production search and are never cut short by
  new work.
- **Second opinions stay second opinions.** `sha2` cross-checks
  `compress_sha_ni`; do not replace the hand-written path with it, or remove it,
  without redoing the comparison. `noise_sv2`, `mining_sv2`,
  `common_messages_sv2` and `binary_sv2` (independent Noise and message
  implementations every SV2 byte is checked against) stay dev-only: at runtime
  they add a second `secp256k1`, `secp256k1-sys` and `bitcoin_hashes`, and
  `cargo tree -e normal` must show one of each.
- SHA-NI selection is a runtime feature check, never a compile-time assumption:
  the same binary must run on non-x86 machines such as Apple Silicon.
- `compress_sha_ni` stays checked against `compress_portable` over arbitrary
  blocks, not only header shapes. The original bug, a `sha256msg1` one group
  early, was correct for 60 of 64 rounds.
- **`screen` is a shortcut beside `hash`, never a change to it.**
  `HeaderHasher::screen` and the search kernel stop the second hash after round
  60 and decide from word seven, which is final there. They must return exactly
  the verdict and rank that `hash`, `meets_target` and `best_rank` would; a tie
  or a zero word takes the whole hash. `hash` and the shader's `hash_nonce` stay
  the full digest. The rare branches fire about once in 2³², so tests construct
  them; keep probe steps 3c and 3d.
- **`screen_lanes` returns, lane by lane, exactly what `screen` returns.** The
  CPU searches hash `sha256::LANES` consecutive nonces per call and handle them
  in ascending order, so the first winner and every share match a
  one-at-a-time walk. Each lane's rare branches hash *that lane's* nonce, and
  tests build the tie and the zero word in every lane position. Keep
  `sha_ni_rounds_4_to_59!` as it is rather than rewriting it with the lane
  macro. The nonce goes in a register, never a copied tail: a 16-byte load
  across the 4-byte nonce store defeats store forwarding, which was most of
  what the lanes recovered. `LANES` stays a power of two (it divides 2³² and the
  stop interval); at four, the E-cores lose 9% to spills.

### GPU

- **Keep `MINER_MODE=probe` passing and node-free.** It checks digests against
  `rust-bitcoin`, including the mainnet genesis header, then the whole winner
  *set* against the CPU's — the only check that catches a dropped winner.
- **An overflowed winner buffer: three callers, two answers.** Harmless for a
  block search (every winner is a block, and at regtest difficulty a dispatch
  overflows routinely); fatal for the probe, which compares sets, and for a
  share search, where each dropped winner is lost credit and an understated
  rate.
- **A dispatch in flight belongs to the header it was submitted under.**
  `GpuMiner::finish` drains the engine before anything changes the merkle root
  (the extranonce roll, the interruption paths) or the version; handing
  `advance` a new header while one is pending stays an error. Finding a block
  may `abandon` instead. Shares do not get that exception — every other winner
  in the dispatch is separate credit — so `stratum/search.rs` drains.
- **A paired winner's version is whichever header `rust-bitcoin` verifies it
  under.** `search_pair` (AsicBoost) records a nonce once per version that
  meets the target, without saying which, so `attribute` requires each nonce
  listed exactly as many times as it verifies; listed once but verifying under
  both is a dropped winner and an error. Pairing happens only where
  `VersionRoll`'s span is two or more, so a job announcing `30000000` stays
  single. Never let the host trust a shader-reported version index, and keep
  probe step 5: 5c and 5d catch the rare path reading the other version's
  midstate, and the second version's rank.
- The bind group layout is explicit, because `search` and `probe` use different
  bindings and an inferred layout holds only one entry point's.
- **The shader's rounds are written out, not looped:** as a loop, 445 MH/s
  against 2,395. Do not fold `unrolled_rounds` back into a WGSL `for`; the
  padding literals in `tail_block` are worth 2.2% for the same reason.
- After an edit that preserves the shader's mtime, force a rebuild: Cargo tracks
  `include_str!` by timestamp and keeps the old shader silently.

### Templates and stopping

- **Stale and expired are different signals.** `Ending::Expired` exists because
  testnet4's window opens on the clock, which no longpoll reports. Do not fold
  it into `Stale`, and do not set `MINER_TEMPLATE_SECONDS=0` on such a chain.
- A stale template ends a search, not a run, and `Ending::Found` outranks every
  other ending: a block found as a flag is raised is still a block.
- The watcher's generation counter is load-bearing. After a submit, the longpoll
  on the mined template answers after the next template is fetched; without the
  counter, that late answer marks the fresh template stale.

### Settings and credentials

- **One name, two spellings; the flag is derived from the variable.**
  `settings.rs` holds the list and `command()` builds `clap` from it, never
  writing a flag by hand. A flag beats the variable, which beats a `--config`
  file, which beats the default. `constants.rs` is the only place a default
  lives; `clap` gets no `default_value`. A file is a third source, not a third
  spelling: its keys are the variable names. Tests check the registry against
  `Config`, the README's table and `sample.env`, so a new setting needs all four.
- **The cookie is the only credential path.** Never configure an RPC password,
  and no credential ever becomes a flag, since `ps` shows command lines.
  `MINER_POOL_PASS` is a difficulty request, not a password; the V2 authority
  key is public, so it may be a flag.

### Pools

- **A pool is a stranger's server.** With `MINER_POOL` unset, no pool socket is
  opened in any mode, and a config file is read only when named, since one
  picked up from the working directory could supply `MINER_POOL`. Discovery is
  refused permanently. Two settings are refused off the loopback, checked before
  connecting beside the regtest gate: `MINER_VERSION_ROLLING=force`, which rolls
  bits the pool did not agree to in order to test that a pool rejects them (do
  that to your own pool), and, under v2, an unset `MINER_POOL_AUTHORITY`, since
  a Noise session checked against nothing is encrypted to whoever answered.
  There is no trust-on-first-use. `skip` is the one explicit opt-out and never a
  default: unset and empty refuse, `skip` beside a key in the URL is a
  disagreement, and a `Reconnect` redirect is refused when nothing is pinned.
- **The protocol cannot be discovered.** Pool A serves both on one port and
  tells them apart from the client's first bytes, so a wrong guess hangs; the
  setting or a `stratum2+tcp://` URL decides.
- **A share has no `check_block` and needs none.** The client never sees the
  transaction set and reads the coinbase only to report the payout
  (`payout.rs`: a warning, never a refusal); the pool is the authority on all
  but the proof of work. The one local check is the header against the share
  target, through `rust-bitcoin`.
- **`MINER_POOL_CAPTURE` records only in `v2/conn.rs`, after a frame's AEAD tag
  verifies and before `messages.rs` parses it,** so a capture checks the parser
  rather than copying it. A test pins the position: a frame that authenticates
  and does not parse is recorded, one that fails its tag is not. Nothing from
  the handshake is written; the `send` lines exist only so shares can be
  rebuilt.
- **The scripted pool's frames come from SRI's encoder, never `messages.rs`.**
  `v2/scripted.rs` builds payloads with `mining_sv2` and `common_messages_sv2`,
  under SRI's message numbers and channel bits, and rebuilds shares with
  `rust-bitcoin`, not `job.rs`. `session_tests` uses this repository's codec and
  cannot stand in for it.
- **V1: a reply's `id` may be `null`, and call ids start at 1.** Pool B
  echoes a null back; Pool A coerces it to `0`. `messages.rs` accepts a
  number or a null and nothing else, and `Conn::call` starts at 1 so a reply to
  a notification never matches a call. SV2 has no request ids.
- **V1: `mining.suggest_difficulty` carries an id, and nothing waits for its
  reply.** Pool B refuses a null-id one and stays at its floor, which looks
  exactly like ignoring it. The
  difficulty is asked both ways, the frame and `d=` in the password, because
  neither works everywhere. A floor is not cosmetic: at difficulty 512 this
  hardware made one share every 49 minutes, which looks like a hung socket.
- **V2: a difficulty request points the other way, and the hash rate is what
  lowers it.** `MINER_POOL_DIFFICULTY` becomes `max_target`, a floor under the
  difficulty, so Pool A honours "1" by serving 512. `MINER_POOL_HASHRATE`
  (`nominal_hash_rate`, claiming nothing by default) is the lever: declaring
  690 MH/s moved Pool A from 512 to 2.42. The single `UpdateChannel` sent
  once a session has measured itself carries the `max_target` the channel was
  **opened with**, never the target being served: §5.3.7 makes a smaller value a
  request the server "must reflect", so echoing the served target locks the
  pool at its floor. That is invisible when asked and granted are equal, which
  is why `session_tests` makes them differ.
- **Held jobs on a new target: V1 and V2 are opposite, and both right.** V1:
  Pool B judges a share by the difficulty it wants now, so
  `mining.set_difficulty` retargets every held job **and** wakes the search;
  without the wake, a raise cost seven rejects over 52 seconds. V2: spec
  §5.3.21 applies `SetTarget` only to future and not-yet-activated jobs, so
  `v2/job.rs` snapshots the target at activation. One is a measured server, the
  other a specification; keep each file's rule separate.
- **Version rollability is decided per job.** V1: BIP310 leaves the
  reconstruction unstated — the spec reading is
  `(announced & !mask) | submitted`, Pool B computes
  `announced ^ submitted` — and the two agree
  only when the announced version has no bits inside the mask. Against a regtest
  `30000000` (bit 28) every share failed, which looks like a byte-order bug and
  is not. Core v31 announces `20000000`, so the case is reproduced with
  `bitcoind -blockversion=805306368`;
  `tests/fixtures/stratum-pool-b-30000000.jsonl` holds 37 accepted
  unrolled shares, where always sending the sixth parameter had 7 of 7
  rejected. Where it is ambiguous, `search::rollable` returns `None`: nothing
  rolls and the sixth `mining.submit` parameter is omitted. Do not "simplify"
  that into always sending it. V2: `version_rolling_allowed` is explicit and
  `SubmitSharesExtended.version` is the full nVersion, so
  `v2::job::Job::rollable` ignores the announced version; do not write it by
  analogy to `search::rollable`.

## Rust style

- **Imports.** Merge nested paths into one `use` per crate (`use std::{io, net::SocketAddr};`). Split them
  into three blocks separated by a blank line: `std`/`core`/`alloc`, then external crates, then
  `crate`/`super`/`self`. Don't hand-sort within a block — `cargo fmt` does it (edition 2024 version-sorts).
  The project builds on stable Rust, where rustfmt cannot merge or group imports, so keep both by hand.
- **No glob imports** (`use module::*;`), except a designated `prelude` module and `use super::*;` inside a
  `#[cfg(test)]` module. Clippy enforces this through `wildcard_imports` and `enum_glob_use` in `Cargo.toml`,
  but skips test modules entirely, so the `super::*`-only limit there is kept by hand.

## Formatting

- **Every `*.md` file must lint clean.** Markdown is linted by markdownlint in the editor; leave no
  warnings behind, including in files you only partly touched.
- Write table delimiter rows with spaces around every pipe and dash run (`| --- | :---: | --- |`, not
  `|---|:---:|---|`) — the compact, space-less form trips `MD060/table-column-style`.
- Run `npx markdownlint-cli2@0.23.2 "**/*.md"` before handing work over; `--fix` handles the
  mechanical rules. Pin the version: markdownlint 0.38 and earlier do not implement `MD060`, so an
  older linter reports clean on delimiter rows that the editor still flags.
- Deliberate departures from markdownlint defaults live in `.markdownlint.json`, each with the reason
  it was relaxed. Fix the Markdown rather than adding an entry unless the rule is wrong for this project.

### Conventions

- **Changelog style.** [CHANGELOG.md](CHANGELOG.md) is strictly reverse chronological: newest first, both
  across version groups *and within* a version group — a new entry goes at the top of its version's list,
  never appended at the bottom. Prefer concise changelog entries.
- Generated logs, build artifacts and local runtime files stay uncommitted unless a task calls for them.
  `results/` is gitignored and holds the shared log.
