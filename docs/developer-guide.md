# Developer guide

How to build, test and change PuntoMiner. Read the
[architecture](architecture.md) first for how the pieces fit together.
[AGENTS.md](../AGENTS.md) holds the full list of rules any change must keep,
for people and coding agents alike.

- [Prerequisites](#prerequisites)
- [Repository layout](#repository-layout)
- [Checks](#checks)
- [Smoke tests](#smoke-tests)
- [Testing against a local pool](#testing-against-a-local-pool)
- [Heat and measurements](#heat-and-measurements)
- [Test fixtures](#test-fixtures)
- [Making common changes](#making-common-changes)
- [Dependencies](#dependencies)
- [Conventions](#conventions)

## Prerequisites

- Rust 1.85 or newer, with `rustfmt` and `clippy`.
- For the GPU paths, a GPU and driver that `wgpu` can use. The tests do not
  need one.
- For the smoke tests against a node, Bitcoin Core (`bitcoind` and
  `bitcoin-cli`).
- On Linux, `lm-sensors`, for watching temperatures under load.

## Repository layout

| Path | Contents |
| --- | --- |
| `src/` | The miner. Unit tests live beside the code, in `#[cfg(test)]` modules |
| `src/miner.wgsl` | The GPU shader, minus its SHA-256 rounds, which `gpu.rs` generates |
| `tests/fixtures/` | Captured pool sessions and node templates that the parser tests read. Their provenance is in [its README](../tests/fixtures/README.md) |
| `docs/` | The user guide, the architecture, and this guide |
| `m`, `v1`, `v2` | Wrappers around `cargo run --release` for a node, a V1 pool and a V2 pool. Each reads its defaults from the matching `.env` file |
| `sample.env` | Every setting, commented out, with its description |
| `results/` | Run logs. Ignored by git |

## Checks

Run the cheapest checks first:

```sh
cargo fmt --check
cargo clippy --all-targets
cargo test
```

`cargo test` needs no node, GPU or network. It covers:

- **The hashers.** SHA-NI against the portable compression over arbitrary
  blocks, the multi-lane paths lane by lane, and the `screen` shortcut against
  the full hash. The rare branches are constructed explicitly.
- **Block building and `check_block`**, and version-bit selection against
  real templates.
- **Both pool clients' wire formats**, against the committed captures in
  `tests/fixtures/`. This is where a byte-order or JSON-shape regression shows
  up without a socket.
- **The Stratum V2 stack** against SRI's independent implementation: the Noise
  handshake against `noise_sv2`, every message against SRI's encoders and
  decoders, and whole sessions against a scripted pool whose frames SRI encodes.
- **The settings registry** against the settings `Config` reads, the README's
  table, and `sample.env`.

It does **not** cover the GPU shader, the long-poll, or a live pool. The smoke
tests below do.

Two tests are ignored by default, because neither is an assertion the suite can
make: one needs the network, and the other is a timed measurement.

```sh
# A live pool's first set_difficulty
cargo test --release stratum::conn::tests::a_live -- --ignored --nocapture
# The share search's rate against the block search's (full CPU load: see below)
cargo test --release stratum::search::tests::the_share_search -- --ignored --nocapture
```

## Smoke tests

The binary resolves paths from the working directory, so run these from the
repository root.

```sh
# The GPU shader against rust-bitcoin, then the GPU's winner set against the CPU's. No node.
./m --mode probe --log /tmp/miner.log

# One block on regtest, submitted and confirmed
bitcoind -regtest -daemon
bitcoin-cli -regtest createwallet dev
ADDRESS=$(bitcoin-cli -regtest getnewaddress)
./m --chain regtest --address "$ADDRESS" --bitcoind-datadir "$HOME/.bitcoin" \
    --blocks 1 --log /tmp/miner.log

# The long-poll watcher: mine nothing, and report each template change
./m --chain regtest --mode watch --bitcoind-datadir "$HOME/.bitcoin" --log /tmp/miner.log

# The block-writing experiments (regtest only)
./m --chain regtest --address "$ADDRESS" --bitcoind-datadir "$HOME/.bitcoin" --mode rejections
./m --chain regtest --address "$ADDRESS" --bitcoind-datadir "$HOME/.bitcoin" --mode reorg

# A pool over Stratum V1, then V2. The V2 URL must carry the pool's authority key.
./m --mode stratum --pool <host:port> --address <address> --log /tmp/miner.log
./m --mode stratum --pool stratum2+tcp://<host:port>/<authority key> --address <address> \
    --log /tmp/miner.log
```

`./m` reads `m.env` first, so those flags override the settings it ships with.
Keep `probe` passing and keep it node-free. Its winner-set comparison is the
only check that catches a dropped winner.

## Testing against a local pool

`cargo test` covers the wire. It cannot cover what only a second pool disagrees
about, and a green run against one mainnet pool proves little. Before believing
a change to either client, run it against a pool you control on regtest:

1. Start a regtest node with whatever the pool needs (typically ZMQ block
   notifications, and RPC reachable from the pool).
2. Run any open-source Stratum V1 or V2 pool against it.
3. Point the client at it with a regtest address:
   `./v1 127.0.0.1:<port> <bcrt1 address>`, or for V2,
   `./v2 stratum2+tcp://127.0.0.1:<port>/<key> <bcrt1 address>`. A loopback
   pool may also run with `--pool-authority skip`.

Regtest's target is easier than any share's, so every share is also a block,
and the node is a second oracle beside the pool. A local pool is also the only
place where these can be exercised:

- `--version-rolling force`, which is refused off the loopback.
- A job announcing a version with a bit inside the rolling mask. Start the node
  with `-blockversion=805306368` to make it announce `30000000`.
- Job cleaning on a new block, vardiff in both directions, and named
  rejections.

## Heat and measurements

Anything that holds the CPU near full load for long can overheat the machine.
That includes mining, benchmarks, the timed test above, and long sweeps.

- Check the CPU package temperature with `sensors` before starting, and watch
  it during the run (`watch -n 5 sensors`, plus `nvidia-smi` or your GPU's tool
  when the card is busy). Stop or lower the load if the package stays within
  10 °C of its `high` limit.
- Start light and raise the load in steps: `--workers`, `--cpu-percent`,
  `--gpu-percent`, `--device cpu`. Treat `--device cpu` and `hybrid` as full
  load, even at the defaults. `probe` and `lottery` run the GPU flat out.
- Let the machine cool to near idle between long runs.

Heat costs clock, and clock is hash rate:

- **Record the CPU clock beside every rate.**
- **Alternate runs that are being compared** instead of running them back to
  back. A cold run can read nearly 20% above a warm one.
- **Name the hasher.** `naive` and `sha-ni` differ by more than 2x, so a
  speedup quoted against the wrong baseline means nothing. `portable` is a
  correctness reference, never a performance result.
- **Measure with `bench`.** It replaces the target and nothing else, so it
  times the production search. It runs without a watcher, so it is never cut
  short by new work.

## Test fixtures

`tests/fixtures/` holds real sessions captured from pools, and real
`getblocktemplate` answers. Each V1 frame is kept as the exact string that
crossed the wire, not as re-encoded JSON, so a parser is tested against the
wire instead of a normalised copy of it. V2 frames are the plaintext recorded
after decryption, by `--pool-capture`. [The fixtures README](../tests/fixtures/README.md)
says where each file came from, what it pins down, and why it is safe to
commit.

Regenerate a fixture only with a reason. A new capture is a different session
against a different chain tip, and the tests pinned to the current values would
have to be rewritten.

## Making common changes

### Adding a setting

1. Add the default to `src/constants.rs`, with a doc comment that explains it.
   This is the only place a default lives.
2. Register it in `src/settings.rs` under its `MINER_*` name. The flag is
   derived from the name, so never write one out by hand.
3. Read it in `Config` (`src/runner.rs`).
4. Add a row to the README's settings table, and a commented block to
   `sample.env`.

The suite fails if steps 2–4 disagree. **No credential ever becomes a
setting**: the cookie is the only credential path.

### Changing the shader

- The SHA-256 rounds are generated by `gpu::unrolled_rounds` and appended to
  `miner.wgsl` before compiling. Do not fold them back into a WGSL loop: as a
  loop it ran about five times slower.
- Cargo tracks `include_str!` by modification time. If an edit preserved the
  file's mtime, `touch src/miner.wgsl` before building, or the binary keeps the
  old shader without saying so.
- Run `./m --mode probe` afterwards. Do not remove its steps as redundant: the
  tie, zero-word and version-pair steps are the only coverage of branches that
  fire about once in 2³² nonces.

### Changing a hasher

- `compress_sha_ni` must stay tested against `compress_portable` over
  arbitrary blocks, not only header-shaped ones. A bug that is correct for 60
  of 64 rounds passes every header test.
- `screen` and `screen_lanes` must return exactly what `hash` followed by the
  target check returns, lane by lane. Their tests build the rare branches in
  every lane position, because a lane that hashed its neighbour's nonce passes
  every random test.
- `LANES` stays a power of two, so that it divides 2³².
- Selection stays a runtime feature check.

### Changing the GPU search path

- Drain the engine (`finish`) before anything changes the merkle root or the
  version. Handing `advance` a new header while a dispatch is pending is an
  error, and must stay one.
- A block search may abandon a dispatch once it has found a block. A share
  search must drain, because every other winner in the dispatch is a separate
  share.
- An overflowing winner buffer is fine for a block search, and fatal for the
  probe and for a share search. Keep the three answers separate.

### Changing a pool client

- Run the fixture tests, and for V2 the scripted pool in `v2/scripted.rs`. The
  scripted pool's frames must come from SRI's encoder, never from this
  repository's `messages.rs`, or both ends would agree about any bug in it.
- V1 and V2 have opposite rules in places: whether a held job keeps its
  target, which way a difficulty request points, and how version rolling is
  decided. Each file states its own rule. Do not write one by analogy to the
  other. [The architecture](architecture.md#stratum-v2-stratumv2) has the
  table.
- Then [test against a local pool](#testing-against-a-local-pool).

### Adding a mode

Decide two things up front:

- **Does it write blocks?** If so, add it to `writes_blocks` so it is refused
  off regtest.
- **Does it need a node?** If not, dispatch it before the RPC client is
  created, as `probe` and `stratum` are.

## Dependencies

The dependency list is kept short on purpose.

- `rpc.rs` is hand-rolled HTTP/1.1 to the loopback, so the miner needs no HTTP
  client.
- `sha2` is a second opinion. It cross-checks the hand-written SHA-NI path, and
  is not a utility to replace it with.
- `noise_sv2`, `mining_sv2`, `common_messages_sv2` and `binary_sv2` are
  dev-dependencies only, used as independent implementations to test against.
  As runtime dependencies they would put a second `secp256k1`, `secp256k1-sys`
  and `bitcoin_hashes` in the binary. This must keep showing one of each:

  ```sh
  cargo tree -e normal | grep -E 'secp256k1|bitcoin_hashes'
  ```

## Conventions

- Keep changes small and focused. `cargo fmt --check` and
  `cargo clippy --all-targets` stay clean.
- Imports follow the [Rust style](../AGENTS.md#rust-style) in AGENTS.md: one
  `use` per crate, in three blocks, and no glob imports outside test modules.
- The docs describe the software as it is. Plans and work logs are not kept in
  the repository.
- [CHANGELOG.md](../CHANGELOG.md) is strictly reverse chronological: the newest
  version first, and the newest entry first within a version. Entries are
  short, and prefixed `feat:`, `perf:`, `fix:`, `refactor:`, `test:`, `docs:` or
  `chore:`.
- A new document goes in `docs/` and gets a row in
  [docs/README.md](README.md).
