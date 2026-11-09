# User guide

This guide covers installing PuntoMiner, pointing it at a Bitcoin Core node or a
pool, and running each of its modes safely. The [README](../README.md) has the
short version and the full settings table. The [architecture](architecture.md)
document explains how the miner works.

- [What PuntoMiner is](#what-puntominer-is)
- [Requirements](#requirements)
- [Building](#building)
- [Before the first run](#before-the-first-run)
- [Keeping the hardware safe](#keeping-the-hardware-safe)
- [Configuring a run](#configuring-a-run)
- [Mining against your own node](#mining-against-your-own-node)
- [Modes](#modes)
- [Mining for a pool](#mining-for-a-pool)
- [Logs](#logs)
- [Troubleshooting](#troubleshooting)

## What PuntoMiner is

PuntoMiner is an experimental Bitcoin miner for learning and testing. It gets
work in one of two ways:

- **From your own Bitcoin Core node.** It fetches a block template, builds the
  whole block itself (coinbase, witness commitment, merkle root), searches for
  a header that meets the target, checks the block locally, submits it, and
  reads the chain tip back to confirm it.
- **From a pool, over Stratum V1 or V2.** The pool decides what is mined and
  builds the coinbase. PuntoMiner sends back *shares*: headers that meet the
  pool's much easier target. This mode needs no node.

It searches on the CPU, on the GPU, or on both at once. It also has modes that
submit nothing, for benchmarking, verifying the GPU shader, and checking a block
against a real node.

It is not a way to earn bitcoin. A laptop GPU is around 10⁻¹² of the Bitcoin
network's hash rate, which works out to one mainnet block every several million
years. Pooled or solo, the expected return is the same, and it is negligible.

## Requirements

- **Rust 1.85 or newer.** The crate uses the 2024 edition. Install it with
  [rustup](https://rustup.rs), or run `rustup update stable` to upgrade.
- **A GPU is optional.** The GPU search runs through `wgpu`. It was developed
  and measured on Linux over Vulkan. `wgpu` also targets Metal and DirectX 12,
  but those are not regularly tested. Without a usable GPU, run with
  `--device cpu`.
- **On the CPU**, PuntoMiner uses the x86 SHA extensions (SHA-NI) where the
  processor has them, and a portable implementation otherwise. This is chosen
  at runtime, so the same binary runs on either kind of processor.
- **Bitcoin Core** is needed only for the modes that work against a node, which
  is every mode except `probe` and `stratum`. Development used Bitcoin Core
  v31. The node must be fully synced, except on regtest.

## Building

```sh
git clone <repository URL> puntominer
cd puntominer
cargo build --release
```

The wrapper scripts `./m`, `./v1` and `./v2` call `cargo run --release`, so the
first run builds the binary if you have not already. **Run everything from the
repository root.** Relative paths, including the default log at `results/log`,
resolve from the working directory. The wrappers `cd` there themselves.

`./m --help` prints every setting with its description.

## Before the first run

The defaults that ship are the author's own, so a run that changes nothing
mines for the author. Check these four places before running anything:

| Where | What it sets | What to do |
| --- | --- | --- |
| `src/constants.rs`, `MINER_ADDRESS` | The compiled-in payout address, used when nothing else sets one | Pass `--address`, or set it in a config file |
| `m.env` (read by `./m`) | The author's payout address and Bitcoin Core datadir | Edit both, or override them with flags |
| `v1.env` (read by `./v1`) | The author's address, and the author's pool as the default | Edit, or pass the pool and address as arguments |
| `v2.env` (read by `./v2`) | The same for Stratum V2, plus a hash-rate claim for the author's hardware | Edit, or override with flags |

**The address must belong to the chain you mine on.** A mainnet address is
refused on regtest, and the other way round. On regtest, ask the node's wallet
for one (see [below](#a-first-run-on-regtest)).

**Check the datadir.** `MINER_BITCOIND_DATADIR` is where the RPC cookie is
read from. The compiled-in default is `~/.bitcoin`, Bitcoin Core's default on
Linux, but `m.env` overrides it with the author's path. A leading `~` is
expanded to your home directory wherever the setting comes from. Bitcoin
Core's default datadir is `~/Library/Application Support/Bitcoin` on macOS and
`%LOCALAPPDATA%\Bitcoin` on Windows.

## Keeping the hardware safe

Mining holds the CPU, the GPU, or both at sustained full load for as long as it
runs. That can overheat hardware that is not cooled for it, laptops especially,
where the CPU and GPU usually share one power and thermal budget.

- **Start light, and raise the load gradually.** Use `--device`, `--workers`,
  `--cpu-percent` and `--gpu-percent`. For example:
  `./m --cpu-percent 25 --gpu-percent 25`.
- **Know the defaults.** The default device is `gpu`, which leaves the CPU
  nearly idle. On the CPU, the defaults use 80% of the logical cores at a 75%
  duty cycle. On a laptop even that can reach the CPU's thermal limit, so treat
  `--device cpu` and `--device hybrid` as full load.
- **Two modes ignore `--gpu-percent`.** `probe` and `lottery` always run the
  GPU flat out.
- **Watch temperatures while it runs.** On Linux, `watch -n 5 sensors` shows
  the CPU, and `nvidia-smi` shows an NVIDIA card. Stop or lower the load if the
  CPU package stays within about 10 °C of the `high` limit that `sensors`
  reports.
- **Heat costs hash rate.** A hot CPU runs at a lower clock, so a benchmark
  taken on a warm machine reads lower than one taken cold. When comparing two
  configurations, alternate between them instead of running one after the
  other.

## Configuring a run

Every setting has a name, such as `MINER_GPU_LANES`, and three ways to set it:

1. **A flag**: drop `MINER_`, lowercase the rest, and change underscores to
   dashes, giving `--gpu-lanes 131072`. Boolean settings also take a `--no-`
   form, such as `--no-prefetch`.
2. **An environment variable**: `MINER_GPU_LANES=131072`.
3. **A line in a config file** named by `--config`: `MINER_GPU_LANES=131072`.

**A flag beats the variable, which beats the config file, which beats the
compiled-in default.** The startup log names every file setting that was
overridden. The README's [settings table](../README.md#settings) lists every
setting, and `./m --help` prints the same list.

No credential is ever a flag, because any user on the machine can read a
command line through `ps`. The node is reached with its cookie file, and no RPC
password is ever configured.

### Settings from a file

A config file holds only the settings you changed:

```sh
# rig.env: 20 blocks on regtest, on the GPU
MINER_CHAIN=regtest
MINER_BLOCKS=20
MINER_DEVICE=gpu
```

```sh
./m --config rig.env
MINER_BLOCKS=1 ./m --config rig.env --device cpu   # one block, on the CPU
```

`sample.env` lists every setting, commented out, with its description. Copy it
and uncomment what you want to change.

The rules:

- **The keys are the variable names.** Each line is `KEY=VALUE`, split at the
  first `=`. Whole-line `#` comments are allowed. Quote a value that contains a
  space. Booleans take the same spellings as the variables.
- **Some things are refused**: `$`, backticks, backslashes, trailing comments,
  unknown keys and duplicate keys. The error names the file and line.
- **A file is read only when it is named**, with `--config` or `MINER_CONFIG`.
  A bare `./m` ignores `v1.env`, `v2.env` and `sample.env` even though they sit
  beside it. That keeps a bare run from connecting to a pool nobody named.
- **One file per run.** A second `--config` replaces the first instead of
  merging with it, and `--config ""` reads none. The wrappers pass their own
  `--config` first, so a `--config` you type replaces the wrapper's file.
- **Relative paths resolve from the working directory.** The wrappers `cd` to
  the repository root first, so give them an absolute path.
- **The same file works elsewhere.** `set -a; . rig.env; set +a` loads it into a
  shell, and systemd's `EnvironmentFile=` reads it too. `docker --env-file`
  keeps quotes literally, so only unquoted values carry over to Docker.

## Mining against your own node

### Connecting to Bitcoin Core

PuntoMiner talks JSON-RPC to the node on the loopback, at the chain's default
RPC port: 8332 for mainnet, 48332 for testnet4, 38332 for signet, and 18443 for
regtest. It authenticates with the `.cookie` file Bitcoin Core writes into its
datadir, in the chain's subdirectory: `<datadir>/regtest/.cookie` for regtest,
for example. Nothing else needs configuring on the node.

The node must be out of initial block download. Regtest is exempt, because a
fresh regtest chain reports initial block download until its first block is
mined.

### A first run on regtest

Regtest is a private chain with negligible difficulty. A block takes
milliseconds, and a mistake comes back as a named rejection without costing
anything.

```sh
bitcoind -regtest -daemon
bitcoin-cli -regtest createwallet miner
ADDRESS=$(bitcoin-cli -regtest getnewaddress)

./m --chain regtest --address "$ADDRESS" --bitcoind-datadir "$HOME/.bitcoin" \
    --blocks 5 --log /tmp/miner.log
```

Each block is built from the node's template, searched, checked locally,
submitted, and confirmed by reading the tip back. `bitcoin-cli -regtest
getblockcount` should go up by five.

### What a solo run does

1. Fetch a template with `getblocktemplate`.
2. Build the coinbase, which pays `MINER_ADDRESS` and carries the BIP34
   height, an extranonce, and the coinbase tag. Then compute the witness
   commitment and the merkle root.
3. Search the 32-bit nonce space for a header that meets the target. When the
   nonce space is exhausted, roll the extranonce, which changes the merkle
   root, and search again.
4. Recompute any winning header with `rust-bitcoin`, then check the block
   locally (height, witness commitment, merkle root, coinbase value,
   mintime, version).
5. Submit it, then read the tip back. An accepted block is not necessarily the
   best chain.

While it searches, a watcher thread holds a long-poll open on the node. When
the node has better work (a new block, or new transactions), the search stops
within one GPU dispatch and starts on the new template. Related settings:

- `--template-seconds N` also refetches the template every N seconds. The
  default 0 waits for the long-poll alone.
- `--no-prefetch` discards the template a long-poll answers with and fetches a
  fresh one instead.
- `--blocks N` stops after N blocks. The default 0 runs until Ctrl-C.

### Devices and hashers

`--device` chooses where the nonce search runs:

| Device | What it does |
| --- | --- |
| `gpu` (default) | The search runs in a compute shader. The CPU stays nearly idle. |
| `cpu` | The search runs on `--workers` threads, each at `--cpu-percent`. |
| `hybrid` | Both devices work on one template, starting half the extranonce space apart so neither repeats the other's work. The first to win stops the other. |

On the CPU, `--hasher` chooses the SHA-256 implementation. `auto` (the default)
picks `sha-ni` where the processor supports it and `portable` otherwise. The
other choices exist so that a speed measurement can say which baseline it beat:
`naive` is `rust-bitcoin`'s plain `block_hash()`, and `rustcrypto` and
`rustcrypto-naive` use the `sha2` crate.

The GPU's dispatch size is `--gpu-lanes` × `--gpu-nonces`. The defaults were
tuned on an RTX 4070 Laptop. `--gpu-pipeline` sets how many dispatches are in
flight at once.

### Version rolling on the solo search

By default the GPU block search hashes two block versions per nonce (the
technique known as AsicBoost). It rolls only version bits the template leaves
free: BIP320's bits 13 to 28, minus any bit the template already sets and any
bit the node lists as assigned to a deployment. A template with no deployment
list never rolls. `--no-template-version-rolling` mines the template's own
version. The CPU search always uses a single version.

### The coinbase tag

A solo block's coinbase carries a short text tag, `Mined by PuntoMiner. Hit by
XX`, where `XX` rotates through a compiled-in list. It is permanent: a block you
win carries it on the chain for good, readable in any block explorer. The tag
and its rotation are in `src/constants.rs`. In pool mode the pool builds the
coinbase, so no tag of PuntoMiner's appears.

### Chains

| Chain | Notes |
| --- | --- |
| `main` (default) | A bare `./m` mines mainnet until Ctrl-C. The no-submit modes `validate` and `lottery` are meant for mainnet. |
| `testnet4` | Its real difficulty is out of reach. Testnet4 allows a difficulty-1 block twenty minutes after the previous one, but most of the chain's blocks are stamped exactly twenty minutes and one second after their parent to open that window artificially. PuntoMiner deliberately does not do that: it timestamps honestly with the node's `curtime`, so its templates carry the real difficulty. `--template-seconds` refetches on the clock, which no long-poll reports. |
| `signet` | Signet blocks must be signed by the network's challenge key, which PuntoMiner does not do. Use signet for the modes that submit nothing. |
| `regtest` | The chain for development and experiments. The only chain `rejections` and `reorg` run on. |

### Watching a search on regtest

Regtest blocks arrive too fast to see a search do anything. `--bits` sets a
target **harder** than the chain's, and a header that meets a harder target
still makes a valid block. That is what makes stale templates, abandoned
searches and long-polls visible:

```sh
# Difficulty 6 instead of regtest's ~5e-10: about 2.6e10 hashes, or seconds of a GPU, per block
./m --chain regtest --address "$ADDRESS" --bits 1d002aaa
```

An easier target than the chain's is refused at startup, because it would
produce blocks the node rejects. The one exception is `lottery`, which submits
nothing.

## Modes

`--mode` chooses what a run does.

| Mode | Needs | Writes to the chain | What it does |
| --- | --- | --- | --- |
| `mine` (default) | node | yes | Mines blocks and submits them, as described above. |
| `bench` | node | no | Measures the search rate against a target no header can meet. Only the target differs from a real run, so what it measures is the production search. Runs for `--bench-seconds`. |
| `probe` | GPU only | no | Checks the GPU shader against `rust-bitcoin`, including the mainnet genesis header, then compares the GPU's whole set of winners with the CPU's. No node needed. |
| `watch` | node | no | Follows the node's template through its long-poll and reports each change, mining nothing. |
| `validate` | node | no | Builds the block a real template describes and checks everything except the proof of work, then asks Bitcoin Core for its verdict through `getblocktemplate` proposal mode. Safe on mainnet. |
| `lottery` | node | no | Hashes a real template against a deliberately easy threshold and compares the digest distribution with theory. Runs the GPU flat out. |
| `rejections` | regtest node | yes | Breaks a block ten ways, each still with a valid proof of work, and records the node's answer to each. Regtest only. |
| `reorg` | regtest node | yes | Mines two competing blocks at one height, then extends the loser and watches the chain reorganise. Regtest only. |
| `stratum` | pool | no (shares only) | Mines for a pool. See below. |

Every node mode except `watch` also needs a payout address valid on that
chain, even when it submits nothing, because it builds a real coinbase.

Examples:

```sh
./m --mode probe                                        # verify the GPU shader; no node
./m --mode bench --device cpu --workers 8               # CPU search rate, 10 seconds
./m --mode watch                                        # follow mainnet's template
./m --mode validate                                     # check a real mainnet block, submit nothing
./m --chain regtest --address "$ADDRESS" --mode rejections
```

## Mining for a pool

`--mode stratum` takes work from a pool instead of a node. The pool chooses
what is mined and builds the coinbase. PuntoMiner splices in its extranonce,
searches, and submits shares. Every share is recomputed with `rust-bitcoin`
before it is sent.

**No socket to a pool is opened unless `MINER_POOL` is set.** It has no
compiled-in default, in any mode.

The wrappers are the short way to run it. Each takes an optional pool and an
optional payout address, then passes any further flags through to the miner:

```sh
./v1 <host:port> [address] [flags...]
./v2 <stratum2+tcp://host:port/authority-key> [address] [flags...]
```

The long way is `./m --mode stratum --pool <pool> --address <address>`, with
`--pool-protocol v2` for Stratum V2.

### The worker name and the payout

The pool is sent the worker name `<address>.<worker>`. The address comes from
`MINER_ADDRESS` and the worker from `--pool-worker`, which defaults to
`puntominer`. If `--pool-worker` is empty, the machine's hostname is used.
`--pool-user` replaces the whole name. On a solo pool, the address is what a
found block pays, so it has to be valid on the pool's chain.

PuntoMiner decodes each job's coinbase and logs who it pays. It warns when none
of the outputs pays the address in the worker name. That is expected on a
pooled (PPLNS or FPPS) pool, whose coinbase pays the pool. It is a warning
only, because the pool is the authority on everything except the proof of work.

### Stratum V1

```sh
./m --mode stratum --pool pool.example.com:3333 --address <address>
```

- `--pool` takes `host:port` or a `stratum+tcp://host:port` URL.
- **Share difficulty** is requested two ways, because neither works on every
  pool: through `d=<n>` in the password field (`--pool-pass`, default `d=1`) and
  through `mining.suggest_difficulty` (`--pool-difficulty`, default 1). The pool
  decides. Some pools start at a high floor. At difficulty 512, a miner doing
  600 MH/s finds about one share an hour, which looks just like a hung
  connection.
- **Version rolling** (BIP310): `--version-rolling auto` (default) rolls the
  bits the pool agreed to. `off` never rolls. `force` rolls bits the pool did
  *not* agree to, to test that a pool rejects them. It is refused against any
  pool that is not on the loopback.
- A dropped connection is normal. The client reconnects after
  `--pool-reconnect-seconds`.

### Stratum V2

Stratum V2 carries the same work over a binary protocol, inside an encrypted
tunnel that authenticates the pool. The easiest way to configure it is to paste
the URL the pool publishes, which carries the protocol, host, port and the
pool's authority key:

```sh
./v2 stratum2+tcp://pool.example.com:3336/<authority key> <address>
```

- **The protocol cannot be detected.** Some pools serve V1 and V2 on the same
  port and tell them apart by the client's first bytes, so the wrong guess
  hangs instead of failing. A `stratum2+tcp://` URL or `--pool-protocol v2`
  decides it. A URL that disagrees with `--pool-protocol` is refused.
- **The pool's authority key must be pinned** for any pool that is not on the
  loopback. It comes from the URL, or from `--pool-authority` as base58check or
  64 hex characters. The key is public: pools publish it so that miners can pin
  it, which is why it can be a flag. Without it the client refuses to connect,
  because an encrypted session whose certificate is checked against nothing is
  encrypted to whoever answered. Nothing is remembered between runs, and there
  is no trust-on-first-use. `--pool-authority skip` connects without checking
  the certificate. It is an explicit opt-out, never a default.
- **Difficulty works the other way round from V1.** `--pool-difficulty` sets
  the channel's maximum target, which can only ask for *harder* work. What
  lowers the difficulty is the hash rate the client declares, because the pool
  sizes the target from it. `--pool-hashrate <hashes per second>` declares one
  up front. The default 0 declares nothing and takes the pool's default
  difficulty, and the client reports its measured rate after the first job.
  Declaring a realistic rate can turn one share an hour into several a minute.
- `--pool-pass` has no V2 counterpart, and a run that sets it is told so.
- `--pool-capture <file>` records every frame after the handshake, decrypted,
  one hex line per frame. It holds nothing from the handshake and nothing
  secret. It is refused under V1, whose plaintext any logging proxy can record.

## Logs

Every run appends its log to `results/log`, or to the file named by `--log`,
and prints the same lines to the console. The log records the configuration,
the device and hasher in use, each template, the search rate, and every block
or share with its outcome. `results/` is ignored by git.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `could not read <path>/.cookie: ... (is the <chain> node running?)` | The node is not running, or the datadir is wrong. Check `--bitcoind-datadir`, which `./m` takes from `m.env` unless you pass it. |
| `the payout address is not a regtest address` | The address belongs to another chain. Pass `--address` with one from that chain. |
| `the main node is still in initial block download` | Wait for the node to sync. Only regtest is exempt. |
| `this mode writes blocks and is only allowed on regtest` | `rejections` and `reorg` need `--chain regtest`. |
| `could not find a GPU adapter` | No GPU usable by `wgpu` was found. Check the graphics driver and Vulkan installation, or run with `--device cpu`. |
| The pool connection is silent, with no job and no error | Probably the wrong protocol. Check `--pool-protocol`, or use the pool's `stratum2+tcp://` URL. |
| Connected and receiving jobs, but no shares for a long time | The share difficulty is too high for your hash rate. Under V1, check what difficulty the pool granted (it is logged). Under V2, declare your hash rate with `--pool-hashrate`. |
| A Stratum V2 pool is refused before connecting | The authority key is not pinned. Use the pool's full `stratum2+tcp://host:port/<key>` URL, or `--pool-authority`. |
| `MINER_BITS` is refused | It is easier than the chain's target. Only harder targets are allowed. |
| Hash rate lower than expected | Check the temperature and clock, and that `--cpu-percent` and `--gpu-percent` are at 100 when measuring. A short `bench` on a warm machine reads low. |
