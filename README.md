# PuntoMiner

PuntoMiner is an experimental Bitcoin miner. It can:

- mine for a pool over Stratum V1 or V2
- take a block template from a Bitcoin Core node, build the block itself (BIP34 coinbase, BIP141 witness commitment, merkle root), and search for a valid header on the CPU, the GPU, or both
- run modes that submit nothing, for benchmarking and diagnostics

## Tested platform and hashrates

Intel Core i9-14900HX / 96GB RAM / 8GB NVIDIA GeForce RTX 4070 Laptop GPU / Linux Ubuntu 26.04

- CPU, `sha-ni`, 32 workers: ~455 MH/s
- GPU: 2,637 MH/s with version rolling, the default (2,396 MH/s with `--no-template-version-rolling`); 2,602 MH/s for pool shares with version rolling
- `hybrid`: 2,835 MH/s (2,601 MH/s without template version rolling)

## How to run

### Installing Rust

Install the toolchain with [rustup](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### If Rust already installed

Please check the installed version

```sh
rustc --version
```

The crate uses the 2024 edition, so it needs Rust 1.85 or newer. To update the Rust version:

```sh
rustup update stable
```

The wrapper scripts below call `cargo run --release`, so the first run builds the binary.

### Run

> **Before your first run, set your own payout address.** The defaults that ship are the author's own: the compiled-in `MINER_ADDRESS` and the one in `m.env`, `v1.env` and `v2.env` pay the author, `m.env` points `MINER_BITCOIND_DATADIR` at the author's disk, and `v1.env` and `v2.env` name the author's pool. Pass `--address <your address>` (and `--bitcoind-datadir` for `./m`), or edit the three `.env` files, unless you mean to mine for the author. The [user guide](docs/user-guide.md#before-the-first-run) has the details.
>
> **Hardware warning:** mining keeps the CPU and GPU at full load for as long as it runs, which can overheat or damage hardware that isn't cooled for it, especially laptops. Start light, for example `./m --cpu-percent 25 --gpu-percent 25` or `--device cpu`, watch temperatures, and raise the load gradually. See the [disclaimer](#no-obligation-software-disclaimer).

1. `./m` mines **mainnet** until Ctrl-C. The miner authenticates to the node with its datadir cookie. No password is configured, and no credential is ever a flag.

2. `./v1` and `./v2` do the same for a Stratum V1 or V2 pool: they take the pool's `host:port` and, off mainnet, a payout address, and read their other defaults from `v1.env` and `v2.env`. Over Stratum V2 the pool's authority key must be pinned, or the client refuses any pool that is not on the loopback. The `stratum2+tcp://` URL a pool publishes carries the key.

```sh
./v1                           # the default pool, from v1.env
./v1 pool.example.com:3333     # another pool, same defaults otherwise
./v1 127.0.0.1:3333 bcrt1q...  # a local pool on regtest, which needs its own address
./v2                           # the same pool over Stratum V2, key and all
```

## Settings

Every setting is an environment variable and a flag: drop `MINER_`, lowercase it, and use dashes for underscores (`MINER_GPU_LANES` is `--gpu-lanes`). A flag beats the variable, which beats a config file, which beats the default in `src/constants.rs`. `./m --help` prints the same list.

| Flag | Variable | Default | Meaning |
| --- | --- | --- | --- |
| `--config` | `MINER_CONFIG` | empty | A file of MINER_ settings, one KEY=VALUE per line, which the environment and flags override. Empty reads none. |
| `--chain` | `MINER_CHAIN` | `main` | Chain to work against: main, testnet4, signet or regtest |
| `--mode` | `MINER_MODE` | `mine` | What the run does: mine, bench, probe, watch, rejections, reorg, validate, lottery or stratum |
| `--blocks` | `MINER_BLOCKS` | `0` | Blocks to mine before stopping; 0 runs until Ctrl-C |
| `--address` | `MINER_ADDRESS` | the configured address | Where the coinbase pays; must decode on the chain in use |
| `--device` | `MINER_DEVICE` | `gpu` | Where the nonce search runs: cpu, gpu or hybrid (both at once) |
| `--workers` | `MINER_WORKERS` | a share of the logical cores | CPU search threads |
| `--cpu-percent` | `MINER_CPU_PERCENT` | `75` | Duty cycle per search thread, 1 to 100; the CPU search only |
| `--hasher` | `MINER_HASHER` | `auto` | Which implementation walks the nonce space: auto, naive, portable, sha-ni, rustcrypto or rustcrypto-naive |
| `--gpu-lanes` | `MINER_GPU_LANES` | `262144` | GPU invocations per dispatch |
| `--gpu-nonces` | `MINER_GPU_NONCES` | `256` | Nonces each GPU lane walks per dispatch |
| `--gpu-pipeline` | `MINER_GPU_PIPELINE` | `2` | Dispatches in flight; 1 submits and waits |
| `--gpu-percent` | `MINER_GPU_PERCENT` | `100` | Duty cycle of the GPU, 1 to 100, resting between dispatches; the block and share searches only |
| `--gpu-capacity` | `MINER_GPU_CAPACITY` | `4096` | Winners one GPU dispatch may record |
| `--bits` | `MINER_BITS` | empty | Compact target to grind to instead of the template's, which may only be harder; empty uses the template's |
| `--extranonce-start` | `MINER_EXTRANONCE_START` | `0` | Where the extranonce walk begins: auto, a decimal u64, or a 0x-prefixed hex one |
| `--template-seconds` | `MINER_TEMPLATE_SECONDS` | `0` | Seconds a template may be ground before it is refetched; 0 waits for the longpoll |
| `--prefetch` / `--no-prefetch` | `MINER_PREFETCH` | `true` | Mine the template a longpoll answers with, rather than refetching it |
| `--template-version-rolling` / `--no-template-version-rolling` | `MINER_TEMPLATE_VERSION_ROLLING` | `true` | Roll the template's free version bits on the GPU, two versions per nonce (AsicBoost); the solo block search only |
| `--bench-seconds` | `MINER_BENCH_SECONDS` | `10` | Duration of a benchmark run, in seconds |
| `--bitcoind-datadir` | `MINER_BITCOIND_DATADIR` | the configured datadir | Bitcoin Core's datadir, which is where the RPC cookie is read from |
| `--log` | `MINER_LOG` | `results/log` | Append-only log destination |
| `--pool` | `MINER_POOL` | empty | host:port of a Stratum pool, or a stratum+tcp:// or stratum2+tcp:// URL. Empty means off, and there is no default pool |
| `--pool-user` | `MINER_POOL_USER` | empty | The whole worker name to authorize as; empty builds it from MINER_ADDRESS and MINER_POOL_WORKER |
| `--pool-worker` | `MINER_POOL_WORKER` | `puntominer` | The `worker` in `address.worker`; letters, digits, dashes and underscores only. Empty falls back to this machine's hostname |
| `--pool-pass` | `MINER_POOL_PASS` | `d=1` | The password field, which on a solo pool is a difficulty request rather than a credential |
| `--pool-difficulty` | `MINER_POOL_DIFFICULTY` | `1` | Share difficulty to ask for: a request under v1, a floor under v2 |
| `--pool-agent` | `MINER_POOL_AGENT` | `puntominer/0.1` | User agent announced in mining.subscribe |
| `--pool-reconnect-seconds` | `MINER_POOL_RECONNECT_SECONDS` | `5` | Pause before reconnecting; a dropped socket is normal, not fatal |
| `--pool-protocol` | `MINER_POOL_PROTOCOL` | `v1` | Which protocol the pool speaks: v1 or v2. Cannot be discovered, so a wrong guess is a hang; a stratum2+tcp:// URL in MINER_POOL says it instead |
| `--pool-authority` | `MINER_POOL_AUTHORITY` | empty | The Stratum V2 pool authority key to pin, as base58check or 64 hex characters. Empty refuses any pool that is not on the loopback; `skip` connects without verifying the certificate |
| `--pool-hashrate` | `MINER_POOL_HASHRATE` | `0` | Hash rate to claim in the Stratum V2 channel open, in h/s; 0 claims nothing and takes the pool's default difficulty |
| `--pool-capture` | `MINER_POOL_CAPTURE` | empty | File to record every Stratum V2 frame to, in plaintext hex; empty records nothing. V2 only |
| `--version-rolling` | `MINER_VERSION_ROLLING` | `auto` | BIP310 version rolling: auto, off, or force (loopback pools only) |

### Settings from a file

The keys are the variable names. A file is read only when named with `--config` or `MINER_CONFIG`, and the environment and flags override it:

```sh
cp sample.env rig.env      # every setting, commented out, with its description
$EDITOR rig.env            # uncomment what you want to change
./m --config rig.env
```

The file format's rules are in the
[user guide](docs/user-guide.md#settings-from-a-file).

## Further reading

- [puntominer.com](https://puntominer.com): this README and the documents below, as a website
- [User guide](docs/user-guide.md): setting up a node, every mode, pools over Stratum V1 and V2, config files, throttling and troubleshooting
- [Architecture](docs/architecture.md): how a block and a share are built, searched, verified and submitted, and the safety rules the code keeps
- [Developer guide](docs/developer-guide.md): building, testing, the committed fixtures, and how to change the code without breaking its invariants
- [Contributing](CONTRIBUTING.md)

## No-Obligation Software Disclaimer

PuntoMiner is provided "as is", without warranty of any kind, express or implied, as set out in the [MIT License](LICENSE). The authors and contributors have no obligation to provide support, maintenance, updates, bug fixes or new features, to answer issues or review pull requests, or to keep any behaviour, setting or interface stable between versions.

You run it at your own risk and are responsible for how you use it: for the hardware, power and network it consumes, for the nodes and pools it connects to, and for any blocks or shares it submits. Nothing here is financial advice or a promise of any mining return.

Mining keeps the CPU and GPU at sustained full load, which can overheat or damage hardware that was not built or cooled for it, and laptops especially. Run PuntoMiner with careful settings: start with a light load (`--device`, `--workers`, `--cpu-percent`, `--gpu-percent`), watch temperatures, fans and power draw, and raise the load only as far as your cooling and power supply can sustain.
