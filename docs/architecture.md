# Architecture

How PuntoMiner is put together: the two ways it gets work, the search engines
both share, and the rules that keep what it submits correct and what it
connects to deliberate. The [user guide](user-guide.md) covers running it, and
the [developer guide](developer-guide.md) covers changing it.

- [Overview](#overview)
- [Module map](#module-map)
- [Settings](#settings)
- [The solo pipeline](#the-solo-pipeline)
- [Search engines](#search-engines)
- [Template freshness and stopping](#template-freshness-and-stopping)
- [The pool clients](#the-pool-clients)
- [Trust and safety rules](#trust-and-safety-rules)
- [Second opinions](#second-opinions)
- [Where the speed comes from](#where-the-speed-comes-from)

## Overview

```text
                      settings.rs   flag > MINER_* variable > --config file > constants.rs
                           │
                       runner.rs    mode dispatch
          ┌────────────────┼──────────────────────────────┐
          │                │                              │
     solo modes          probe                         stratum
          │            (no node)                      (no node)
   rpc.rs ⇄ bitcoind       │                              │
   (cookie, loopback)      │            ┌─────────────────┴─────────────────┐
          │                │      stratum/ (V1)                    stratum/v2/ (V2)
   template.rs             │      JSON over TCP              Noise_NX + binary frames
   block.rs                │            └─────────────────┬─────────────────┘
          │                │                    stratum/search.rs
          │                │                    (share searches over &dyn ShareJob)
          ▼                ▼                              ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │ search engines:  cpu.rs + sha256.rs   gpu.rs + miner.wgsl   hybrid.rs │
   └─────────────────────────────────────────────────────────────────┘
          │                                               │
   rust-bitcoin verifies every winner             rust-bitcoin verifies every share
   check_block → submitblock → read tip back      mining.submit / SubmitSharesExtended
```

A **solo** run builds whole blocks from a node's template and submits them. A
**pool** run takes jobs from a pool, which owns the coinbase, and submits
shares. Both feed the same search engines, and both verify every result with
`rust-bitcoin` before anything leaves the process.

## Module map

| Module | Responsibility |
| --- | --- |
| `main.rs`, `lib.rs` | Entry point, crate root |
| `settings.rs` | The registry of every setting, and the `clap` command built from it |
| `constants.rs` | Every compiled-in default, and the reasoning behind each one |
| `runner.rs` | Configuration, mode dispatch, and the mining and benchmark loops |
| `rpc.rs` | A hand-rolled HTTP/1.1 JSON-RPC client for the loopback, authenticated by the cookie. `Chain` owns each network's port and datadir subdirectory |
| `template.rs` | `getblocktemplate` parsed into the fields a block commits to, including the version bits that may be rolled |
| `block.rs` | Coinbase, merkle root, header, `check_block` (the local rule checks), and `VersionRoll`, the version walk the solo and share searches share |
| `sha256.rs` | The midstate header hasher: a portable compression function, an x86 SHA-NI one, and the multi-lane variant |
| `cpu.rs` | The threaded CPU search, hasher selection, and the `Search` result that reports work done whether or not anything was found |
| `gpu.rs`, `miner.wgsl` | The GPU search and its correctness probe. `gpu.rs` generates the shader's unrolled SHA-256 rounds and appends them before compiling |
| `hybrid.rs` | Both devices on one template, on disjoint extranonces |
| `watch.rs` | The long-poll watcher thread, and `Signals`/`Ending`: the flags every search checks and the reason it reports for stopping |
| `validate.rs`, `lottery.rs` | The no-submit experiments: full validation except proof of work, and the digest distribution against theory |
| `rejections.rs`, `reorg.rs` | The block-writing experiments, regtest only |
| `stratum/` | The Stratum V1 client, plus what both clients share: `pool.rs` (configuration and URL parsing), `search.rs` (the share searches), `payout.rs` (who a job's coinbase pays) |
| `stratum/v2/` | The Stratum V2 client |
| `logger.rs`, `utils.rs` | The console and file log, and the formatting helpers its lines use |

## Settings

Every setting is registered once, in `settings.rs`, under its variable name
(`MINER_GPU_LANES`). The flag (`--gpu-lanes`) is derived from that name by a
rule instead of being written out, so the two spellings cannot drift apart.
`./m --help` is generated from the same registry.

Values resolve in one order: **flag, then environment variable, then the
`--config` file, then the compiled-in default**. Defaults live only in
`constants.rs`, and `clap` is given none. A config file is a third *source* for
the same settings, not a third spelling: its keys are the variable names, and it
is read only when named.

Three tests hold the lists together. The registry must match the settings
`Config` actually reads, the README's table, and `sample.env`. Adding a setting
without all four fails the suite.

## The solo pipeline

```text
getblocktemplate ──► Template ──► coinbase ──► merkle root ──► header ──► midstate
                                    │                                       │
                     BIP34 height, extranonce, tag,                 search engines
                     witness reserved value; witness                        │
                     commitment copied from the template            winner (nonce, version)
                                                                            │
         read the tip back ◄── submitblock ◄── check_block ◄── rust-bitcoin recomputes the hash
```

- **The coinbase** pays `MINER_ADDRESS` and carries the BIP34 height, an
  8-byte extranonce, and the coinbase tag. Its witness is the 32-byte reserved
  value, and the witness commitment is copied from the template's
  `default_witness_commitment`. Both are valid only for the template's own
  transaction set. Dropping or reordering a transaction would mean computing
  the witness merkle root instead. `validate.rs` is the one place that
  recomputes the commitment from the block's own wtxids, as a check that it is
  right rather than merely present.
- **The search order**: the nonce is innermost, because it costs nothing to
  change. The version comes next, at the cost of one compression to rebuild
  the midstate. The extranonce is outermost, because changing it means hashing
  the coinbase and the whole merkle branch again.
- **CPU workers split the extranonce space.** Worker *k* of *W* takes
  extranonces *start + k*, *start + k + W*, and so on, and walks all 2³² nonces
  under each. No two workers ever hash the same header.
- **The time** is honest: `max(curtime, mintime)` from the node. Manufacturing
  a timestamp to open testnet4's minimum-difficulty window is deliberately not
  done.
- **Before `submitblock`**, `check_block` states the height, commitment, merkle
  root, coinbase value, mintime and version rules locally, so a broken builder fails with a
  named rule instead of an opaque rejection. The node remains the authority.
- **After `submitblock`**, the tip is read back. A null answer means accepted,
  not necessarily best chain, and `inconclusive` is not a rejection. It is the
  answer for a valid block that does not extend the best chain.

### Version rolling on the solo search

`Template::rollable_bits` decides which version bits the GPU block search may
roll: BIP320's bits 13–28, minus every bit the template's version sets, minus
every bit `vbavailable` assigns to a deployment. A template without
`vbavailable` never rolls. A rolled version keeps the top bits `001`, never
clears a template bit, and changes nothing outside the rollable bits.
`check_block` enforces all of this. It is not simply "the BIP320 bits are free",
because Bitcoin Core counts unexpected bits towards its unknown-rules warning.

## Search engines

### CPU

The first 64 bytes of a header do not depend on the nonce, so their compression
(the *midstate*) is computed once per header, not once per nonce.
What remains per nonce is the second block of the first hash and the whole
second hash. `sha256.rs` provides these on two backends:

- **SHA-NI**: the x86 SHA extensions, written out by hand. It is selected by a
  runtime feature check, never a compile-time assumption, so one binary runs
  everywhere. It hashes `LANES` consecutive nonces per call, so that one
  nonce's rounds fill another's latency. The nonce is passed in a register,
  never through a copied buffer, which avoids a store-forwarding stall.
- **Portable**: a readable reference implementation, used where SHA-NI is
  absent and as the oracle SHA-NI is tested against.

**`screen` is a shortcut beside `hash`, never a change to it.** A header can
only win if the top word of its digest is small. That word is final after
round 60 of the second hash, three rounds before the end, so `screen` stops
there and decides almost every nonce without the last three rounds. Ties and zero words fall through to the full
hash. `screen` must return exactly the verdict that `hash` followed by the
target check would. The same shortcut runs in the shader.

`--cpu-percent` is a duty cycle: each worker hashes for that share of every
100 ms window and sleeps the rest.

### GPU

The GPU search is a persistent `wgpu` compute pipeline over `miner.wgsl`. The
division of labour is fixed:

- **The host owns everything that changes the merkle root**: the coinbase, the
  extranonce, and therefore the midstate.
- **The GPU owns the nonce space under one midstate.** A dispatch covers
  `lanes × nonces_per_lane` nonces and returns those that met the target, in a
  winner buffer of fixed capacity.

The details that matter:

- **The SHA-256 rounds are generated, not looped.** `gpu::unrolled_rounds`
  writes all 64 rounds out and appends them to the shader before compiling. As
  a loop, the round constants and message window were indexed dynamically and
  spilled to per-invocation memory, which made it about five times slower. The
  shader needs no 64-bit integer support.
- **Dispatches are pipelined.** `--gpu-pipeline` dispatches are in flight at
  once, so that readback overlaps compute.
- **A dispatch in flight belongs to the header it was submitted under.**
  Before anything changes the merkle root or the version, `finish` drains the
  engine, so no winner is verified against the wrong block. Finding a *block*
  may abandon the rest of the dispatch instead, because every other winner
  covers the same block. Finding a *share* may not, because every other winner
  in the dispatch is a separate share worth credit.
- **An overflowing winner buffer** is harmless for a block search, where any
  winner will do, and at regtest difficulty it happens routinely. It is fatal
  for the probe, which compares complete winner sets, and for a share search,
  where each dropped winner is a lost share.
- **Version pairs (AsicBoost).** Where two versions can be rolled, each lane
  hashes both over one shared message schedule (`search_pair`). The shader
  reports a nonce once per version that met the target, never *which* version.
  The host attributes each nonce by re-verifying it under each header with
  `rust-bitcoin`, and treats a count mismatch as an error.
- **The bind group layout is explicit**, because the `search` and `probe` entry
  points use different bindings, and an inferred layout would hold only one
  entry point's.

### Hybrid

`hybrid` runs the CPU and GPU searches on one template at once, starting half
the extranonce space apart, so neither ever hashes the other's headers. The
first device to find a block stops the other. On a laptop the two share one
power and thermal budget, so the CPU half runs at a lower clock than it would
alone.

## Template freshness and stopping

A watcher thread (`watch.rs`) holds a `getblocktemplate` long-poll open. Bitcoin
Core answers it on a new tip *or* on new transactions, so "stale" means "there
is better work", not only "the chain moved". Every search checks a shared set
of flags between batches, at least once per GPU dispatch, and reports why it
returned:

| `Ending` | Meaning | What the run does |
| --- | --- | --- |
| `Found` | A header met the target | Verify and submit. Outranks the rest: a block found in the same instant a flag is raised is still a block |
| `Stale` | The node has better work | Fetch the next template and continue |
| `Expired` | The template is older than `--template-seconds` | Fetch the next template and continue. Separate from `Stale` because a clock-based change (testnet4's window) produces no long-poll event |
| `Signalled` | Ctrl-C | Stop the run |

The watcher keeps a **generation counter**. Submitting a block changes the
tip, so the long-poll on the template just mined answers *after* the next
template has been fetched. Without the counter, that late answer would mark
the fresh template stale.

The long-poll's answer is itself a full template, and by default it is mined
directly (`--prefetch`). Benchmarks run without a watcher, so a measurement is
never cut short by new work.

## The pool clients

Both clients have the same shape. The pool owns the coinbase and decides what is
mined. The client splices its extranonce into the coinbase it was given, builds
headers, and submits shares. **The protocol cannot be discovered**: some pools
serve V1 and V2 on one port and tell them apart by the client's first bytes, so
a wrong guess hangs. The setting, or a `stratum2+tcp://` URL, decides.

### What both share

- **`search.rs`** holds the share searches (CPU, GPU, and GPU with version
  pairs). They take a `&dyn ShareJob`, a three-method trait (`target`,
  `version`, `header(extranonce, version)`), so either protocol's job reaches
  the same search. The roll order matches the solo search: nonce, then version,
  then extranonce2.
- **`ShareTarget`** is a newtype, not a `Target`. A share target is easier than
  the network's by construction, the opposite of the solo rule that a target
  may only be harder, so passing one through the other's validation is a
  compile error.
- **`payout.rs`** decodes each job's coinbase and logs who it pays, warning
  when nothing pays the worker's address. It reports and never refuses: the
  pool is the authority on everything except the proof of work.

### Stratum V1 (`stratum/`)

| File | Role |
| --- | --- |
| `wire.rs` | The byte-order conversions between Stratum's hex fields and header bytes |
| `messages.rs` | The JSON message shapes. Accepts a numeric or null `id`, and nothing else |
| `conn.rs` | The socket and handshake: `mining.configure` (BIP310), `subscribe`, `authorize`, `suggest_difficulty`. Call ids start at 1, so a pool's reply to a notification can never match a call |
| `job.rs` | The coinbase splice, the share target, and per-job version rollability |
| `run.rs` | The session loop: jobs, difficulty changes, submits, reconnects |
| `fixture.rs` | Test-only. Loads the committed captures in `tests/fixtures/` |

Behaviour learned from real pools, and kept because each one broke a client:

- **A reply's `id` may be null.** Some pools echo a null id, and others coerce
  it to 0.
- **`mining.suggest_difficulty` carries an id**, because at least one pool
  rejects the request without one. The difficulty is asked for twice, through
  that frame and through `d=` in the password, because neither works on every
  pool.
- **A difficulty change retargets every held job and wakes the search.** Pools
  judge a share by the difficulty they want *now*.
- **Version rollability is decided per job.** BIP310 does not say how a pool
  rebuilds the version, and pools differ: `(announced & !mask) | submitted`
  against `announced ^ submitted`. They agree only when the announced version
  has no bits inside the mask. Where they would disagree, the client rolls
  nothing and omits the sixth `mining.submit` parameter.

### Stratum V2 (`stratum/v2/`)

| File | Role |
| --- | --- |
| `codec.rs` | The spec's little-endian types |
| `frame.rs` | The six-byte frame header and the message table |
| `noise.rs` | The `Noise_NX` handshake (secp256k1 with ElligatorSwift, ChaCha20-Poly1305) and the certificate check against the pinned authority key |
| `conn.rs` | The socket, the cipher states, and the one point where `--pool-capture` records frames |
| `messages.rs` | The messages: twelve received, four sent |
| `job.rs` | A job plus a prevhash becomes a header |
| `run.rs` | The session loop: setup, channel open, jobs, targets, submits, reconnects |
| `scripted.rs` | Test-only. A scripted pool whose frames come from SRI's encoder |

Where V2 differs from V1, and why each choice is right for its protocol:

| Topic | V1 | V2 |
| --- | --- | --- |
| Transport | Plaintext JSON | Encrypted, and the server is authenticated against a pinned key |
| Difficulty request | `d=` and `suggest_difficulty` ask for *easier* work | `max_target` is a ceiling on the target, so it can only ask for *harder* work. The declared hash rate is what lowers difficulty |
| Held jobs on a new target | Retargeted, as measured on real pools | Kept: the spec applies `SetTarget` to future jobs, so `job.rs` snapshots the target at activation |
| Version rolling | Ambiguous reconstruction, decided per job | Explicit: `version_rolling_allowed` per job, and the share carries the full version |
| Request ids | Numeric or null, matched to calls | None |

Two V2 details that must hold:

- **The channel update restates the original request.** Once a session has
  measured its own rate, it sends a single `UpdateChannel` carrying the
  `max_target` the channel was *opened* with, never the target currently being
  served. A smaller value is a request the server must honour, so echoing the
  served target would lock the pool at its own floor.
- **Captures are taken after authentication, before parsing.** A frame is
  recorded once its AEAD tag has verified and before `messages.rs` reads it.
  The recorded bytes are therefore the pool's encoder's, and a capture tests the
  parser instead of copying it.

## Trust and safety rules

Each of these is enforced in code and covered by tests.

**What is reported is verified.**

- Only a header that `rust-bitcoin` verifies is ever reported, for blocks and
  shares alike, and for every GPU winner, not only the one that would be
  submitted. A fast hasher finds candidates. It never certifies one, and a
  disagreement fails loudly and names the hasher.
- Blocks pass `check_block` before `submitblock`, and the tip is read back
  afterwards.

**Credentials stay out of reach.**

- The node's cookie is the only credential path. No RPC password is ever
  configured.
- No credential is ever a flag, because command lines are visible to every
  user through `ps`. `MINER_POOL_PASS` is a difficulty request, not a password.
  The V2 authority key may be a flag because it is public.

**Nothing connects without being asked.**

- With `MINER_POOL` unset, no pool socket is opened in any mode.
- A config file is read only when named. One picked up from the working
  directory could supply `MINER_POOL`.
- `--version-rolling force` deliberately sends shares a pool did not agree to,
  so it is refused against anything that is not on the loopback.
- Under V2, an unpinned authority key is refused against anything that is not
  on the loopback. There is no trust-on-first-use path, `skip` is an explicit
  opt-out and never a default, and a `Reconnect` redirect is refused when
  nothing is pinned.

**Nothing is written where it should not be.**

- `rejections` and `reorg` write blocks, and are refused anywhere but regtest.
  The no-submit modes (`validate`, `lottery`, `watch`, `bench`, `probe`) may
  point at mainnet.
- `MINER_BITS` may only make the target harder, which keeps every block valid.
  An easier target is refused up front. The exception is `lottery`, which
  submits nothing.
- Timestamps are honest.

## Second opinions

Hand-written code is checked against independent implementations rather than
against itself:

| What | Checked against |
| --- | --- |
| The SHA-NI compression | The portable compression, over arbitrary blocks and not only header-shaped ones, and the `sha2` crate |
| The GPU shader | `rust-bitcoin` digests, including the mainnet genesis header, then the GPU's whole winner set against the CPU's. This is the `probe` mode |
| The Noise handshake | SRI's `noise_sv2`: this client's initiator completes a handshake against SRI's responder and carries traffic both ways |
| The V2 message codecs | SRI's `mining_sv2`, `common_messages_sv2` and `binary_sv2`, byte for byte |
| The V1 and V2 parsers | Sessions captured from real pools, in `tests/fixtures/` |
| Accepted shares in captures | Rebuilt with `rust-bitcoin`, not with the client's own `job.rs` |

The SRI crates are dev-dependencies only. Promoting any of them to a runtime
dependency would put a second copy of `secp256k1` and `bitcoin_hashes` in the
binary.

## Where the speed comes from

The README lists measured rates for the reference machine. They come from:

1. **The midstate.** The header's first 64 bytes are compressed once per
   header, not once per nonce.
2. **Early exit.** The first rounds of the second block are shared by every
   nonce and hashed once per header. `screen` stops the second hash after
   round 60.
3. **SHA-NI with interleaved lanes** on the CPU, with the nonce kept in a
   register.
4. **Unrolled rounds** in the shader, generated by the host.
5. **Version pairs** (AsicBoost) on the GPU: two headers per nonce over one
   message schedule, worth about 10%.

Any hash rate quoted for this project must name its hasher. `naive` and
`sha-ni` differ by more than 2x, and `portable` is a correctness reference, not
a performance result.
