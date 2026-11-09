# Test fixtures

Pool A and Pool B stand for the two third-party pools the V1 captures were
taken against: Pool A a hosted solo pool on mainnet, Pool B an open-source
pool, public and run locally.

`stratum-pool-a.jsonl` is one captured Stratum V1 session, taken on
18 September 2026 against Pool A's solo port by cpuminer 2.5.1.

One record per line:

```json
{"ts":"2026-09-18 00:08:20","dir":"recv","line":"{\"id\":1,\"result\":[...]}"}
```

`line` is the **exact text that crossed the wire**, kept as a string rather
than re-encoded JSON, because the parser under test has to be fed the original
bytes rather than a normalised reserialisation of them. `dir` and `ts` carry
what the wire itself does not: who sent the frame, and when.

42 frames — the whole handshake, 11 `mining.notify`, and 13 `mining.submit`
that the pool **accepted**. Those thirteen are the point. They are the only
available proof that a from-scratch client's byte-order handling is right, and
`every_accepted_submit_rebuilds_into_a_rust_bitcoin_header_that_is_a_share`, in
[`src/stratum/job.rs`](../../src/stratum/job.rs), rebuilds every one of them
from its notify to demonstrate it.

## `stratum-pool-b.jsonl`

A second, deliberately tiny capture — 7 frames, 45 seconds, one thread — taken
against Pool B's public instance on the same day. It contains
**no accepted shares and no `mining.submit` at all**, and that is not a defect:
Pool B ignores `d=` in the password and cpuminer 2.5.1 sends no
`mining.suggest_difficulty`, so the session runs at the pool's default
difficulty, which is weeks per share at cpuminer's rate. It is a
shape fixture, not an oracle.

What it pins down, which the Pool A capture cannot:

- **`result[0]` holds one entry**, not two. Pool A advertises
  `mining.set_difficulty` and `mining.notify`; Pool B advertises only
  `mining.notify`. A parser that reads the subscription list positionally
  works against one of these two and not the other.
- **The subscription id equals the `extranonce1`** here (`19aeecb4` for both),
  where on other pools they differ. A test using only this fixture would pass
  while conflating them, which is why the rule is stated against Pool A's
  frames and this file is the counter-shape.
- **Key order differs between pools.** Pool B answers
  `{"id","error","result"}`; Pool A answers `{"id","result","error"}`.
  `serde_json` does not care, and no hand-rolled parser here may either.

## `stratum-pool-b-rolled.jsonl`

This client, not cpuminer, against a local Pool B on regtest. It was taken
on 28 September 2026 through a logging relay, which sits between the client and
the pool and records every line that crosses. 35 frames, and 8
`mining.submit` frames the pool **accepted**. Every one of them carries the
sixth BIP310 parameter, and 5 are at a rolled version.

It fills the one gap the Pool A capture leaves. cpuminer 2.5.1 does not roll
versions, so before this file no committed fixture contained an accepted share
with rolled bits. The oracle is stronger than a pool's word, too. Regtest's
target is easier than any share's, so each of these shares was also a block,
and the node kept every one. Blocks 120 to 122 of that chain carry the rolled
versions exactly.

What it does not pin:

- The chain announces `20000000`, so the spec's reconstruction and
  Pool B's XOR build the same header, and the tests in
  `src/stratum/job.rs` rebuild every share. The `30000000` case, where the two disagree, is
  `stratum-pool-b-30000000.jsonl`, below.
- It is one pool on one chain. `stratum-pool-a-rolled.jsonl`, below, is the
  same client against a second pool on mainnet.

The capture came from this client, and that is fine: the oracle is the pool's
acceptance and the node's, not the client that produced the share.

## `stratum-pool-a-rolled.jsonl`

The same relay, this time in front of Pool A's solo port, on
28–29 September 2026. It is 45 minutes of hybrid mining at about 595 MH/s:
114 frames, of which 93 are `mining.notify`, and 6 `mining.submit` frames the
pool **accepted**. 4 of the 6 are at a rolled version (`2002a000` three times,
`20034000` once). None was a block, as expected at mainnet difficulty.

It puts a production pool's acceptance behind rolled shares, which the
cpuminer capture could not, because cpuminer does not roll.

One difference from the 18 September session is worth writing down. The client
asked for difficulty 1 both ways, through `d=1` and `mining.suggest_difficulty`,
and Pool A answered **64**. On 18 September it granted 1. The first share took
11 minutes, and until it arrived the pool's dashboard showed no hashrate for
the worker.

## `stratum-pool-b-30000000.jsonl`

The same relay and local Pool B, on 29 September 2026, but with the regtest
node started with `-blockversion=805306368`, so every job announces `30000000`.
It has 133 frames and 37 accepted `mining.submit` frames. Each was also a block
the node kept.

This is the case `search::rollable` exists for. Bit 28 is inside BIP320's mask,
so the spec's reconstruction and Pool B's XOR build different headers from
the same submit. The client therefore rolls nothing, and none of the 37 submits
carries the sixth parameter. Bitcoin Core v31 announces `20000000` on regtest,
which is why the node had to be told to announce this.

It is also the evidence that the rule still matters against today's
Pool B. A throwaway build whose `rollable` always returned the agreed
mask sent `10000000` as the sixth parameter against the same pool. It had 7 of
7 shares rejected with `Difficulty too low`, one of them at difficulty 249,
which that build had also hashed as a block. That is the 18 September symptom
exactly.

## `sv2-puntohunter.hex`

The first Stratum V2 fixture. It was taken on 6 November 2026, this client
against PuntoHunter `0.1.17+242334b5`'s solo V2 port on its own regtest
harness, by `MINER_POOL_CAPTURE`. Two sessions: two minutes on the CPU and
two on the GPU.

One frame per line: `recv` or `send`, the hex of the six-byte header and the
payload, and the message name after a `#`. A `# connected` line opens each
session.

```text
recv 000001060000020000000000 # SetupConnection.Success
```

**There is no wire capture under Noise**, because `tcpdump` sees ciphertext.
So this is the plaintext at the client's decrypt boundary: each `recv` frame
was written after its AEAD tag verified and before `messages.rs` parsed it. A
wrong `noise.rs` cannot produce frames that authenticate, so the bytes are
PuntoHunter's, which come from SRI's encoder. The `send` lines are this
client's own and are there only so that the shares can be rebuilt.

82 frames: 20 `NewExtendedMiningJob`, 18 `SetNewPrevHash`, 2 `SetTarget` from
vardiff, and 16 `SubmitSharesExtended` with 16 `SubmitShares.Success`. Ten of
the shares are at rolled versions. Regtest's target is easier than any
share's, so every share was also a block, and the chain kept all sixteen,
blocks 103 to 118.

What it does not hold: a `SetTarget` against a job in flight, a
`SetExtranoncePrefix`, a rejected share, or a job announcing `30000000`.
PuntoHunter sent none of them. `src/stratum/v2/scripted.rs` covers those.

## Why this is safe to commit

A Stratum session against a public solo pool carries no credential. The
username is a payout address, which is public data and is already in
`src/constants.rs`; the password is `d=1`, a share-difficulty request. The
rolled capture's addresses, and the SV2 one's, belong to throwaway regtest
wallets. The SV2 capture holds nothing from the handshake. Nothing
here is a secret, unlike the raw capture in `results/` — which is gitignored
not because it is sensitive but because it is a local artifact full of
cpuminer's own hash-rate lines and libcurl tracing.

## Regenerating

The capture tooling behind these files is not part of this repository. A V2
fixture needs nothing but this client: `MINER_POOL_CAPTURE` writes the frames
in the format above. A V1 session is plaintext JSON, so any logging proxy
between the client and the pool can record one.

A regenerated fixture is a different session against a different chain tip, so
regenerate only with a reason — the committed one is already proven, and tests
pinned to its values would have to be rewritten.

## `template-*.json`

`getblocktemplate` answers captured on 6 November 2026 from Bitcoin Core
v31.1, for `Template::rollable_bits`. These were captured for the solo
block search's version rolling:

| File | Node | Version | `vbavailable` |
| --- | --- | --- | --- |
| `template-mainnet-974833.json` | mainnet | `20000000` | empty |
| `template-regtest-1.json` | fresh regtest | `20000000` | empty |
| `template-regtest-145-testdummy.json` | regtest after 144 blocks | `30000000` | `testdummy: 28` |
| `template-regtest-1-blockversion.json` | fresh regtest, `-blockversion=805306368` | `30000000` | empty |

The regtest files are verbatim. **The mainnet one is not.** Its 2,886
transactions, 4.2 MB, are replaced by an empty list, and the rest is
re-indented. Its `coinbasevalue` and `default_witness_commitment` therefore
belong to the transactions that were dropped. Nothing that reads this file
may build a block from it.
