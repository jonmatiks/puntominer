//! The Stratum V1 client: taking work from a pool instead of from a node.
//!
//! Everything else in `src/` builds a whole block and submits it to
//! `bitcoind`. This does the opposite of both halves: the pool owns the
//! coinbase and therefore the payout, the pool decides what is being mined, and
//! what goes back is a *share* — a header that meets a target the pool set,
//! which is easier than the network's by construction and is almost never a
//! block. See [`docs/architecture.md`](../../docs/architecture.md) for how
//! this fits beside the solo miner.
//!
//! One property holds across the whole module and is worth stating once: **it
//! is optional at runtime, not at build time.** There is no Cargo feature and
//! no `cfg`. This module is always compiled and is inert until
//! `MINER_MODE=stratum` asks for it, which is how `lottery`, `reorg` and
//! `validate` are already optional and is the same call `Backend::detect`
//! makes about SHA-NI: one binary, deciding at runtime.
//!
//! The existing search is not modified to serve this. Where a rule inverts —
//! and two of them do, an overflowed GPU winner buffer and the reason to stop
//! at the first hit — this module gets a sibling rather than the existing
//! function getting a flag.

pub mod conn;
pub mod job;
pub mod messages;
pub mod payout;
pub mod pool;
pub mod run;
pub mod search;
pub mod v2;
pub mod wire;

#[cfg(test)]
pub mod fixture;
