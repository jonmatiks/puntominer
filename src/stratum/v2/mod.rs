//! The Stratum V2 client: the same job, over a binary protocol inside an
//! encrypted tunnel.
//!
//! A sibling of the V1 client beside it rather than a replacement for it, and
//! the two share exactly one thing: the share search. See
//! [`docs/architecture.md`](../../../docs/architecture.md) for how the two
//! stacks fit together.
//!
//! What is the same is worth saying first, because it is most of the client.
//! The pool still owns the coinbase and still decides what is mined; this
//! still splices an extranonce into a transaction it never reads, folds a
//! merkle path it was handed, and sends back a header that meets a target
//! easier than the network's. Nothing about the *mining* changed.
//!
//! Three things did:
//!
//! 1. **The wire is binary and little-endian.** [`codec`] is the whole of
//!    that, and it is the easy part — V1's byte-order minefield has no V2
//!    counterpart, because every integer goes one way round. What replaces it
//!    is that a message has no field names in it, so a parser that is one
//!    field out reads plausible values for everything after. `Reader::finish`
//!    is the only structural check there is, and every parse ends with it.
//! 2. **The session is encrypted, and the server is authenticated.**
//!    [`noise`] is `Noise_NX` over secp256k1 with an ElligatorSwift-encoded
//!    ECDH, and the pool's certificate is checked against an authority key
//!    this run was configured with. That is the hard part, and it is the one
//!    layer here where a bug is silent: a mis-ordered ECDH or a reused nonce
//!    produces a session that works perfectly and is not secure. It is
//!    checked against an independent implementation for exactly that reason —
//!    see the `noise_sv2` dev-dependency, which is `sha2`'s role played again.
//! 3. **A job is not a complete description of work.** A
//!    `NewExtendedMiningJob` carries the version, the merkle path and the
//!    coinbase halves; a `SetNewPrevHash` carries the previous hash, the time
//!    and the nbits. A *future* job has neither until a prevhash names it.
//!    [`job`] is where those two halves meet, and it is the one structural
//!    difference from V1 that is not about encoding.
//!
//! The same property holds as for the module above: **optional at runtime,
//! not at build time**. There is no Cargo feature and no `cfg`. This is always
//! compiled and is inert until `MINER_POOL_PROTOCOL=v2` asks for it.

pub mod codec;
pub mod conn;
pub mod frame;
pub mod job;
pub mod messages;
pub mod noise;
pub mod run;
#[cfg(test)]
mod scripted;
