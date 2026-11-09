//! One `mining.notify` plus the session state a header needs, and the target a
//! share is measured against.
//!
//! This is where the splice lives — `coinb1 ++ extranonce1 ++ extranonce2 ++
//! coinb2`, hashed, folded, framed — and it is the last step before anything
//! hashes. Everything it does is [`wire`] called in the right
//! order; what it adds is that the order is written down once.
//!
//! The client needs no transaction to build a header. The pool splits the
//! coinbase around the extranonce and hands over a merkle branch, so a miner
//! holds no transaction set at all — the coinbase is decoded once per job only
//! to report who it pays, in [`payout`](super::payout). That is also what
//! makes the pool, and not this miner, the owner of the coinbase outputs —
//! which is the reason a pool client is a different program from the rest of
//! this repository rather than a mode of it.

use std::collections::HashMap;

use bitcoin::{
    BlockHash, Target, TxMerkleNode,
    block::{Header, Version},
};
use serde_json::{Value, json};

use crate::block::Extranonce;

use super::{
    messages::{Notify, Subscribed},
    wire,
};

/// How many jobs are remembered at once.
///
/// A job outlives its notify: shares against a previous job are legitimate
/// until `clean_jobs`, so a single current job would throw away every share
/// found in the moment a new notify arrives. Small, because the only jobs worth
/// keeping are the ones a search could still be inside, and a pool that has
/// sent sixteen notifies without a `clean_jobs` has moved on from all of them.
const JOB_TABLE_MAX: usize = 16;

/// The target a share is measured against.
///
/// **A distinct type from [`Target`], deliberately.** `MINER_BITS` may only
/// make the network target *harder* and refuses anything easier, because an
/// easier one produces headers a node rejects. A share target is easier than
/// the network's by construction — that is what a share *is* — so the two are
/// governed by opposite rules, and one routed through the other's validation
/// would be refused for being exactly what it is meant to be. A newtype makes
/// that a compile error rather than a runtime surprise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareTarget(Target);

impl ShareTarget {
    /// The target a scalar `mining.set_difficulty` names.
    ///
    /// `target = 0xffff * 2^208 / difficulty`, which is difficulty 1's target
    /// scaled — the same definition Bitcoin's own difficulty uses, and the one
    /// every pool computes its verdict with.
    ///
    /// Fallible rather than clamped, because there is no sensible clamp. A
    /// difficulty small enough to push the target past 2^256 would make every
    /// header a share, and one large enough to push it below 1 would make no
    /// header ever a share; both are a pool sending nonsense, and silently
    /// mining under a made-up target is worse than stopping.
    ///
    /// The arithmetic is 256-bit and the input is an `f64`, so it is done by
    /// taking the float apart exactly — `difficulty = mantissa * 2^-scale`,
    /// which every normal `f64` is — and then placing the quotient's bits. The
    /// division truncates, which makes the target a shade *stricter* than
    /// exact, by under one part in 2^63: a share this client submits is one the
    /// pool will agree with, never the other way round.
    pub fn from_difficulty(difficulty: f64) -> Result<Self, String> {
        if !difficulty.is_finite() || difficulty <= 0.0 {
            return Err(format!(
                "a share difficulty of {difficulty} is not a difficulty"
            ));
        }

        let bits = difficulty.to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as i32;
        if exponent == 0 {
            return Err(format!(
                "a share difficulty of {difficulty} is subnormal, which no pool means"
            ));
        }
        // Exact: every normal f64 is `mantissa * 2^-scale` with a 53-bit
        // mantissa, so nothing is lost taking it apart this way.
        let mantissa = u128::from((1u64 << 52) | (bits & ((1u64 << 52) - 1)));
        let scale = 1075 - exponent;

        // 0xffff * 2^208 / difficulty, rearranged so the division happens in a
        // u128 with 64 bits of headroom and the scaling happens afterwards:
        //     = (0xffff * 2^100 / mantissa) << (108 + scale)
        let quotient = (0xffffu128 << 100) / mantissa;
        let shift = 108 + scale;

        // Placed bit by bit rather than shifted, because the shift can go in
        // either direction and this way there is no second code path to be
        // wrong in. 128 iterations, once per `mining.set_difficulty`.
        let mut bytes = [0u8; 32];
        for bit in 0..128 {
            if (quotient >> bit) & 1 == 0 {
                continue;
            }
            let position = shift + bit;
            if position >= 256 {
                return Err(format!(
                    "a share difficulty of {difficulty} puts the target past 2^256, \
                     which would make every header a share"
                ));
            }
            if position < 0 {
                // Below the bottom bit: precision this target does not have.
                continue;
            }
            let position = position as usize;
            bytes[31 - position / 8] |= 1 << (position % 8);
        }

        if bytes == [0u8; 32] {
            return Err(format!(
                "a share difficulty of {difficulty} puts the target below 1, \
                 which would make no header ever a share"
            ));
        }

        Ok(Self(Target::from_be_bytes(bytes)))
    }

    /// The target a Stratum V2 `U256` names.
    ///
    /// A sibling of [`Self::from_difficulty`] and a much simpler one: SV2
    /// sends the target itself rather than a difficulty to divide by, so
    /// there is no float to take apart, no truncation, and none of the
    /// exactness argument that function's doc comment has to make. **The
    /// bytes are little-endian**, as every SV2 integer is — see
    /// [`v2::codec`](super::v2::codec), where that is the one rule the whole
    /// binary format has.
    ///
    /// The newtype is unchanged and its reason for existing is unchanged: a
    /// share target is easier than the network's by construction, so routing
    /// one through `MINER_BITS` validation stays a compile error.
    pub fn from_u256(bytes: [u8; 32]) -> Self {
        Self(Target::from_le_bytes(bytes))
    }

    /// And back, for the `max_target` this client asks a channel to open with.
    pub fn to_u256(self) -> [u8; 32] {
        self.0.to_le_bytes()
    }

    /// The target itself, for the one place it has to meet `rust-bitcoin`.
    pub fn inner(&self) -> Target {
        self.0
    }

    /// Whether a header is a share.
    pub fn is_met_by(&self, hash: BlockHash) -> bool {
        self.0.is_met_by(hash)
    }

    /// The difficulty this target represents, for the log.
    pub fn difficulty(&self) -> f64 {
        self.0.difficulty_float()
    }
}

impl std::fmt::Display for ShareTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "difficulty {:.6}", self.difficulty())
    }
}

/// One job: a notify, the session state it needs, and the target it was
/// announced under.
#[derive(Clone, Debug)]
pub struct Job {
    notify: Notify,
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    /// The share target this job is currently measured against.
    ///
    /// Set from the session's difficulty when the notify arrives, and moved by
    /// [`Jobs::retarget`] when the pool changes it. See that function: which of
    /// those two a pool credits by is a measured fact rather than a protocol
    /// rule, and the measurement went against the obvious answer.
    target: ShareTarget,
}

impl Job {
    pub fn new(notify: Notify, subscribed: &Subscribed, target: ShareTarget) -> Self {
        Self {
            notify,
            extranonce1: subscribed.extranonce1.clone(),
            extranonce2_size: subscribed.extranonce2_size,
            target,
        }
    }

    pub fn id(&self) -> &str {
        &self.notify.job_id
    }

    pub fn clean_jobs(&self) -> bool {
        self.notify.clean_jobs
    }

    pub fn target(&self) -> ShareTarget {
        self.target
    }

    /// The version the pool announced, before any rolling.
    pub fn version(&self) -> u32 {
        self.notify.version
    }

    pub fn ntime(&self) -> u32 {
        self.notify.ntime
    }

    pub fn extranonce2_size(&self) -> usize {
        self.extranonce2_size
    }

    /// The spliced coinbase for one extranonce2.
    ///
    /// The pool's own bytes on both sides and this client's in the middle. The
    /// width is the pool's and the interpretation is this client's — see
    /// [`wire::extranonce2_bytes`].
    pub fn coinbase(&self, extranonce2: Extranonce) -> Vec<u8> {
        let mut coinbase =
            Vec::with_capacity(self.notify.coinb1.len() + self.notify.coinb2.len() + 16);
        coinbase.extend_from_slice(&self.notify.coinb1);
        coinbase.extend_from_slice(&self.extranonce1);
        coinbase.extend_from_slice(&wire::extranonce2_bytes(
            extranonce2.0,
            self.extranonce2_size,
        ));
        coinbase.extend_from_slice(&self.notify.coinb2);
        coinbase
    }

    /// The merkle root the coinbase folds to.
    ///
    /// The coinbase in a `mining.notify` is the stripped form, so its double
    /// SHA-256 is the txid directly — there is no witness to serialize past.
    pub fn merkle_root(&self, extranonce2: Extranonce) -> TxMerkleNode {
        wire::fold_merkle(
            wire::sha256d(&self.coinbase(extranonce2)),
            &self.notify.branch,
        )
    }

    /// The 80-byte header, as `rust-bitcoin` holds it.
    ///
    /// Infallible: every field was checked when the notify was parsed and the
    /// extranonce2 has no width it can violate. The nonce is left at zero — it
    /// is what the search fills in, and a header is keyed for the midstate by
    /// everything except it.
    pub fn header(&self, extranonce2: Extranonce, version: u32) -> Header {
        Header {
            version: Version::from_consensus(version as i32),
            prev_blockhash: self.notify.prevhash,
            merkle_root: self.merkle_root(extranonce2),
            time: self.notify.ntime,
            bits: self.notify.bits,
            nonce: 0,
        }
    }

    /// The `mining.submit` parameters for a header that met the target.
    ///
    /// Positional, in the protocol's order, with `ntime` and `nonce` going back
    /// out as big-endian hex — the opposite of how the header holds them. The
    /// `ntime` comes from the header rather than from the notify, so that a
    /// search which rolled the clock submits the time it actually hashed.
    ///
    /// `mask` is the version bits the pool agreed this client may roll, and its
    /// presence is what decides whether the BIP310 sixth parameter is sent at
    /// all. **Only the masked bits go out**, not the whole version: the pool
    /// rebuilds the header as `(announced & !mask) | (submitted & mask)`, so
    /// sending the full version would hand it bits it will ignore and hide the
    /// one thing the field exists to carry. Without a mask the parameter is
    /// omitted entirely — a five-element submit is what every pool understood
    /// before 2018, and a sixth element a pool did not ask for is a frame it
    /// may refuse to parse.
    pub fn submit_params(
        &self,
        user: &str,
        extranonce2: Extranonce,
        header: &Header,
        mask: Option<u32>,
    ) -> Value {
        let extranonce2 = wire::extranonce2_bytes(extranonce2.0, self.extranonce2_size);
        let mut params = vec![
            json!(user),
            json!(self.notify.job_id),
            json!(
                extranonce2
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            json!(wire::be_hex_from_u32(header.time)),
            json!(wire::be_hex_from_u32(header.nonce)),
        ];
        if let Some(mask) = mask {
            params.push(json!(wire::be_hex_from_u32(
                header.version.to_consensus() as u32 & mask
            )));
        }
        Value::Array(params)
    }
}

/// The V1 side of the share search's contract.
///
/// Three lines of forwarding, and the reason it is a trait impl rather than
/// the inherent methods being used directly is the SV2 client:
/// `search_shares` takes `&dyn ShareJob` so that it reaches the same CPU, GPU
/// and hybrid loops. Nothing about V1 changed, which is what
/// the existing tests in [`search`](super::search) assert by still passing
/// with no edit to their bodies.
impl super::search::ShareJob for Job {
    fn target(&self) -> ShareTarget {
        Job::target(self)
    }

    fn version(&self) -> u32 {
        Job::version(self)
    }

    fn header(&self, extranonce2: Extranonce, version: u32) -> Header {
        Job::header(self, extranonce2, version)
    }
}

/// The jobs a connection is currently willing to submit shares against.
///
/// Keyed by the pool's job id, which is **pool-global rather than
/// per-connection** — two Pool A sessions saw the same id — so the table is
/// keyed by id but owned by the connection. A reconnect drops it wholesale
/// rather than merging, because the new `extranonce1` invalidates every entry:
/// the coinbase under it would splice the old pool half.
#[derive(Debug, Default)]
pub struct Jobs {
    table: HashMap<String, Job>,
    /// Insertion order, so the bound evicts the oldest rather than an arbitrary
    /// entry. A `HashMap` alone would evict whichever the hasher happened to
    /// reach first, which is the entry a search might still be inside.
    order: Vec<String>,
    current: Option<String>,
}

impl Jobs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a notify's job, and return whether it invalidated everything else.
    ///
    /// `clean_jobs` maps onto the existing stale discipline: it is the pool
    /// saying the chain moved, so every job before it is dead and a search
    /// inside one of them is spending electricity on a block that already has a
    /// successor. The caller raises `Signals::mark_stale` on a `true` here.
    pub fn accept(&mut self, job: Job) -> bool {
        let clean = job.clean_jobs();
        if clean {
            self.table.clear();
            self.order.clear();
        }

        let id = job.id().to_string();
        if self.table.insert(id.clone(), job).is_none() {
            self.order.push(id.clone());
        }
        self.current = Some(id);

        while self.order.len() > JOB_TABLE_MAX {
            let oldest = self.order.remove(0);
            // Never the one just accepted, which the bound cannot reach.
            self.table.remove(&oldest);
        }

        clean
    }

    /// The job a share names, which is not always the newest one.
    pub fn get(&self, id: &str) -> Option<&Job> {
        self.table.get(id)
    }

    /// The job to grind now: the most recent notify.
    pub fn current(&self) -> Option<&Job> {
        self.current.as_ref().and_then(|id| self.table.get(id))
    }

    /// Point every held job at a new share target.
    ///
    /// **This rule was first written down backwards, and corrected by
    /// measurement.**
    /// The original reasoning was that a `set_difficulty` between a notify and
    /// a share found under it must not retroactively change what that share was
    /// worth, because the pool credits the difficulty in force when the job was
    /// sent. A local Pool B on 18 September 2026 does the opposite: it
    /// raised the difficulty by vardiff and judged the job already in flight at
    /// the new one, answering `Difficulty too low` to seven shares in a row
    /// that were perfectly good at the difficulty the job arrived under.
    ///
    /// So the pool's *current* difficulty governs, and a client that kept the
    /// announced one submits shares below the bar and counts rejects it caused
    /// itself — which is what the old rule was trying to avoid, in the other
    /// direction. Retargeting can only make the target harder in the case that
    /// matters; if a pool lowers its difficulty the worst cost is shares not
    /// found until the next notify.
    pub fn retarget(&mut self, target: ShareTarget) {
        for job in self.table.values_mut() {
            job.target = target;
        }
    }

    /// Drop everything, on reconnect or on a new `extranonce1`.
    pub fn clear(&mut self) {
        self.table.clear();
        self.order.clear();
        self.current = None;
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        super::{fixture, messages::Incoming},
        *,
    };

    /// Difficulty 1's target, which is also `Target::MAX`.
    const DIFFICULTY_ONE: Target = Target::MAX;

    #[test]
    fn difficulty_one_is_the_target_everything_else_is_measured_against() {
        let share = ShareTarget::from_difficulty(1.0).expect("difficulty 1 is a difficulty");
        assert_eq!(share.inner(), DIFFICULTY_ONE);
        assert_eq!(
            share.inner().to_be_bytes()[..6],
            [0x00, 0x00, 0x00, 0x00, 0xff, 0xff],
            "0xffff * 2^208, the number every pool divides"
        );
    }

    #[test]
    fn a_difficulty_halves_the_target_when_it_doubles() {
        // The relation the whole share economy rests on: expected hashes per
        // share is difficulty * 2^32, because the target is inversely
        // proportional and digests are uniform.
        let one = ShareTarget::from_difficulty(1.0)
            .unwrap()
            .inner()
            .to_be_bytes();
        let two = ShareTarget::from_difficulty(2.0)
            .unwrap()
            .inner()
            .to_be_bytes();
        let half = ShareTarget::from_difficulty(0.5)
            .unwrap()
            .inner()
            .to_be_bytes();

        // 0xffff * 2^207 and 0xffff * 2^209, read off the byte they land in.
        assert_eq!(&one[4..6], &[0xff, 0xff]);
        assert_eq!(&two[4..7], &[0x7f, 0xff, 0x80]);
        assert_eq!(&half[3..6], &[0x01, 0xff, 0xfe]);
    }

    #[test]
    fn a_difficulty_round_trips_through_the_target_it_names() {
        // Every difficulty a pool has been observed to set, plus the extremes.
        // `difficulty_float` is rust-bitcoin's own inverse, so this is the
        // conversion checked against a second implementation rather than
        // against itself.
        for difficulty in [
            0.001, 0.5, 1.0, 2.0, 3.0, 512.0, 1000.0, 65536.0, 100_000.0, 1e9, 1.2345e12,
        ] {
            let share = ShareTarget::from_difficulty(difficulty)
                .unwrap_or_else(|why| panic!("{difficulty} should be a difficulty: {why}"));
            let back = share.difficulty();
            let error = (back - difficulty).abs() / difficulty;
            assert!(
                error < 1e-12,
                "difficulty {difficulty} came back as {back}, a relative error of {error}"
            );
        }
    }

    #[test]
    fn the_target_is_never_looser_than_the_difficulty_asked_for() {
        // Truncation must go one way. A target a shade too easy means shares
        // the pool rejects as low difficulty; a shade too hard means shares
        // that are simply never found, which costs nothing measurable. The
        // division truncates, so this is the direction it must fall in.
        for difficulty in [3.0, 7.0, 11.0, 1e3 + 0.5, 12345.678] {
            let share = ShareTarget::from_difficulty(difficulty).unwrap();
            assert!(
                share.difficulty() >= difficulty,
                "a target for difficulty {difficulty} reports {} and is therefore looser",
                share.difficulty()
            );
        }
    }

    #[test]
    fn a_difficulty_no_pool_means_is_refused_rather_than_clamped() {
        // There is no sensible clamp: too small makes every header a share and
        // too large makes none, and mining under a made-up target is worse than
        // stopping and saying so.
        for nonsense in [
            0.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::MIN_POSITIVE / 2.0,
            1e-20,
            1e80,
        ] {
            assert!(
                ShareTarget::from_difficulty(nonsense).is_err(),
                "{nonsense} is not a share difficulty"
            );
        }
    }

    /// Rebuild the Pool A capture as jobs, keyed by id, with the session state
    /// the handshake established.
    fn captured_jobs() -> (Vec<fixture::Frame>, Subscribed, HashMap<String, Job>) {
        let frames = fixture::load(fixture::POOL_A);

        let reply = frames
            .iter()
            .find(|frame| !frame.is_send() && frame.json["id"] == 1)
            .expect("the capture opens with a subscribe reply");
        let subscribed =
            Subscribed::parse(reply.result().expect("a result")).expect("a subscribe reply");

        let difficulty = frames
            .iter()
            .find_map(|frame| match Incoming::parse(&frame.line) {
                Ok(Incoming::SetDifficulty(value)) => Some(value),
                _ => None,
            })
            .expect("the capture sets a difficulty");
        let target = ShareTarget::from_difficulty(difficulty).expect("a captured difficulty");

        let jobs = frames
            .iter()
            .filter_map(|frame| match Incoming::parse(&frame.line) {
                Ok(Incoming::Notify(notify)) => Some(notify),
                _ => None,
            })
            .map(|notify| {
                let job = Job::new(notify, &subscribed, target);
                (job.id().to_string(), job)
            })
            .collect();

        (frames, subscribed, jobs)
    }

    #[test]
    fn every_accepted_submit_rebuilds_into_a_rust_bitcoin_header_that_is_a_share() {
        // The second half of the oracle. `wire.rs`
        // already proved the conversions against hand-framed bytes; this proves
        // the layer built on them, through `rust-bitcoin`'s own `Header` and
        // its own `block_hash`. Two paths to the same thirteen shares.
        let (frames, subscribed, jobs) = captured_jobs();
        let mut checked = 0;

        for submit in frames
            .iter()
            .filter(|frame| frame.is_send() && frame.method() == Some("mining.submit"))
        {
            let job = jobs
                .get(submit.param(1))
                .expect("every submit answers a notify");

            // cpuminer counts its extranonce2 little-endian and this client
            // counts big-endian; both are correct and neither is visible to the
            // pool, which sees only bytes. Read back as the counter whose
            // big-endian form *is* those bytes, so the splice is identical.
            let raw = wire::bytes_from_hex(submit.param(2)).expect("a captured extranonce2");
            assert_eq!(raw.len(), subscribed.extranonce2_size);
            let extranonce2 = Extranonce(u64::from_be_bytes(
                raw.clone().try_into().expect("eight bytes"),
            ));

            let mut header = job.header(extranonce2, job.version());
            header.time = wire::be_u32_from_hex(submit.param(3)).expect("a captured ntime");
            header.nonce = wire::be_u32_from_hex(submit.param(4)).expect("a captured nonce");

            assert!(
                job.target().is_met_by(header.block_hash()),
                "share {checked} on job {} rebuilt to {}, which is not a share at {}",
                job.id(),
                header.block_hash(),
                job.target()
            );

            // And the submit this client would have sent for that header is the
            // one the pool accepted, field for field. Nothing else proves that
            // a correct search would also be correctly *reported*.
            assert_eq!(
                job.submit_params(submit.param(0), extranonce2, &header, None),
                Value::Array(submit.params().to_vec()),
                "the rebuilt submit should be the captured one"
            );

            // And with a mask, the same submit plus exactly one field: the
            // rolled bits, which for an unrolled header are the announced
            // version's bits inside the mask.
            let rolled =
                job.submit_params(submit.param(0), extranonce2, &header, Some(0x1fff_e000));
            let rolled = rolled.as_array().expect("an array of parameters");
            assert_eq!(rolled.len(), 6, "BIP310 adds one parameter, not more");
            assert_eq!(rolled[..5], submit.params()[..5]);
            assert_eq!(
                rolled[5],
                json!("00000000"),
                "version 20000000 has no bits in the mask"
            );

            checked += 1;
        }

        assert_eq!(checked, 13, "every accepted submit in the capture");
    }

    /// Rebuild every accepted submit in one of this client's own captures, and
    /// return each header with whether it was at a rolled version.
    ///
    /// The shares were also verified independently, outside this repository;
    /// this is the Rust check. Replies are matched to requests by id, because this
    /// client sends `mining.configure` before `mining.subscribe`. Each header
    /// must be a share, and the submit this client builds for it — with or
    /// without the sixth parameter, as `search::rollable` decides for its job
    /// — must be the one the pool accepted.
    fn accepted_submits(capture: &str) -> Vec<(Header, bool)> {
        use super::super::search::rollable;

        let frames = fixture::load(capture);
        let mut asked = HashMap::new();
        let (mut subscribed, mut mask, mut target) = (None, None, None);
        let mut jobs = HashMap::new();
        let mut rebuilt = Vec::new();

        for frame in &frames {
            if frame.is_send()
                && let Some(method) = frame.method()
            {
                asked.insert(frame.json["id"].clone(), method.to_string());
            }
            match Incoming::parse(&frame.line).expect("every captured frame parses") {
                Incoming::Reply { result, .. } => {
                    match asked.get(&frame.json["id"]).map(String::as_str) {
                        Some("mining.subscribe") => {
                            subscribed = Some(Subscribed::parse(&result).expect("a subscribe"))
                        }
                        Some("mining.configure") => {
                            mask = result["version-rolling.mask"]
                                .as_str()
                                .map(|mask| wire::be_u32_from_hex(mask).expect("a mask"))
                        }
                        _ => {}
                    }
                }
                Incoming::SetDifficulty(difficulty) => {
                    target = Some(ShareTarget::from_difficulty(difficulty).unwrap())
                }
                Incoming::Notify(notify) => {
                    let job = Job::new(
                        notify,
                        subscribed.as_ref().expect("subscribed before any job"),
                        target.expect("a difficulty before any job"),
                    );
                    jobs.insert(job.id().to_string(), job);
                }
                _ => {}
            }
            if !(frame.is_send() && frame.method() == Some("mining.submit")) {
                continue;
            }

            // Judged at the difficulty in force when it was sent, which is
            // what both pools do — see `Jobs::retarget`.
            let mut job = jobs
                .get(frame.param(1))
                .expect("a submit answers a job")
                .clone();
            job.target = target.expect("a difficulty");
            let mask = rollable(job.version(), mask);

            let raw = wire::bytes_from_hex(frame.param(2)).expect("an extranonce2");
            let extranonce2 = Extranonce(u64::from_be_bytes(raw.try_into().expect("8 bytes")));
            let version = match mask {
                Some(mask) => {
                    let bits = wire::be_u32_from_hex(frame.param(5)).expect("rolled bits");
                    (job.version() & !mask) | bits
                }
                None => job.version(),
            };

            let mut header = job.header(extranonce2, version);
            header.time = wire::be_u32_from_hex(frame.param(3)).expect("an ntime");
            header.nonce = wire::be_u32_from_hex(frame.param(4)).expect("a nonce");

            assert!(
                job.target().is_met_by(header.block_hash()),
                "{capture} submit {} at version {version:08x} is not a share at {}",
                rebuilt.len(),
                job.target()
            );
            assert_eq!(
                job.submit_params(frame.param(0), extranonce2, &header, mask),
                Value::Array(frame.params().to_vec()),
                "the submit this client builds is the one the pool accepted"
            );
            rebuilt.push((header, version != job.version()));
        }
        rebuilt
    }

    #[test]
    fn every_accepted_rolled_submit_on_regtest_is_a_share_and_a_block() {
        // Regtest's target is easier than any share's, and the node kept
        // every one of these as a block.
        let rebuilt = accepted_submits(fixture::POOL_B_ROLLED);
        assert_eq!(rebuilt.len(), 8);
        assert_eq!(rebuilt.iter().filter(|(_, rolled)| *rolled).count(), 5);
        assert!(
            rebuilt
                .iter()
                .all(|(header, _)| super::super::search::is_block(header))
        );
    }

    #[test]
    fn a_version_with_a_bit_inside_the_mask_is_mined_unrolled_and_every_share_counts() {
        // Regtest made to announce `30000000` with `-blockversion`. Bit 28 is
        // inside BIP320's mask, so BIP310's two readings disagree and this
        // client rolls nothing and sends no sixth parameter — which the
        // helper's submit comparison asserts, with `rollable` answering `None`.
        // All 37 were accepted. The same pool rejected 7 of 7 from a build
        // that sent the sixth parameter anyway.
        let rebuilt = accepted_submits(fixture::POOL_B_30000000);
        assert_eq!(rebuilt.len(), 37);
        for (header, rolled) in &rebuilt {
            assert!(!rolled);
            assert_eq!(header.version.to_consensus(), 0x3000_0000);
            assert!(super::super::search::is_block(header));
        }
    }

    #[test]
    fn every_accepted_rolled_submit_on_mainnet_is_a_share() {
        // The same client against Pool A, where a share is only a share.
        let rebuilt = accepted_submits(fixture::POOL_A_ROLLED);
        assert_eq!(rebuilt.len(), 6);
        assert_eq!(rebuilt.iter().filter(|(_, rolled)| *rolled).count(), 4);
        assert!(
            rebuilt
                .iter()
                .all(|(header, _)| !super::super::search::is_block(header))
        );
    }

    #[test]
    fn rolling_the_extranonce2_moves_the_merkle_root_and_nothing_else() {
        // The whole reason the extranonce2 exists: a new merkle root is a new
        // header prefix and therefore a fresh 2^32 nonces to walk. The same
        // argument `block.rs` makes for the coinbase extranonce, one layer up.
        let (_, _, jobs) = captured_jobs();
        let job = jobs.values().next().expect("the capture has jobs");

        let first = job.header(Extranonce(0), job.version());
        let second = job.header(Extranonce(1), job.version());

        assert_ne!(first.merkle_root, second.merkle_root);
        assert_eq!(first.prev_blockhash, second.prev_blockhash);
        assert_eq!(first.version, second.version);
        assert_eq!(first.bits, second.bits);
        assert_eq!(first.time, second.time);

        // And the splice is exactly the pool's bytes around this client's, in
        // that order, with nothing inserted and nothing dropped.
        let source = fixture::load(fixture::POOL_A);
        let source = source
            .iter()
            .find(|frame| frame.method() == Some("mining.notify") && frame.param(0) == job.id())
            .expect("the job came from a notify");
        let coinb1 = wire::bytes_from_hex(source.param(2)).expect("a captured coinb1");
        let coinb2 = wire::bytes_from_hex(source.param(3)).expect("a captured coinb2");

        let mut expected = coinb1.clone();
        expected.extend_from_slice(&[0x10, 0x08, 0x6b, 0xd1]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&coinb2);
        assert_eq!(job.coinbase(Extranonce(1)), expected);
        assert_eq!(
            job.coinbase(Extranonce(1)).len(),
            coinb1.len() + 4 + job.extranonce2_size() + coinb2.len()
        );
    }

    #[test]
    fn a_clean_jobs_notify_empties_the_table_and_a_dirty_one_does_not() {
        // "A job outlives its notify": shares against a previous job are
        // legitimate until `clean_jobs`, so the table only empties when the
        // pool says the chain moved.
        let (_, subscribed, _) = captured_jobs();
        let target = ShareTarget::from_difficulty(1.0).unwrap();
        let frames = fixture::load(fixture::POOL_A);
        let notify = |clean: bool, id: &str| {
            let source = frames
                .iter()
                .find(|frame| frame.method() == Some("mining.notify"))
                .expect("the capture has notifies");
            let mut params = source.params().to_vec();
            params[0] = json!(id);
            params[8] = json!(clean);
            Job::new(
                Notify::parse(&params).expect("a rewritten notify"),
                &subscribed,
                target,
            )
        };

        let mut jobs = Jobs::new();
        assert!(
            !jobs.accept(notify(false, "a")),
            "a dirty notify keeps the rest"
        );
        assert!(!jobs.accept(notify(false, "b")));
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs.current().map(Job::id), Some("b"));
        assert!(
            jobs.get("a").is_some(),
            "the older job is still submittable"
        );

        assert!(
            jobs.accept(notify(true, "c")),
            "a clean notify reports as one"
        );
        assert_eq!(jobs.len(), 1, "everything before it is dead");
        assert!(jobs.get("a").is_none() && jobs.get("b").is_none());
        assert_eq!(jobs.current().map(Job::id), Some("c"));

        jobs.clear();
        assert!(jobs.is_empty() && jobs.current().is_none());
    }

    #[test]
    fn the_job_table_is_bounded_and_evicts_the_oldest() {
        // A pool that never sends `clean_jobs` must not grow this without
        // limit, and the entry to drop is the one no search can still be
        // inside — which is the oldest, not whichever the hasher reaches first.
        let (_, subscribed, _) = captured_jobs();
        let target = ShareTarget::from_difficulty(1.0).unwrap();
        let frames = fixture::load(fixture::POOL_A);
        let source = frames
            .iter()
            .find(|frame| frame.method() == Some("mining.notify"))
            .expect("the capture has notifies");

        let mut jobs = Jobs::new();
        for index in 0..JOB_TABLE_MAX * 2 {
            let mut params = source.params().to_vec();
            params[0] = json!(format!("job{index}"));
            params[8] = json!(false);
            jobs.accept(Job::new(
                Notify::parse(&params).expect("a rewritten notify"),
                &subscribed,
                target,
            ));
        }

        assert_eq!(jobs.len(), JOB_TABLE_MAX);
        assert!(jobs.get("job0").is_none(), "the oldest went first");
        assert!(jobs.get("job31").is_some(), "the newest is always kept");
        assert_eq!(jobs.current().map(Job::id), Some("job31"));
    }

    #[test]
    fn a_job_keeps_the_target_it_was_announced_under() {
        // A `set_difficulty` between a notify and a share found under it must
        // not retroactively change what that share was worth. The pool credits
        // the difficulty in force when the job was sent.
        let (_, subscribed, _) = captured_jobs();
        let frames = fixture::load(fixture::POOL_A);
        let source = frames
            .iter()
            .find(|frame| frame.method() == Some("mining.notify"))
            .expect("the capture has notifies");
        let notify = Notify::parse(source.params()).expect("a captured notify");

        let easy = Job::new(
            notify.clone(),
            &subscribed,
            ShareTarget::from_difficulty(1.0).unwrap(),
        );
        let hard = Job::new(
            notify,
            &subscribed,
            ShareTarget::from_difficulty(512.0).unwrap(),
        );

        assert_ne!(easy.target(), hard.target());
        assert_eq!(easy.target().difficulty(), 1.0);
        assert_eq!(hard.target().difficulty(), 512.0);
        // Same job, same header: only what counts as a share differs.
        assert_eq!(
            easy.header(Extranonce(7), easy.version()),
            hard.header(Extranonce(7), hard.version())
        );
    }
}
