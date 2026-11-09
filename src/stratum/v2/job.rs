//! Where a job and a prevhash become a header.
//!
//! **This file holds the one structural difference between the two protocols
//! that is not about encoding.** A V1 `mining.notify` is a complete
//! description of work: it carries the version, the prevhash, the coinbase
//! halves, the merkle branch, the time and the nbits, and a client can start
//! hashing the moment it arrives. An SV2 job is deliberately half of one.
//!
//! | Field | V1 | SV2 |
//! | --- | --- | --- |
//! | version, merkle path, coinbase halves | `mining.notify` | `NewExtendedMiningJob` |
//! | prev_hash, nbits | `mining.notify` | `SetNewPrevHash` |
//! | ntime | `mining.notify` | whichever of the two activated the job |
//!
//! That split is the whole latency argument for SV2: a pool can send the
//! expensive half — a merkle path over a full block template — *before* the
//! block it belongs to exists, as a **future job** with an empty `min_ntime`.
//! When the block arrives, the pool sends a `SetNewPrevHash` naming that job,
//! which is 48 bytes, and every miner switches at once.
//!
//! The consequence for this file is that **a job that cannot be mined must
//! not be representable as one that can.** So a [`Job`] always holds its
//! prevhash, and a future job is not a `Job` at all — it waits in [`Jobs`] as
//! the raw message it arrived as. There is no `Option` to forget to check and
//! no invariant kept by hand; `ShareJob::header` is total because the type
//! makes it so.
//!
//! Two snapshots are taken per job, and they are separate because the rules
//! that move them are opposites:
//!
//! - **The extranonce state is snapshotted when the job arrives.** §5.3.10
//!   says a `SetExtranoncePrefix` applies to jobs sent *after* it, so a job
//!   already in hand keeps the prefix it was built against.
//! - **The target is snapshotted when the job is activated.** §5.3.21 says a
//!   `SetTarget` applies to future jobs and to jobs not yet activated, and is
//!   "not applicable for already received jobs with `min_ntime=nTime`". That
//!   is **the exact opposite of the V1 rule** that
//!   [`Jobs::retarget`](super::super::job::Jobs::retarget) had to be corrected
//!   to by measurement. Both are right, each about its own protocol, and each
//!   file says so.

use std::collections::BTreeMap;

use bitcoin::{
    BlockHash, CompactTarget, TxMerkleNode,
    block::{Header, Version},
};

use super::{
    super::{job::ShareTarget, pool::BIP320_MASK, search::ShareJob, wire},
    messages::{ExtendedJob, NewPrevHash, Outgoing, submit_shares_extended},
};
use crate::block::Extranonce;

/// How many future jobs are queued at once.
///
/// A pool is entitled to pre-distribute several jobs for the next block —
/// §5.3.17 names the case, an empty block and a full one — but a
/// `SetNewPrevHash` invalidates every one it does not name, so the queue only
/// ever grows between blocks. Bounded anyway, because the queue is filled by
/// a stranger's server and nothing else limits it.
const FUTURE_JOBS_MAX: usize = 16;

/// What the channel contributes to a job's coinbase.
///
/// Snapshotted into each job as it arrives rather than read live, for the
/// §5.3.10 reason in this module's header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    pub channel_id: u32,
    /// The pool's own extranonce bytes, which sit in front of this client's.
    pub extranonce_prefix: Vec<u8>,
    /// How many bytes belong to this client. Requested as 8, which is
    /// [`Extranonce`]'s own width.
    pub extranonce_size: usize,
}

/// The half of a header that only a `SetNewPrevHash` can supply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Chain {
    prev_hash: BlockHash,
    bits: CompactTarget,
}

/// One job that can actually be mined.
///
/// Every field a header needs is present, which is what makes
/// [`ShareJob::header`] infallible. A future job is not one of these.
#[derive(Clone, Debug)]
pub struct Job {
    job: ExtendedJob,
    channel: ChannelState,
    chain: Chain,
    /// The time this job is hashed at. See [`Self::ntime`].
    ntime: u32,
    /// The target in force when this job was activated, and for its lifetime.
    target: ShareTarget,
}

impl Job {
    pub fn id(&self) -> u32 {
        self.job.job_id
    }

    pub fn channel_id(&self) -> u32 {
        self.channel.channel_id
    }

    /// The time in the header, which is `min_ntime` and is not rolled.
    ///
    /// §5.3.11 requires `min_ntime <= ntime <= min_ntime + seconds since the
    /// message arrived`, so the lower bound is always inside the window and
    /// the simplest choice is also the always-valid one.
    ///
    /// **This is not the timestamp-honesty rule being bent.** That rule is
    /// about a miner manufacturing a testnet4 min-difficulty window by
    /// setting `nTime` to the parent's plus 1201. Here the pool builds the
    /// block and owns the clock; this client reports the time it was told to
    /// hash at, and it is the time it did hash at.
    pub fn ntime(&self) -> u32 {
        self.ntime
    }

    /// The coinbase for one extranonce.
    ///
    /// `coinbase_tx_prefix ‖ extranonce_prefix ‖ extranonce ‖
    /// coinbase_tx_suffix`, per §5.3.16 — the same four-part splice as V1's
    /// `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2`, with the pool's bytes
    /// on the outside and this client's in the middle.
    ///
    /// [`wire::extranonce2_bytes`] is reused rather than reimplemented,
    /// because the width is the pool's and the interpretation is the
    /// client's in exactly the same way. **The trap is here**: what goes
    /// into the coinbase and what goes back in the submit must be the same
    /// bytes, and it is the same call in both places.
    pub fn coinbase(&self, extranonce: Extranonce) -> Vec<u8> {
        let mut coinbase = Vec::with_capacity(
            self.job.coinbase_tx_prefix.len()
                + self.channel.extranonce_prefix.len()
                + self.channel.extranonce_size
                + self.job.coinbase_tx_suffix.len(),
        );
        coinbase.extend_from_slice(&self.job.coinbase_tx_prefix);
        coinbase.extend_from_slice(&self.channel.extranonce_prefix);
        coinbase.extend_from_slice(&self.extranonce_bytes(extranonce));
        coinbase.extend_from_slice(&self.job.coinbase_tx_suffix);
        coinbase
    }

    /// This client's own extranonce bytes, exactly `extranonce_size` of them.
    fn extranonce_bytes(&self, extranonce: Extranonce) -> Vec<u8> {
        wire::extranonce2_bytes(extranonce.0, self.channel.extranonce_size)
    }

    /// The merkle root the coinbase folds to.
    ///
    /// **A suspected trap that is not one.** §5.3.16's
    /// pseudo-code is concatenate, double SHA-256, left to right over the
    /// path — which is what [`wire::fold_merkle`] already does for V1, byte
    /// for byte. It is *reused*, not reimplemented, which is the only way to
    /// be sure the two agree. And §5.3.16 confirms in writing that the
    /// coinbase halves are stripped of BIP141 fields: their double
    /// SHA-256 is the txid directly with no witness to serialize past.
    pub fn merkle_root(&self, extranonce: Extranonce) -> TxMerkleNode {
        wire::fold_merkle(
            wire::sha256d(&self.coinbase(extranonce)),
            &self.job.merkle_path,
        )
    }

    /// The version bits this job may be rolled through, or `None`.
    ///
    /// **Not written by analogy to [`search::rollable`](super::super::search::rollable),
    /// and that is the point.** The V1 function of the same name exists to
    /// decide whether two readings of BIP310 agree about how the pool will
    /// rebuild the header, and returns `None` when they do not — which on a
    /// regtest chain announcing version `30000000` is always. There is
    /// nothing to disagree about here: `SubmitSharesExtended` carries the
    /// *full* nVersion, so the pool does not reconstruct anything, and the
    /// announced version is irrelevant to whether rolling is safe.
    ///
    /// So this is `version_rolling_allowed` and the BIP320 mask, full stop.
    pub fn rollable(&self) -> Option<u32> {
        self.job.version_rolling_allowed.then_some(BIP320_MASK)
    }

    /// The `SubmitSharesExtended` frame for a header that met the target.
    ///
    /// The `ntime`, `nonce` and `version` come from the header rather than
    /// from the job, so a search that rolled the version submits what it
    /// actually hashed — and `version` is the **full** nVersion, the
    /// opposite of V1's masked sixth parameter.
    pub fn submit(
        &self,
        sequence_number: u32,
        extranonce: Extranonce,
        header: &Header,
    ) -> Result<Outgoing, String> {
        submit_shares_extended(
            self.channel.channel_id,
            sequence_number,
            self.job.job_id,
            header.nonce,
            header.time,
            header.version.to_consensus() as u32,
            &self.extranonce_bytes(extranonce),
        )
    }
}

impl ShareJob for Job {
    fn target(&self) -> ShareTarget {
        self.target
    }

    fn version(&self) -> u32 {
        self.job.version
    }

    /// Infallible, because a [`Job`] is by construction a job that can be
    /// mined — see this module's header.
    fn header(&self, extranonce: Extranonce, version: u32) -> Header {
        Header {
            version: Version::from_consensus(version as i32),
            prev_blockhash: self.chain.prev_hash,
            merkle_root: self.merkle_root(extranonce),
            time: self.ntime,
            bits: self.chain.bits,
            nonce: 0,
        }
    }
}

/// What changed when a message was taken, for the caller to log and act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Took {
    /// Queued as a future job. **The search is not woken**: there is nothing
    /// to mine yet, and waking it would throw away a search in progress for
    /// work that is not minable.
    Queued,
    /// There is a new current job, so the search should start again.
    Activated,
}

/// The job table: futures awaiting a prevhash, and the one being mined.
#[derive(Clone, Debug)]
pub struct Jobs {
    /// Future jobs by id, each with the extranonce state it arrived under.
    ///
    /// Ordered rather than hashed so that the bound evicts the oldest id
    /// rather than whichever the hasher reached first.
    future: BTreeMap<u32, (ExtendedJob, ChannelState)>,
    /// The most recent `SetNewPrevHash`, which an activated job inherits.
    chain: Option<Chain>,
    /// The channel state new jobs are snapshotted from.
    channel: ChannelState,
    /// The target new activations are snapshotted from.
    target: ShareTarget,
    current: Option<Job>,
}

impl Jobs {
    pub fn new(channel: ChannelState, target: ShareTarget) -> Self {
        Self {
            future: BTreeMap::new(),
            chain: None,
            channel,
            target,
            current: None,
        }
    }

    /// Take a `NewExtendedMiningJob`.
    ///
    /// A future job is queued; an activated one becomes current immediately,
    /// inheriting the prevhash from the last `SetNewPrevHash` as §5.3.16
    /// requires. An activated job before any prevhash has arrived is a pool
    /// error — there is no prevhash to build a header from — and is refused
    /// rather than queued, because queueing it would silently drop work the
    /// pool believes is being mined.
    pub fn accept(&mut self, job: ExtendedJob) -> Result<Took, String> {
        let Some(min_ntime) = job.min_ntime else {
            let id = job.job_id;
            self.future.insert(id, (job, self.channel.clone()));
            while self.future.len() > FUTURE_JOBS_MAX {
                // Never the one just inserted unless it is also the oldest,
                // which the bound cannot reach in one step.
                let oldest = *self.future.keys().next().expect("the queue is not empty");
                if oldest == id {
                    break;
                }
                self.future.remove(&oldest);
            }
            return Ok(Took::Queued);
        };

        let chain = self.chain.ok_or_else(|| {
            format!(
                "the pool sent job {} with min_ntime {min_ntime} before any SetNewPrevHash, \
                 so there is no previous block to build a header on",
                job.job_id
            )
        })?;

        self.current = Some(Job {
            job,
            channel: self.channel.clone(),
            chain,
            ntime: min_ntime,
            target: self.target,
        });
        Ok(Took::Activated)
    }

    /// Take a `SetNewPrevHash`: activate the job it names, kill the rest.
    ///
    /// §5.3.17: "only the job referenced by Job ID is valid. The
    /// remaining jobs already queued by the client have to be made invalid",
    /// and the server "MUST NOT send this message referencing a `job_id` that
    /// was not previously sent as a future job". Both halves are enforced —
    /// the queue is emptied either way, and a `job_id` that was never a
    /// future job is an error naming it rather than a silently ignored
    /// message that leaves the miner on the previous block.
    pub fn set_prev_hash(&mut self, prev: NewPrevHash) -> Result<Took, String> {
        self.chain = Some(Chain {
            prev_hash: prev.prev_hash,
            bits: prev.bits,
        });

        let named = self.future.remove(&prev.job_id);
        // Emptied whether or not the job was found: every other queued job is
        // work on a block that now has a successor.
        self.future.clear();

        let (job, channel) = named.ok_or_else(|| {
            format!(
                "the pool's SetNewPrevHash names job {}, which it never sent as a future job. \
                 Every queued job has been dropped, because they were all for the previous block",
                prev.job_id
            )
        })?;

        self.current = Some(Job {
            job,
            channel,
            chain: self.chain.expect("just set"),
            // **From the prevhash, not from the job**: a future job has no
            // `min_ntime` of its own, which is what made it a future job.
            ntime: prev.min_ntime,
            target: self.target,
        });
        Ok(Took::Activated)
    }

    /// Take a `SetTarget`.
    ///
    /// **The type does the work.** The new target applies to
    /// every job activated from here on, which includes every queued future
    /// job — they hold no target, so they take this one when they are
    /// activated. The job currently being mined keeps the target it was
    /// activated under, because §5.3.21 says a `SetTarget` "is not applicable
    /// for already received jobs with `min_ntime=nTime`, as their maximum
    /// target remains stable".
    ///
    /// The V1 client does the opposite and is also right: Pool B was
    /// measured judging a job already in flight by the difficulty it wants
    /// now. One is a specification and the other is a measurement, and
    /// nothing reconciles them because they are about different servers.
    ///
    /// Returns whether the current job's target changed, which is always
    /// `false` and is returned anyway so the caller does not have to know
    /// that — see [`Self::current_target`].
    pub fn set_target(&mut self, target: ShareTarget) -> bool {
        self.target = target;
        false
    }

    /// The target new activations will use, for the log line.
    pub fn target(&self) -> ShareTarget {
        self.target
    }

    /// The target the job being mined is measured against, which may be an
    /// older one.
    pub fn current_target(&self) -> Option<ShareTarget> {
        self.current.as_ref().map(|job| job.target)
    }

    /// Take a `SetExtranoncePrefix`.
    ///
    /// §5.3.10: it applies "for all jobs sent after this message", so nothing
    /// already in hand moves — the current job keeps mining under the prefix
    /// it was built with, and the queued futures keep theirs. That falls out
    /// of the snapshots rather than being arranged, which is why this
    /// function is one line.
    ///
    /// **This is the one place the SV2 client is gentler than V1's**, where a
    /// `mining.set_extranonce` drops every held job. V1 has no choice: its
    /// jobs hold no extranonce state of their own, so there is nothing to
    /// keep them consistent with.
    pub fn set_extranonce_prefix(&mut self, prefix: Vec<u8>) {
        self.channel.extranonce_prefix = prefix;
    }

    /// The job to grind now.
    pub fn current(&self) -> Option<&Job> {
        self.current.as_ref()
    }

    /// How many future jobs are waiting for a prevhash.
    pub fn queued(&self) -> usize {
        self.future.len()
    }

    /// Drop everything, on reconnect.
    pub fn clear(&mut self) {
        self.future.clear();
        self.current = None;
        self.chain = None;
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::{
        super::super::{fixture, messages::Notify},
        *,
    };

    fn channel() -> ChannelState {
        ChannelState {
            channel_id: 42,
            extranonce_prefix: vec![0xde, 0xad, 0xbe, 0xef],
            extranonce_size: 8,
        }
    }

    fn difficulty(value: f64) -> ShareTarget {
        ShareTarget::from_difficulty(value).expect("a difficulty")
    }

    fn future_job(job_id: u32) -> ExtendedJob {
        ExtendedJob {
            channel_id: 42,
            job_id,
            min_ntime: None,
            version: 0x2000_0000,
            version_rolling_allowed: true,
            merkle_path: vec![[0x11u8; 32]],
            coinbase_tx_prefix: vec![0x01, 0x02],
            coinbase_tx_suffix: vec![0x03],
        }
    }

    fn prev_hash(job_id: u32) -> NewPrevHash {
        NewPrevHash {
            channel_id: 42,
            job_id,
            prev_hash: BlockHash::from_byte_array([0x55u8; 32]),
            min_ntime: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
        }
    }

    /// The V1 Pool A capture, re-expressed as the SV2 messages that would
    /// carry the same work.
    ///
    /// **The oracle, and it is a real one.** The capture holds thirteen
    /// shares a production pool accepted, and the coinbase splice is
    /// structurally identical across the two protocols —
    /// `coinb1 ‖ extranonce1 ‖ extranonce2 ‖ coinb2` is
    /// `coinbase_tx_prefix ‖ extranonce_prefix ‖ extranonce ‖
    /// coinbase_tx_suffix` — so a V1 notify *is* an SV2 extended job with the
    /// fields renamed and the byte orders undone. Rebuilding those shares
    /// through this file therefore checks the merkle fold, the coinbase
    /// halves and the extranonce bytes — the whole splice-fold-frame chain —
    /// against headers a real pool agreed were shares.
    ///
    /// What it does not check is the prevhash byte order, because the
    /// conversion below does that with the V1 decoder before handing over
    /// the result. That is tested directly in
    /// [`messages`](super::super::messages), against an independent encoder.
    fn captured_session() -> (Vec<(Job, Extranonce, u32, u32)>, ShareTarget) {
        let frames = fixture::load(fixture::POOL_A);

        let subscribe = frames
            .iter()
            .find(|frame| !frame.is_send() && frame.json["id"] == 1)
            .expect("the capture opens with a subscribe reply");
        let result = subscribe.result().expect("a subscribe reply has a result");
        let extranonce_prefix =
            wire::bytes_from_hex(result[1].as_str().expect("an extranonce1")).expect("hex");
        let extranonce_size = result[2].as_u64().expect("an extranonce2_size") as usize;

        let channel = ChannelState {
            channel_id: 1,
            extranonce_prefix,
            extranonce_size,
        };
        // The capture was taken at difficulty 1, which the V1 tests assert.
        let target = difficulty(1.0);

        let notifies: std::collections::HashMap<&str, Notify> = frames
            .iter()
            .filter(|frame| frame.method() == Some("mining.notify"))
            .map(|frame| {
                (
                    frame.param(0),
                    Notify::parse(frame.params()).expect("a captured notify"),
                )
            })
            .collect();

        let mut rebuilt = Vec::new();
        for submit in frames
            .iter()
            .filter(|frame| frame.is_send() && frame.method() == Some("mining.submit"))
        {
            let notify = notifies
                .get(submit.param(1))
                .expect("every submit answers a notify");

            // The V1 fields, converted exactly as an SV2 pool would have sent
            // them: the prevhash in internal order, the merkle branch and the
            // coinbase halves unchanged, and the big-endian hex integers as
            // plain numbers.
            let job = Job {
                job: ExtendedJob {
                    channel_id: 1,
                    job_id: 1,
                    min_ntime: Some(notify.ntime),
                    version: notify.version,
                    version_rolling_allowed: false,
                    merkle_path: notify.branch.clone(),
                    coinbase_tx_prefix: notify.coinb1.clone(),
                    coinbase_tx_suffix: notify.coinb2.clone(),
                },
                channel: channel.clone(),
                chain: Chain {
                    prev_hash: notify.prevhash,
                    bits: notify.bits,
                },
                ntime: notify.ntime,
                target,
            };

            // The extranonce2 the capture actually used, read back into the
            // counter this client walks.
            let raw = wire::bytes_from_hex(submit.param(2)).expect("a captured extranonce2");
            assert_eq!(raw.len(), extranonce_size);
            let mut padded = [0u8; 8];
            padded[8 - raw.len()..].copy_from_slice(&raw);
            let extranonce = Extranonce(u64::from_be_bytes(padded));

            let ntime = wire::be_u32_from_hex(submit.param(3)).expect("a captured ntime");
            let nonce = wire::be_u32_from_hex(submit.param(4)).expect("a captured nonce");
            rebuilt.push((job, extranonce, ntime, nonce));
        }

        assert_eq!(rebuilt.len(), 13, "every accepted submit in the capture");
        (rebuilt, target)
    }

    #[test]
    fn every_accepted_share_in_the_capture_rebuilds_through_the_sv2_path() {
        // The direct analogue of V1's share-rebuilding test, which is the
        // single most valuable test in that suite. If the splice, the fold or the
        // extranonce width is wrong here, none of these headers lands under
        // the target a real pool measured them against.
        let (session, target) = captured_session();

        for (index, (job, extranonce, ntime, nonce)) in session.iter().enumerate() {
            let mut header = job.header(*extranonce, job.version());
            header.time = *ntime;
            header.nonce = *nonce;

            let hash = header.block_hash();
            assert!(
                target.is_met_by(hash),
                "share {index} rebuilt to {hash}, which does not meet difficulty 1"
            );
        }
    }

    /// One share from the PuntoHunter capture, with the job it was found on.
    struct Replayed {
        job: Job,
        sequence: u32,
        extranonce: Extranonce,
        ntime: u32,
        nonce: u32,
        version: u32,
        /// The `SubmitSharesExtended` payload exactly as it went out.
        payload: Vec<u8>,
    }

    /// Every share in the PuntoHunter capture, rebuilt from the jobs that
    /// pool sent, with the target each was found against.
    ///
    /// **Replayed through [`Jobs`], in capture order**, so the job, the
    /// prevhash and the target a share is checked under are the ones this
    /// client's own state machine held — not ones the test picked. A job is
    /// looked up by id rather than taken as the current one, because the
    /// capture is in socket order: the reader thread can record the next
    /// block's job before the grinder has written the share for this one.
    fn puntohunter_shares() -> Vec<Replayed> {
        use std::collections::HashMap;

        use super::super::{codec::Reader, frame::msg, messages::Incoming};

        let frames = fixture::load_sv2(fixture::SV2_PUNTOHUNTER);
        let mut shares = Vec::new();
        let mut jobs: Option<Jobs> = None;
        let mut seen: HashMap<(usize, u32), Job> = HashMap::new();

        for frame in &frames {
            if frame.send {
                if frame.header.msg_type != msg::SUBMIT_SHARES_EXTENDED {
                    continue;
                }
                let mut reader = Reader::new(&frame.payload);
                let _channel = reader.u32().unwrap();
                let sequence = reader.u32().unwrap();
                let job_id = reader.u32().unwrap();
                let nonce = reader.u32().unwrap();
                let ntime = reader.u32().unwrap();
                let version = reader.u32().unwrap();
                let bytes = reader
                    .bytes(super::super::codec::Prefix::Bytes32)
                    .unwrap()
                    .to_vec();
                reader.finish().expect("nothing after the extranonce");

                assert_eq!(bytes.len(), 8, "the extranonce_size granted");
                let extranonce = Extranonce(u64::from_be_bytes(bytes[..].try_into().unwrap()));
                let job = seen
                    .get(&(frame.session, job_id))
                    .unwrap_or_else(|| panic!("share {sequence} names job {job_id}, never active"))
                    .clone();
                shares.push(Replayed {
                    job,
                    sequence,
                    extranonce,
                    ntime,
                    nonce,
                    version,
                    payload: frame.payload.clone(),
                });
                continue;
            }

            match Incoming::parse(frame.header, &frame.payload).expect("a captured frame") {
                Incoming::OpenExtendedChannelSuccess(channel) => {
                    jobs = Some(Jobs::new(
                        ChannelState {
                            channel_id: channel.channel_id,
                            extranonce_prefix: channel.extranonce_prefix,
                            extranonce_size: channel.extranonce_size,
                        },
                        ShareTarget::from_u256(channel.target),
                    ));
                }
                Incoming::NewExtendedMiningJob(job) => {
                    jobs.as_mut().unwrap().accept(job).expect("a captured job");
                }
                Incoming::SetNewPrevHash(prev) => {
                    jobs.as_mut()
                        .unwrap()
                        .set_prev_hash(prev)
                        .expect("a captured prevhash names a future job");
                }
                Incoming::SetTarget { maximum_target, .. } => {
                    jobs.as_mut()
                        .unwrap()
                        .set_target(ShareTarget::from_u256(maximum_target));
                }
                Incoming::SetExtranoncePrefix {
                    extranonce_prefix, ..
                } => jobs
                    .as_mut()
                    .unwrap()
                    .set_extranonce_prefix(extranonce_prefix),
                _ => {}
            }
            if let Some(job) = jobs.as_ref().and_then(Jobs::current) {
                seen.insert((frame.session, job.id()), job.clone());
            }
        }
        shares
    }

    #[test]
    fn every_share_in_the_puntohunter_capture_rebuilds_under_its_target() {
        // **The V2 counterpart of the V1 fixture tests, against bytes from
        // SRI's encoder.** Every field here came off a real SV2 server: the
        // coinbase halves, the merkle path, the prevhash in its internal byte
        // order, which the pool-A-derived test above cannot reach,
        // because its prevhash went through the V1 decoder — the bits and
        // the target. A share that rebuilt to a hash above its target would
        // be a share this client found under a header the pool did not build.
        let shares = puntohunter_shares();
        assert_eq!(shares.len(), 16);

        let mut rolled = 0;
        for Replayed {
            job,
            sequence,
            extranonce,
            ntime,
            nonce,
            version,
            payload,
        } in &shares
        {
            assert_eq!(*ntime, job.ntime(), "share {sequence}: ntime is not rolled");
            let mut header = job.header(*extranonce, *version);
            header.time = *ntime;
            header.nonce = *nonce;

            let hash = header.block_hash();
            assert!(
                job.target().is_met_by(hash),
                "share {sequence} of job {} rebuilt to {hash}, above {}",
                job.id(),
                job.target()
            );
            // Regtest's target is easier than any share's.
            assert!(
                super::super::super::search::is_block(&header),
                "share {sequence} is a block"
            );
            // And what went out is exactly what this file would send again.
            assert_eq!(
                &job.submit(*sequence, *extranonce, &header).unwrap().payload,
                payload,
                "share {sequence}'s submit"
            );
            rolled += usize::from(*version != job.version());
        }
        assert!(
            rolled > 0,
            "the GPU session rolled versions, and they rebuild too"
        );
    }

    #[test]
    fn every_share_in_the_puntohunter_capture_was_acknowledged() {
        use super::super::messages::Incoming;

        let frames = fixture::load_sv2(fixture::SV2_PUNTOHUNTER);
        // One acknowledgement per share, `new_submits_accepted_count` of 1,
        // naming every sequence number of the session in order: like
        // Pool A, PuntoHunter does not batch.
        for session in 0..=1 {
            let acknowledged: Vec<u32> = frames
                .iter()
                .filter(|frame| frame.session == session && !frame.send)
                .filter_map(
                    |frame| match Incoming::parse(frame.header, &frame.payload) {
                        Ok(Incoming::SubmitSharesSuccess {
                            last_sequence_number,
                            new_submits_accepted_count,
                            ..
                        }) => {
                            assert_eq!(new_submits_accepted_count, 1, "no batching");
                            Some(last_sequence_number)
                        }
                        Ok(Incoming::SubmitSharesError { .. }) => panic!("a rejected share"),
                        _ => None,
                    },
                )
                .collect();
            let expected: Vec<u32> = (0..acknowledged.len() as u32).collect();
            assert_eq!(
                acknowledged, expected,
                "session {session}: every sequence, in order"
            );
        }
    }

    /// The first captured notify as an SV2 future job and the prevhash that
    /// activates it, with `pays` spliced over the payout script's program.
    fn activated_capture(pays: [u8; 20]) -> Jobs {
        let frames = fixture::load(fixture::POOL_A);
        let notify = frames
            .iter()
            .find(|frame| frame.method() == Some("mining.notify"))
            .map(|frame| Notify::parse(frame.params()).expect("a captured notify"))
            .expect("the capture has notifies");

        // The payout output's program, found rather than indexed so the test
        // says what it is replacing.
        let program = [
            0xeb, 0xdc, 0xd3, 0xa0, 0x87, 0x62, 0xd1, 0x28, 0xb2, 0x0a, 0xcd, 0x33, 0xb1, 0x33,
            0xdf, 0x9e, 0xd2, 0xd4, 0x97, 0x27,
        ];
        let mut suffix = notify.coinb2.clone();
        let at = suffix
            .windows(20)
            .position(|window| window == program)
            .expect("the capture pays MINER_ADDRESS");
        suffix[at..at + 20].copy_from_slice(&pays);

        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        jobs.accept(ExtendedJob {
            channel_id: 42,
            job_id: 5,
            min_ntime: None,
            version: notify.version,
            version_rolling_allowed: true,
            merkle_path: notify.branch.clone(),
            coinbase_tx_prefix: notify.coinb1.clone(),
            coinbase_tx_suffix: suffix,
        })
        .expect("a future job");
        jobs.set_prev_hash(prev_hash(5)).expect("it activates");
        jobs
    }

    #[test]
    fn the_payout_is_read_out_of_an_extended_job_as_it_is_out_of_a_notify() {
        use super::super::super::payout::{DECODED_AT, Payout};
        use crate::constants::MINER_ADDRESS;

        let user = format!("{MINER_ADDRESS}.puntominer");

        // The coinbase as captured pays MINER_ADDRESS, and says so.
        let ours = activated_capture([
            0xeb, 0xdc, 0xd3, 0xa0, 0x87, 0x62, 0xd1, 0x28, 0xb2, 0x0a, 0xcd, 0x33, 0xb1, 0x33,
            0xdf, 0x9e, 0xd2, 0xd4, 0x97, 0x27,
        ]);
        let lines = Payout::new(&user).check(&ours.current().unwrap().coinbase(DECODED_AT));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("(MINER_POOL_USER)"), "{lines:?}");

        // The same job paying another program warns.
        let theirs = activated_capture([0x42; 20]);
        let lines = Payout::new(&user).check(&theirs.current().unwrap().coinbase(DECODED_AT));
        assert!(
            lines.iter().any(|line| line.starts_with("WARNING")),
            "{lines:?}"
        );
    }

    #[test]
    fn the_submit_carries_exactly_the_extranonce_that_went_into_the_coinbase() {
        // The check is that the same bytes appear in both places
        // — not the prefix, and not prefix-plus-extranonce. The pool
        // reassembles the coinbase itself, so sending the prefix back would
        // give it one with the prefix in twice.
        let (session, _) = captured_session();
        let (job, extranonce, ntime, nonce) = &session[0];

        let mut header = job.header(*extranonce, job.version());
        header.time = *ntime;
        header.nonce = *nonce;
        let outgoing = job.submit(7, *extranonce, &header).expect("a share frame");

        let mut payload = outgoing.payload.clone();
        let decoded: mining_sv2::SubmitSharesExtended =
            binary_sv2::from_bytes(payload.as_mut_slice()).expect("SRI decodes the share");

        let ours = job.extranonce_bytes(*extranonce);
        assert_eq!(decoded.extranonce.as_ref(), ours.as_slice());
        assert_eq!(ours.len(), 8, "exactly extranonce_size bytes");

        // And those same bytes are in the coinbase, immediately after the
        // pool's prefix and before the suffix.
        let coinbase = job.coinbase(*extranonce);
        let at = job.job.coinbase_tx_prefix.len() + job.channel.extranonce_prefix.len();
        assert_eq!(&coinbase[at..at + ours.len()], ours.as_slice());

        // The full nVersion, not the rolled bits.
        assert_eq!(decoded.version, header.version.to_consensus() as u32);
        assert_eq!(decoded.ntime, *ntime);
        assert_eq!(decoded.nonce, *nonce);
        assert_eq!(decoded.channel_id, 1);
        assert_eq!(decoded.sequence_number, 7);
    }

    #[test]
    fn a_future_job_is_not_minable_until_a_prevhash_names_it() {
        // The whole job/prevhash split in one test. A future job is not a
        // `Job`, so there is no header to accidentally build from it.
        let mut jobs = Jobs::new(channel(), difficulty(1.0));

        assert_eq!(jobs.accept(future_job(1)).unwrap(), Took::Queued);
        assert_eq!(jobs.accept(future_job(2)).unwrap(), Took::Queued);
        assert!(jobs.current().is_none(), "nothing is minable yet");
        assert_eq!(jobs.queued(), 2);

        assert_eq!(jobs.set_prev_hash(prev_hash(2)).unwrap(), Took::Activated);
        let current = jobs.current().expect("job 2 is now minable");
        assert_eq!(current.id(), 2);
        assert_eq!(
            current.ntime(),
            1_700_000_000,
            "the ntime is the prevhash's"
        );
        assert_eq!(
            current
                .header(Extranonce::ZERO, current.version())
                .prev_blockhash,
            BlockHash::from_byte_array([0x55u8; 32]),
        );

        // Every other queued job died with it.
        assert_eq!(jobs.queued(), 0, "job 1 was for the previous block");
    }

    #[test]
    fn a_prevhash_naming_a_job_that_was_never_sent_is_an_error_that_says_so() {
        // §5.3.17 forbids it, so a pool doing it is broken — and silently
        // ignoring the message would leave the miner grinding the previous
        // block for as long as the pool kept it up.
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        jobs.accept(future_job(1)).unwrap();

        let why = jobs
            .set_prev_hash(prev_hash(99))
            .expect_err("job 99 was never a future job");
        assert!(why.contains("99"), "{why}");
        assert!(why.contains("never sent"), "{why}");
        assert_eq!(jobs.queued(), 0, "the queue is still emptied");
    }

    #[test]
    fn an_activated_job_inherits_the_last_prevhash_and_keeps_its_own_ntime() {
        // §5.3.16: a job with `min_ntime` set "uses the prev_hash from the
        // last received SetNewPrevHash message" — but its own `min_ntime`,
        // not the prevhash's.
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        jobs.accept(future_job(1)).unwrap();
        jobs.set_prev_hash(prev_hash(1)).unwrap();

        let mut activated = future_job(5);
        activated.min_ntime = Some(1_700_000_500);
        assert_eq!(jobs.accept(activated).unwrap(), Took::Activated);

        let current = jobs.current().expect("an activated job is minable at once");
        assert_eq!(current.id(), 5);
        assert_eq!(current.ntime(), 1_700_000_500, "the job's own min_ntime");
        assert_eq!(
            current
                .header(Extranonce::ZERO, current.version())
                .prev_blockhash,
            BlockHash::from_byte_array([0x55u8; 32]),
            "and the prevhash from the last SetNewPrevHash",
        );
    }

    #[test]
    fn an_activated_job_before_any_prevhash_is_refused_rather_than_guessed_at() {
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        let mut activated = future_job(5);
        activated.min_ntime = Some(1_700_000_500);

        let why = jobs
            .accept(activated)
            .expect_err("there is no previous block to build on");
        assert!(why.contains("SetNewPrevHash"), "{why}");
        assert!(jobs.current().is_none());
    }

    #[test]
    fn set_target_moves_future_jobs_and_leaves_the_one_being_mined_alone() {
        // **The opposite of the V1 rule.** An activated job's
        // maximum target "remains stable" per §5.3.21, and a queued future
        // job takes whatever is in force when it is activated.
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        jobs.accept(future_job(1)).unwrap();
        jobs.set_prev_hash(prev_hash(1)).unwrap();
        assert_eq!(jobs.current_target().unwrap(), difficulty(1.0));

        // A future job queued *before* the retarget, to prove it is the
        // activation and not the arrival that decides.
        jobs.accept(future_job(2)).unwrap();
        jobs.set_target(difficulty(512.0));

        assert_eq!(
            jobs.current_target().unwrap(),
            difficulty(1.0),
            "the job in flight keeps the target it was activated under"
        );
        assert_eq!(jobs.target(), difficulty(512.0));

        jobs.set_prev_hash(prev_hash(2)).unwrap();
        assert_eq!(
            jobs.current_target().unwrap(),
            difficulty(512.0),
            "a job activated after the retarget takes the new one"
        );
    }

    #[test]
    fn an_extranonce_prefix_applies_to_jobs_sent_after_it_and_not_before() {
        // §5.3.10, and the snapshot is what makes it a one-line function.
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        jobs.accept(future_job(1)).unwrap();
        jobs.set_prev_hash(prev_hash(1)).unwrap();
        let before = jobs.current().unwrap().coinbase(Extranonce::ZERO);

        jobs.set_extranonce_prefix(vec![0xaa, 0xbb]);
        assert_eq!(
            jobs.current().unwrap().coinbase(Extranonce::ZERO),
            before,
            "a job already in hand keeps the prefix it was built against"
        );

        jobs.accept(future_job(2)).unwrap();
        jobs.set_prev_hash(prev_hash(2)).unwrap();
        let after = jobs.current().unwrap().coinbase(Extranonce::ZERO);
        assert_ne!(after, before, "a job sent afterwards takes the new prefix");
        assert_eq!(&after[2..4], &[0xaa, 0xbb]);
    }

    #[test]
    fn rollable_is_the_flag_and_the_mask_and_nothing_about_the_announced_version() {
        // The V1 function of this name returns `None` whenever the announced
        // version has bits inside the mask, because two readings of BIP310
        // disagree about how the pool rebuilds the header. There is nothing
        // to rebuild here, so a regtest chain's `30000000` — which made every
        // V1 share fail — is a non-event.
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        let mut regtest = future_job(1);
        regtest.version = 0x3000_0000;
        jobs.accept(regtest).unwrap();
        jobs.set_prev_hash(prev_hash(1)).unwrap();

        let current = jobs.current().unwrap();
        assert_eq!(current.version(), 0x3000_0000);
        assert_eq!(
            current.rollable(),
            Some(BIP320_MASK),
            "bit 28 is inside the mask and it does not matter"
        );

        // And the flag is honoured when it is false.
        let mut fixed = future_job(2);
        fixed.version_rolling_allowed = false;
        jobs.accept(fixed).unwrap();
        jobs.set_prev_hash(prev_hash(2)).unwrap();
        assert_eq!(jobs.current().unwrap().rollable(), None);
    }

    #[test]
    fn the_future_queue_is_bounded_and_keeps_the_newest() {
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        for id in 0..(FUTURE_JOBS_MAX as u32 + 5) {
            jobs.accept(future_job(id)).unwrap();
        }
        assert_eq!(jobs.queued(), FUTURE_JOBS_MAX);

        // The newest survives, which is the one a prevhash is most likely to
        // name next.
        let newest = FUTURE_JOBS_MAX as u32 + 4;
        assert!(jobs.set_prev_hash(prev_hash(newest)).is_ok());
        assert_eq!(jobs.current().unwrap().id(), newest);
    }

    #[test]
    fn a_target_from_a_u256_is_the_little_endian_number_the_spec_names() {
        // 0x00000000ffff0000… as SV2 sends it, which is difficulty 1 and is
        // also `Target::MAX`. Little-endian, so the `ffff` is near the end of
        // the byte string rather than near the start.
        let mut bytes = [0u8; 32];
        bytes[26] = 0xff;
        bytes[27] = 0xff;

        let target = ShareTarget::from_u256(bytes);
        assert_eq!(target, difficulty(1.0));
        assert_eq!(target.to_u256(), bytes, "and back again");

        // The big-endian reading of the same bytes is a wildly different
        // target, which is what makes this worth asserting rather than
        // assuming.
        let mut wrong = bytes;
        wrong.reverse();
        assert_ne!(ShareTarget::from_u256(wrong), target);
    }

    #[test]
    fn a_reconnect_drops_every_job_and_the_chain_with_them() {
        let mut jobs = Jobs::new(channel(), difficulty(1.0));
        jobs.accept(future_job(1)).unwrap();
        jobs.set_prev_hash(prev_hash(1)).unwrap();
        jobs.accept(future_job(2)).unwrap();

        jobs.clear();
        assert!(jobs.current().is_none());
        assert_eq!(jobs.queued(), 0);

        // And the chain went with them, so an activated job arriving on a new
        // connection cannot inherit a prevhash from the old one.
        let mut activated = future_job(9);
        activated.min_ntime = Some(1_700_000_000);
        assert!(jobs.accept(activated).is_err());
    }
}
