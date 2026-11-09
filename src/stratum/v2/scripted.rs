//! The scripted pool: the cases no available server sends, played over a
//! real socket by an encoder nobody here wrote.
//!
//! The V2 client needs six cases covered. PuntoHunter on regtest produced
//! four of them live (see `tests/fixtures/README.md`). Two cannot be had
//! from any server available: **a `SetTarget` against an activated job**,
//! because both live pools have only ever sent one at a job boundary, and
//! **`SetExtranoncePrefix`**, which neither sends at all. A share answered
//! with `SubmitShares.Error` is the third: it happens live only by a race.
//!
//! [`session_tests`](super::run) already runs a whole session against a pool
//! on the loopback, and is not this. Its frames are built with this
//! repository's own codec, so it and the client agree about anything that
//! codec has wrong. Here, everything the pool says is SRI's:
//!
//! - **the Noise responder** is `noise_sv2`'s;
//! - **every payload** is encoded by `mining_sv2` and `common_messages_sv2`
//!   through `binary_sv2`, and the client's submits are decoded the same way;
//! - **the message numbers and channel bits** are SRI's constants;
//! - **each share is rebuilt and checked here**, with `rust-bitcoin` and the
//!   spec's splice written out, never through `job.rs`.
//!
//! The six-byte frame header is written by hand, from §3.2, because SRI's
//! framing lives in `codec_sv2`, which is not a dev-dependency.
//!
//! **What this proves, and what it does not.** It tests the client's handling
//! of the spec's two readings — §5.3.21, a `SetTarget` does not apply to the
//! job in flight, and §5.3.10, a `SetExtranoncePrefix` applies to jobs sent
//! after it. It says nothing about whether any pool reads the spec that way.
//! That stays unconfirmed until a live pool is seen sending either message.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use binary_sv2::{B032, B064K, Seq0255, Str0255, Sv2Option, U256, from_bytes, to_bytes};
use bitcoin::{
    BlockHash, CompactTarget, TxMerkleNode,
    block::{Header as BlockHeader, Version},
    hashes::{Hash, sha256d},
    secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
};
use common_messages_sv2 as common;
use mining_sv2 as mining;

use super::{
    super::pool::{Authority, Pool, Protocol, VersionRolling},
    run::run,
};
use crate::{
    block::Extranonce,
    cpu::{Cpu, Hasher},
    logger::Logger,
    watch::Signals,
};

/// §3.2's AEAD tag length, for reading a payload back off the socket.
const MAC: usize = 16;

/// The channel's first target: `2^244 - 1`, about one share every 4,096
/// hashes, as the 32 little-endian bytes a `U256` carries.
fn easy() -> [u8; 32] {
    let mut target = [0xffu8; 32];
    target[30] = 0x0f;
    target[31] = 0x00;
    target
}

/// The `SetTarget` the script sends mid-job: `2^240 - 1`, sixteen times
/// harder. A share under [`easy`] meets it one time in sixteen, so a run of
/// shares that all met it would be a client that retargeted the job in
/// flight.
fn hard() -> [u8; 32] {
    let mut target = [0xffu8; 32];
    target[30] = 0x00;
    target[31] = 0x00;
    target
}

/// The extranonce prefix the channel opens with, and the one the script
/// moves it to.
const PREFIX_OPEN: [u8; 2] = [0xaa, 0xbb];
const PREFIX_MOVED: [u8; 3] = [0xcc, 0xdd, 0xee];

/// The coinbase halves and merkle path every job in the script uses. Any
/// bytes will do: nothing here is a transaction anyone validates, and the
/// header is rebuilt from them the same way on both sides only if the splice
/// is right.
const COINBASE_PREFIX: [u8; 5] = [0x01, 0x00, 0x00, 0x00, 0x01];
const COINBASE_SUFFIX: [u8; 3] = [0xff, 0xff, 0xff];
const MERKLE_STEP: [u8; 32] = [0x33; 32];

/// Difficulty-1 bits, so that no share is also a block.
const BITS: u32 = 0x1d00_ffff;
const NTIME: u32 = 1_700_000_000;
const CHANNEL: u32 = 7;
const PREV_HASH: [u8; 32] = [0x77; 32];

/// The pool's side of one connection.
struct Script {
    stream: TcpStream,
    engine: noise_sv2::NoiseEngine,
}

/// One share as SRI decoded it.
struct Share {
    sequence: u32,
    job_id: u32,
    nonce: u32,
    ntime: u32,
    version: u32,
    extranonce: Vec<u8>,
}

impl Script {
    /// Send one SRI-encoded message under the type and channel bit SRI gives
    /// it.
    fn send<T>(&mut self, msg_type: u8, channel_bit: bool, message: T)
    where
        T: binary_sv2::Serialize + binary_sv2::GetSize,
    {
        let payload = to_bytes(message).expect("SRI encodes its own struct");
        let extension: u16 = if channel_bit { 0x8000 } else { 0 };
        let length = (payload.len() as u32).to_le_bytes();
        let [low, high] = extension.to_le_bytes();
        let mut header = vec![low, high, msg_type, length[0], length[1], length[2]];
        self.engine.encrypt(&mut header).expect("the header seals");
        let mut body = payload;
        self.engine.encrypt(&mut body).expect("the payload seals");
        self.stream.write_all(&header).expect("the header goes out");
        self.stream.write_all(&body).expect("the payload goes out");
        self.stream.flush().expect("flushed");
    }

    /// Read one frame: its message type and plaintext payload.
    fn recv(&mut self) -> (u8, Vec<u8>) {
        let mut header = vec![0u8; 6 + MAC];
        self.stream.read_exact(&mut header).expect("a frame header");
        self.engine
            .decrypt(&mut header)
            .expect("the header authenticates");
        let length =
            usize::from(header[3]) | usize::from(header[4]) << 8 | usize::from(header[5]) << 16;
        assert!(
            length < 65_519,
            "every frame this client sends is one chunk"
        );
        let mut payload = vec![0u8; length + MAC];
        self.stream.read_exact(&mut payload).expect("a payload");
        self.engine
            .decrypt(&mut payload)
            .expect("the payload authenticates");
        (header[2], payload)
    }

    /// Read until the next `SubmitSharesExtended`, and decode it with SRI.
    fn next_share(&mut self) -> Share {
        loop {
            let (msg_type, mut payload) = self.recv();
            if msg_type != mining::MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED {
                continue;
            }
            let share: mining::SubmitSharesExtended =
                from_bytes(payload.as_mut_slice()).expect("SRI decodes the client's share");
            assert_eq!(share.channel_id, CHANNEL);
            return Share {
                sequence: share.sequence_number,
                job_id: share.job_id,
                nonce: share.nonce,
                ntime: share.ntime,
                version: share.version,
                extranonce: share.extranonce.as_ref().to_vec(),
            };
        }
    }

    fn job(&mut self, job_id: u32) {
        self.job_announcing(job_id, 0x2000_0000, false);
    }

    /// A future job announcing `version`, and the prevhash that activates it.
    fn job_announcing(&mut self, job_id: u32, version: u32, version_rolling_allowed: bool) {
        let mut prefix = COINBASE_PREFIX.to_vec();
        let mut suffix = COINBASE_SUFFIX.to_vec();
        let mut step = MERKLE_STEP;
        self.send(
            mining::MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
            mining::CHANNEL_BIT_NEW_EXTENDED_MINING_JOB,
            mining::NewExtendedMiningJob {
                channel_id: CHANNEL,
                job_id,
                ntime_start: Sv2Option::new(None),
                version,
                version_rolling_allowed,
                merkle_path: Seq0255::new(vec![U256::from(&mut step)]).unwrap(),
                coinbase_tx_prefix: B064K::try_from(prefix.as_mut_slice()).unwrap(),
                coinbase_tx_suffix: B064K::try_from(suffix.as_mut_slice()).unwrap(),
            },
        );
        let mut prev = PREV_HASH;
        self.send(
            mining::MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
            mining::CHANNEL_BIT_MINING_SET_NEW_PREV_HASH,
            mining::SetNewPrevHash {
                channel_id: CHANNEL,
                job_id,
                prev_hash: U256::from(&mut prev),
                ntime_start: NTIME,
                nbits: BITS,
            },
        );
    }

    fn accept(&mut self, share: &Share) {
        self.send(
            mining::MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            mining::CHANNEL_BIT_SUBMIT_SHARES_SUCCESS,
            mining::SubmitSharesSuccess {
                channel_id: CHANNEL,
                last_sequence_number: share.sequence,
                new_submits_accepted_count: 1,
                new_shares_sum: 1,
            },
        );
    }

    fn reject(&mut self, share: &Share, code: &str) {
        self.send(
            mining::MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            mining::CHANNEL_BIT_SUBMIT_SHARES_ERROR,
            mining::SubmitSharesError {
                channel_id: CHANNEL,
                sequence_number: share.sequence,
                error_code: Str0255::try_from(code.as_bytes()).unwrap(),
            },
        );
    }
}

/// The share's header as the pool builds it: §5.3.16's splice,
/// `coinbase_tx_prefix ‖ extranonce_prefix ‖ extranonce ‖ coinbase_tx_suffix`,
/// folded up the merkle path, under the prevhash, bits and ntime the pool
/// sent. Written here from the spec, not borrowed from `job.rs`.
fn rebuild(share: &Share, extranonce_prefix: &[u8]) -> BlockHash {
    let mut coinbase = COINBASE_PREFIX.to_vec();
    coinbase.extend_from_slice(extranonce_prefix);
    coinbase.extend_from_slice(&share.extranonce);
    coinbase.extend_from_slice(&COINBASE_SUFFIX);

    let mut node = sha256d::Hash::hash(&coinbase).to_byte_array();
    let mut pair = node.to_vec();
    pair.extend_from_slice(&MERKLE_STEP);
    node = sha256d::Hash::hash(&pair).to_byte_array();

    BlockHeader {
        version: Version::from_consensus(share.version as i32),
        prev_blockhash: BlockHash::from_byte_array(PREV_HASH),
        merkle_root: TxMerkleNode::from_byte_array(node),
        time: share.ntime,
        bits: CompactTarget::from_consensus(BITS),
        nonce: share.nonce,
    }
    .block_hash()
}

/// Whether a hash meets a target, both as little-endian 256-bit numbers:
/// compared from the most significant byte down.
fn meets(hash: BlockHash, target: &[u8; 32]) -> bool {
    let hash = hash.to_byte_array();
    for index in (0..32).rev() {
        if hash[index] != target[index] {
            return hash[index] < target[index];
        }
    }
    true
}

impl Script {
    /// Accept the client, run `noise_sv2`'s side of the handshake, and answer
    /// `SetupConnection` and the channel open: the easy target, eight
    /// extranonce bytes, and [`PREFIX_OPEN`].
    fn start(listener: &TcpListener, secret: &SecretKey) -> Self {
        let secp = Secp256k1::new();
        let pinned = Keypair::from_secret_key(&secp, secret)
            .x_only_public_key()
            .0;
        let (mut stream, _) = listener.accept().expect("the client connects");
        let mut responder = noise_sv2::Responder::from_authority_kp(
            &pinned.serialize(),
            &secret.secret_bytes(),
            Duration::from_secs(3600),
        )
        .expect("the responder takes its keypair");
        let mut first = [0u8; 64];
        stream.read_exact(&mut first).expect("the ephemeral key");
        let (second, engine) = responder.step_1(first).expect("the handshake");
        stream.write_all(&second).expect("the answer");
        let mut pool = Script { stream, engine };

        let (msg_type, _) = pool.recv();
        assert_eq!(msg_type, common::MESSAGE_TYPE_SETUP_CONNECTION);
        pool.send(
            common::MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            common::CHANNEL_BIT_SETUP_CONNECTION_SUCCESS,
            common::SetupConnectionSuccess {
                used_version: 2,
                flags: 0,
            },
        );

        let (msg_type, _) = pool.recv();
        assert_eq!(msg_type, mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL);
        let mut target = easy();
        let mut prefix = PREFIX_OPEN.to_vec();
        pool.send(
            mining::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            mining::CHANNEL_BIT_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            mining::OpenExtendedMiningChannelSuccess {
                request_id: 1,
                channel_id: CHANNEL,
                target: U256::from(&mut target),
                extranonce_size: 8,
                extranonce_prefix: B032::try_from(prefix.as_mut_slice()).unwrap(),
                group_channel_id: 0,
            },
        );

        pool
    }
}

/// Raises the stop flag when the script ends, however it ends, so a failed
/// assertion on the pool's side ends the client too rather than leaving it
/// reconnecting for ever.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// What the script saw, for the test to assert on once the client has ended.
#[derive(Debug, Default)]
struct Seen {
    /// Shares on the first job after the `SetTarget` and the prefix change,
    /// and how many of those met the harder target anyway.
    in_flight: usize,
    in_flight_meeting_hard: usize,
    /// Shares on the job sent after both.
    after: usize,
    rejected_sequence: Option<u32>,
}

#[test]
fn the_job_in_flight_keeps_its_target_and_prefix_and_the_next_job_takes_the_new_ones() {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[31u8; 32]).unwrap();
    let pinned = Keypair::from_secret_key(&secp, &secret)
        .x_only_public_key()
        .0;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("its address").to_string();
    let stop = Arc::new(AtomicBool::new(false));

    let server = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let _stop = StopOnDrop(stop);
            let mut pool = Script::start(&listener, &secret);

            // Job 11, activated under the easy target and the first prefix.
            pool.job(11);
            let share = pool.next_share();
            assert_eq!(share.job_id, 11);
            assert!(meets(rebuild(&share, &PREFIX_OPEN), &easy()));
            pool.accept(&share);

            // **The two readings, sent while job 11 is being mined.**
            let mut target = hard();
            pool.send(
                mining::MESSAGE_TYPE_SET_TARGET,
                mining::CHANNEL_BIT_SET_TARGET,
                mining::SetTarget {
                    channel_id: CHANNEL,
                    target: U256::from(&mut target),
                },
            );
            let mut prefix = PREFIX_MOVED.to_vec();
            pool.send(
                mining::MESSAGE_TYPE_SET_EXTRANONCE_PREFIX,
                mining::CHANNEL_BIT_SET_EXTRANONCE_PREFIX,
                mining::SetExtranoncePrefix {
                    channel_id: CHANNEL,
                    extranonce_prefix: B032::try_from(prefix.as_mut_slice()).unwrap(),
                },
            );

            // Job 11 keeps both: every share still rebuilds under the first
            // prefix and meets the easy target, and most miss the hard one.
            let mut seen = Seen::default();
            while seen.in_flight < 8 {
                let share = pool.next_share();
                assert_eq!(share.job_id, 11, "nothing else has been sent");
                let hash = rebuild(&share, &PREFIX_OPEN);
                assert!(
                    meets(hash, &easy()),
                    "share {} of the job in flight rebuilt to {hash} under the prefix it was \
                     sent with; a client that moved it mid-job builds a coinbase the pool \
                     did not",
                    share.sequence
                );
                seen.in_flight += 1;
                seen.in_flight_meeting_hard += usize::from(meets(hash, &hard()));
                pool.accept(&share);
            }

            // Job 12, sent after both, takes both. A share for job 11 still in
            // flight when the prevhash lands is answered as what it is.
            pool.job(12);
            while seen.after < 4 {
                let share = pool.next_share();
                if share.job_id == 11 {
                    pool.reject(&share, "stale-share");
                    continue;
                }
                assert_eq!(share.job_id, 12);
                let hash = rebuild(&share, &PREFIX_MOVED);
                assert!(
                    meets(hash, &hard()),
                    "share {} of the next job rebuilt to {hash}, which misses the target it \
                     was activated under",
                    share.sequence
                );

                // **The error path, forced.** The first share on job 12 is
                // answered as a pool that had already cleaned the job would
                // answer it. No live pool can be made to do this on cue;
                // what is under test is that the client names the code and
                // carries on.
                if seen.rejected_sequence.is_none() {
                    seen.rejected_sequence = Some(share.sequence);
                    pool.reject(&share, "stale-share");
                    continue;
                }
                seen.after += 1;
                pool.accept(&share);
            }
            seen
        })
    };

    let text = mine(address, pinned, &stop, "in-flight");

    let seen = server.join().expect("every share met the pool's reading");

    // One in sixteen shares under the easy target also meets the hard one, so
    // eight that all did would be a client that retargeted job 11 in flight.
    assert!(
        seen.in_flight_meeting_hard < seen.in_flight,
        "{seen:?}\n{text}"
    );
    assert!(
        text.contains("the job in flight keeps the target it was activated under"),
        "{text}"
    );
    assert!(
        text.contains("extranonce prefix ccddee from here on; jobs already in hand keep theirs"),
        "{text}"
    );

    // The rejected share is named, with its job and its code, and the session
    // went on to have four more accepted.
    let rejected = seen.rejected_sequence.expect("one share was rejected");
    assert!(
        text.contains(&format!(
            "share REJECTED: sequence {rejected} job 12 nonce "
        )) && text.contains(": stale-share ("),
        "{text}"
    );
    assert!(
        text.contains("1 sessions: ") && text.contains(" rejected, "),
        "{text}"
    );
    assert!(
        !text.contains("session 1 ended"),
        "one session throughout: {text}"
    );
}

/// Run this client against the script at `address` until the script ends,
/// and return its log.
fn mine(address: String, pinned: XOnlyPublicKey, stop: &Arc<AtomicBool>, name: &str) -> String {
    let pool = Pool {
        address,
        user: "bcrt1qexample.puntominer".into(),
        pass: String::new(),
        difficulty: 1e-9,
        agent: "PuntoMiner/0.1".into(),
        reconnect: Duration::from_millis(50),
        version_rolling: VersionRolling::Auto,
        protocol: Protocol::V2,
        authority: Authority::Pinned(pinned),
        hashrate: 1e6,
        capture: String::new(),
    };

    let path = std::env::temp_dir().join(format!(
        "puntominer-scripted-{}-{name}.log",
        std::process::id()
    ));
    let log = Logger::open(&path).expect("the log opens");
    let signals = Signals::new(Arc::clone(stop));
    run(
        &pool,
        Some(Cpu {
            workers: 1,
            hasher: Hasher::Naive,
            load_percent: 100,
        }),
        None,
        Extranonce::ZERO,
        &signals,
        &log,
    )
    .expect("the run ends on the stop flag");
    drop(log);
    let text = std::fs::read_to_string(&path).expect("the log reads back");
    let _ = std::fs::remove_file(&path);

    text
}

#[test]
fn a_job_announcing_30000000_is_a_non_event() {
    // **What killed every V1 share on regtest, and should not matter here.**
    // Under V1 the pool rebuilds the version from the announced one and the
    // rolled bits, and two pools do that two ways that disagree exactly when
    // the announced version has a bit inside the mask, as `30000000` does.
    // `SubmitSharesExtended` carries the full nVersion, so the pool rebuilds
    // nothing. PuntoHunter cannot show it: it clears every BIP320 bit a
    // template does not require before announcing, so a `-blockversion`
    // chain reaches its miners as `20000000`. This script announces
    // `30000000` and allows rolling, and takes the submitted version as the
    // only version there is.
    //
    // The CPU search rolls only after a whole nonce range, so these shares are
    // unrolled. Rolled shares against a `30000000` job are what a GPU run
    // against a pool that announces one would add.
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[32u8; 32]).unwrap();
    let pinned = Keypair::from_secret_key(&secp, &secret)
        .x_only_public_key()
        .0;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("its address").to_string();
    let stop = Arc::new(AtomicBool::new(false));

    let server = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let _stop = StopOnDrop(stop);
            let mut pool = Script::start(&listener, &secret);
            pool.job_announcing(11, 0x3000_0000, true);
            for _ in 0..4 {
                let share = pool.next_share();
                assert_eq!(share.job_id, 11);
                assert_eq!(
                    share.version, 0x3000_0000,
                    "the full nVersion, bit 28 and all"
                );
                assert!(meets(rebuild(&share, &PREFIX_OPEN), &easy()));
                pool.accept(&share);
            }
        })
    };

    let text = mine(address, pinned, &stop, "30000000");
    server
        .join()
        .expect("every share rebuilt under the version it carried");
    assert!(text.contains(" 0 rejected, "), "{text}");
}
