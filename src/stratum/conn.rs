//! The socket, the framing, and the handshake.
//!
//! Stratum V1 is JSON-RPC over a raw TCP stream with a newline between frames
//! and no length prefix, no framing layer and no TLS on the ports every pool
//! actually runs. `rpc.rs` is the precedent for all of it: hand-rolled, no
//! dependency, explicit about its errors. This is less work than that was,
//! because there is no HTTP.
//!
//! The one structural difference from `rpc.rs` is that this connection is held
//! rather than opened per call. It has to be: a pool pushes `mining.notify` and
//! `mining.set_difficulty` at its own pace, and the whole point of the protocol
//! is being on the socket when it does. So `Conn` is not `Clone` and not
//! `Send`-shared — `run.rs` gives it to one thread and reads it there.
//!
//! **Nothing here connects on its own.** [`Conn::connect`] is reached only from
//! `MINER_MODE=stratum` with `MINER_POOL` set, which is asserted in
//! `runner.rs`: a miner that opens a socket to a stranger out of the box is a
//! network-visible action taken without being asked.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use serde_json::{Value, json};

use super::{
    messages::{Incoming, Subscribed, failure},
    pool::BIP320_MASK,
};

/// How long to wait for the TCP handshake before giving up on an address.
///
/// Short, because a pool that cannot be reached in this long is one to report
/// rather than one to wait for, and because [`Conn::connect`] walks every
/// address a hostname resolves to.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a read blocks before it is treated as a dead socket.
///
/// Longer than any pool's notify interval by a wide margin. Pools go quiet
/// between blocks — Pool A's captured interval was tens of seconds, and a
/// quiet mainnet stretch is minutes — so a timeout tuned to "there should have
/// been work by now" reconnects a healthy session. This is tuned to "the far
/// end is gone".
const READ_TIMEOUT: Duration = Duration::from_secs(600);

/// The longest frame this client will read.
///
/// A `mining.notify` with a full merkle branch and a large coinbase is a few
/// kilobytes; this is two orders of magnitude past that. It exists because
/// `BufRead::read_line` on a socket that never sends a newline will grow a
/// `String` until the process dies, and a pool is not a trusted peer.
const FRAME_MAX: usize = 1 << 20;

/// Whether every address this name resolves to is on the loopback.
///
/// Its own function, called before any socket is opened, so that
/// `MINER_VERSION_ROLLING=force` is refused without having connected to
/// anything. **Every** address, not the first: a name that resolves to both
/// `127.0.0.1` and a public address is not a local pool, and which one a
/// connection lands on is not this client's to decide.
pub fn resolves_to_loopback(address: &str) -> Result<bool, String> {
    let resolved: Vec<_> = address
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve the pool address {address}: {error}"))?
        .collect();
    if resolved.is_empty() {
        return Err(format!("the pool address {address} resolved to nothing"));
    }
    Ok(resolved.iter().all(|address| address.ip().is_loopback()))
}

/// One held connection to a pool.
#[derive(Debug)]
pub struct Conn {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    next_id: u64,
    peer: String,
}

impl Conn {
    /// Open a connection to `host:port`.
    ///
    /// Every resolved address is tried in turn, because a pool hostname behind
    /// a load balancer resolves to several and the first is not always up.
    /// `TcpStream::connect` would do that too, but without a per-address
    /// timeout, so a single black-holed address could hang the whole attempt
    /// for the system default.
    pub fn connect(address: &str) -> Result<Self, String> {
        let resolved: Vec<_> = address
            .to_socket_addrs()
            .map_err(|error| format!("could not resolve the pool address {address}: {error}"))?
            .collect();
        if resolved.is_empty() {
            return Err(format!("the pool address {address} resolved to nothing"));
        }

        let mut last = String::new();
        for candidate in &resolved {
            match TcpStream::connect_timeout(candidate, CONNECT_TIMEOUT) {
                Ok(stream) => {
                    // Nagle batches small writes, and every frame this client
                    // sends is a small write that the pool is waiting on. A
                    // share delayed by 40ms of coalescing is a share that may
                    // arrive after the job it answers went stale.
                    stream
                        .set_nodelay(true)
                        .map_err(|error| format!("could not disable Nagle: {error}"))?;
                    stream
                        .set_read_timeout(Some(READ_TIMEOUT))
                        .map_err(|error| format!("could not set a read timeout: {error}"))?;
                    let reader =
                        BufReader::new(stream.try_clone().map_err(|error| {
                            format!("could not clone the pool socket: {error}")
                        })?);
                    return Ok(Self {
                        stream,
                        reader,
                        next_id: 1,
                        peer: format!("{candidate}"),
                    });
                }
                Err(error) => last = format!("{candidate}: {error}"),
            }
        }

        Err(format!(
            "could not connect to the pool at {address} ({} address{}): {last}",
            resolved.len(),
            if resolved.len() == 1 { "" } else { "es" }
        ))
    }

    /// Which address this connection actually reached, for the log.
    ///
    /// Worth saying out loud once: a pool hostname resolving to a different
    /// address than expected is the first thing to check when shares are
    /// accepted and never credited.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Send a call and return the id it was sent under.
    ///
    /// The id rather than the answer, because the answer is not next on the
    /// socket. A pool may push a `mining.notify` between a call and its reply —
    /// Pool A does, within the handshake itself — so a `call` that read
    /// until it saw a reply would have to either drop those frames or buffer
    /// them, and both belong in the caller's loop rather than here.
    ///
    /// Ids start at 1 and never at 0, which is not cosmetic. Pool A answers
    /// a notification — a frame sent with `"id": null` — by coercing that null
    /// to `0` and replying `{"id":0,"result":true,"error":null}`, measured on
    /// 18 September 2026 against `mining.suggest_difficulty`. A client whose
    /// first call was id 0 would read that acknowledgement as the answer to it.
    pub fn call(&mut self, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"id": id, "method": method, "params": params}))?;
        Ok(id)
    }

    /// Send a frame that expects no answer.
    ///
    /// Kept separate from [`Self::call`] so that an id is never allocated for
    /// something nothing will ever match against it. "Expects no answer" is
    /// this client's position and not a promise about the pool: Pool A
    /// answers `mining.suggest_difficulty` regardless, under id 0. That reply
    /// is harmless precisely because nothing is waiting for it.
    pub fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        self.send(json!({"id": Value::Null, "method": method, "params": params}))
    }

    fn send(&mut self, frame: Value) -> Result<(), String> {
        let mut line = frame.to_string();
        line.push('\n');
        self.stream
            .write_all(line.as_bytes())
            .map_err(|error| format!("could not write to the pool: {error}"))?;
        self.stream
            .flush()
            .map_err(|error| format!("could not flush to the pool: {error}"))
    }

    /// Read exactly one frame, blocking until it arrives.
    ///
    /// A read timeout is an error here, which is what the handshake wants: at
    /// that point the pool owes an answer and silence is a dead socket.
    pub fn read(&mut self) -> Result<Incoming, String> {
        self.read_timed()?
            .ok_or_else(|| "the pool sent nothing before the read timed out".to_string())
    }

    /// Read one frame, reporting a read timeout as `None` rather than an error.
    ///
    /// The session loop needs the difference. It sets a short timeout and calls
    /// this in a loop so that a quiet pool — which is the normal state between
    /// blocks — does not leave a thread parked where a Ctrl-C cannot reach it.
    /// Silence is only a dead socket after `READ_TIMEOUT`, and that is the
    /// caller's judgement to make rather than this function's.
    pub fn read_timed(&mut self) -> Result<Option<Incoming>, String> {
        let mut line = String::new();
        loop {
            line.clear();
            let read = match self
                .reader
                .by_ref()
                .take(FRAME_MAX as u64)
                .read_line(&mut line)
            {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(format!("could not read from the pool: {error}")),
            };

            if read == 0 {
                return Err("the pool closed the connection".into());
            }
            if read == FRAME_MAX && !line.ends_with('\n') {
                return Err(format!(
                    "the pool sent more than {FRAME_MAX} bytes with no newline"
                ));
            }
            // Pools send keepalive newlines, and a `\r\n` pool is not unheard
            // of. Neither is a frame.
            if line.trim().is_empty() {
                continue;
            }
            return Incoming::parse(line.trim()).map(Some);
        }
    }

    /// A second handle on the same socket, for writing from another thread.
    ///
    /// The run loop needs both halves at once: a thread parked in
    /// [`Self::read`] so a `mining.notify` is seen the moment it lands, and the
    /// grinding thread writing a `mining.submit` the moment a share is found.
    /// One `Conn` behind a mutex would put every submit behind a read that
    /// blocks for as long as the pool is quiet, which on a mainnet pool is
    /// tens of seconds.
    ///
    /// The clone is a second file descriptor onto one socket, so the kernel
    /// serialises the writes and a frame cannot interleave with another. Ids
    /// continue from where this connection's calls left off, so a submit can
    /// never collide with the handshake's outstanding ones.
    pub fn writer(&self) -> Result<Writer, String> {
        Ok(Writer {
            stream: self
                .stream
                .try_clone()
                .map_err(|error| format!("could not clone the pool socket: {error}"))?,
            next_id: AtomicU64::new(self.next_id),
        })
    }

    /// Bound how long the next [`Self::read`] will block.
    ///
    /// Used by `run.rs` to give the grinding loop a turn rather than to detect a
    /// dead pool — that is `READ_TIMEOUT`'s job.
    pub fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("could not set a read timeout: {error}"))
    }
}

/// The write half of a connection, usable from another thread.
///
/// Holds no reader, so nothing it does can block on the pool being quiet.
/// `&self` rather than `&mut self` throughout, because the grinding thread's
/// share callback has only a shared borrow to give it.
#[derive(Debug)]
pub struct Writer {
    stream: TcpStream,
    next_id: AtomicU64,
}

impl Writer {
    /// Send a call and return the id it was sent under, for matching the reply.
    pub fn call(&self, method: &str, params: Value) -> Result<u64, String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.send(json!({"id": id, "method": method, "params": params}))?;
        Ok(id)
    }

    /// Send a frame as it is, which is how a reply to the pool's own request
    /// goes out: under the pool's id rather than one of this client's.
    pub fn send(&self, frame: Value) -> Result<(), String> {
        let mut line = frame.to_string();
        line.push('\n');
        // One `write_all` per frame, so two threads writing cannot interleave
        // halfway through a line — which would be a frame neither of them sent.
        (&self.stream)
            .write_all(line.as_bytes())
            .map_err(|error| format!("could not write to the pool: {error}"))
    }
}

/// What a completed handshake produced.
#[derive(Debug)]
pub struct Handshake {
    pub subscribed: Subscribed,
    /// Frames the pool pushed before the handshake finished, in arrival order.
    ///
    /// Not discarded, because Pool A sends `mining.set_difficulty` and the
    /// first `mining.notify` between the subscribe reply and the authorize
    /// reply. A handshake that swallowed those would start its first search
    /// against the second job at the default difficulty, and the cross-pool
    /// measurements made in development showed why the first `set_difficulty`
    /// matters.
    pub pushed: Vec<Incoming>,
    /// The version bits the pool will let this client roll, from its
    /// `mining.configure` reply, or `None` if it refused or has never heard of
    /// BIP310.
    ///
    /// All three pools measured in development answer `1fffe000` —
    /// the sixteen bits BIP320 sets aside — but that is a measurement of three
    /// pools rather than a rule, so it is read off the reply and never assumed.
    /// It is also clamped to those sixteen bits: see [`clamp_mask`].
    pub version_mask: Option<u32>,
    /// The mask as the pool sent it, before the clamp, so the log can say when
    /// the two differ.
    pub offered_mask: Option<u32>,
}

/// Subscribe, ask for a difficulty twice, and authorize.
///
/// The order is the capture's, with one addition the capture cannot show:
/// `mining.configure` goes first because BIP310 says it must precede
/// `mining.subscribe`, and cpuminer 2.5.1 predates the extension and never
/// sends it. The reply is not acted on here; [`Handshake::version_mask`] is
/// what the version roll acts on, and a pool that refuses is answered by not
/// rolling rather than by failing — mining without version rolling is what
/// every pool did until 2018.
///
/// **The difficulty is asked for both ways.** Three live pools measured in
/// development showed that neither lever works everywhere: `d=` in the
/// password works on one pool in three, `mining.suggest_difficulty` on two,
/// and `minimum-difficulty` on none. Sending both costs one frame and is the
/// only portable answer.
///
/// **Nothing blocks on the `suggest_difficulty` reply.** Pool B acts on it
/// and never answers, so a handshake that waited would hang against a pool that
/// did exactly what it was asked.
pub fn handshake(
    conn: &mut Conn,
    agent: &str,
    user: &str,
    pass: &str,
    difficulty: f64,
) -> Result<Handshake, String> {
    let mut pushed = Vec::new();

    // Asked before subscribing, per BIP310, and the answer is kept for the roll.
    let configure = conn.call(
        "mining.configure",
        json!([["version-rolling"], {"version-rolling.mask": "1fffe000"}]),
    )?;
    let subscribe = conn.call("mining.subscribe", json!([agent]))?;

    // Two levers, one difficulty. Neither is acknowledged by every pool and
    // neither is waited for.
    //
    // **Sent as a call with an id, not as a notification.** That looks like a
    // detail and is not: Pool B *validates* the id and refuses a null one,
    // so a notification leaves it at its floor — weeks per share at
    // cpuminer's rate, which is what
    // the first cross-pool measurement saw and read as the pool ignoring the
    // request.
    // With an id it acts on it, drops to the asked-for difficulty, and sends no
    // reply at all. Measured against a local instance on 18 September 2026.
    conn.call("mining.suggest_difficulty", json!([difficulty]))?;
    let authorize = conn.call("mining.authorize", json!([user, pass]))?;

    let mut subscribed = None;
    let mut offered_mask = None;
    loop {
        match conn.read()? {
            Incoming::Reply { id, result, error } if id == Some(configure) => {
                // Not fatal in either direction. A pool that has never heard of
                // BIP310 answers with an error, and mining without version
                // rolling is exactly what every pool did until 2018.
                if let Some(why) = failure(&result, &error) {
                    pushed.push(Incoming::Unknown(format!(
                        "mining.configure refused: {why}"
                    )));
                } else {
                    offered_mask = negotiated_mask(&result);
                }
            }

            Incoming::Reply { id, result, error } if id == Some(subscribe) => {
                if let Some(why) = failure(&result, &error) {
                    return Err(format!("the pool refused mining.subscribe: {why}"));
                }
                subscribed = Some(Subscribed::parse(&result)?);
            }

            Incoming::Reply { id, result, error } if id == Some(authorize) => {
                // The one fatal reply. A typo'd address is the likeliest cause
                // and no pool says which field it disliked, so the address goes
                // in the message — the alternative is a run that mines for
                // hours and is credited to nobody.
                if let Some(why) = failure(&result, &error) {
                    return Err(format!(
                        "the pool refused to authorize {user}: {why} \
                         (is the payout address right, and is it an address this pool accepts?)"
                    ));
                }
                if result != Value::Bool(true) {
                    return Err(format!(
                        "the pool answered mining.authorize for {user} with {result} \
                         rather than true"
                    ));
                }
                return match subscribed {
                    Some(subscribed) => Ok(Handshake {
                        subscribed,
                        pushed,
                        version_mask: offered_mask.and_then(clamp_mask),
                        offered_mask,
                    }),
                    // Ordering is the pool's business and both captures answer
                    // subscribe first, but a pool that answered out of order
                    // and then said yes would otherwise leave this returning an
                    // extranonce1 it never received.
                    None => Err("the pool authorized before it subscribed".into()),
                };
            }

            // Everything else the pool pushed while this was in flight — the
            // first set_difficulty and the first notify, on Pool A.
            other => pushed.push(other),
        }
    }
}

/// The version bits a `mining.configure` reply agreed to.
///
/// Both halves are required. A pool may answer `version-rolling: false` and
/// still echo a mask, and one that says `true` without a mask has agreed to
/// nothing this client can act on — rolling bits a pool did not name produces
/// a header it cannot reconstruct, and every share under it is rejected.
///
/// A mask of zero is `None` rather than an empty roll: it is a pool saying no
/// in the other available spelling.
///
/// The mask is returned as the pool sent it; [`clamp_mask`] is what decides
/// how much of it is rolled.
fn negotiated_mask(result: &Value) -> Option<u32> {
    if result.get("version-rolling")? != &Value::Bool(true) {
        return None;
    }
    let mask = result.get("version-rolling.mask")?.as_str()?;
    match super::wire::be_u32_from_hex(mask) {
        Ok(0) | Err(_) => None,
        Ok(mask) => Some(mask),
    }
}

/// The part of a pool's mask this client will roll: BIP320's sixteen bits and
/// no others, or `None` when that leaves nothing.
///
/// BIP310 makes the server's mask a subset of the client's, and this client
/// asks for `1fffe000`, so a pool that answered more has answered outside the
/// question. It may have agreed to those bits, but no block built on a header
/// that rolled bits 29 to 31 or the low thirteen is valid, so they are never
/// rolled. **One function with two callers** — the `mining.configure` answer and
/// every later `mining.set_version_mask` — so the rule has one spelling.
/// `MINER_VERSION_ROLLING=force` adds its bit after this, on purpose.
pub fn clamp_mask(mask: u32) -> Option<u32> {
    Some(mask & BIP320_MASK).filter(|clamped| *clamped != 0)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread::{self, JoinHandle},
    };

    use super::*;
    use crate::constants::MINER_ADDRESS;

    /// The worker name the captures were taken under.
    const USER: &str = "bc1qa0wd8gy8vtgj3vs2e5emzv7lnmfdf9e8nfq8ug.puntominer";

    /// Stand up a pool on the loopback that answers according to `script`.
    ///
    /// Loopback rather than a mock trait, because the thing worth testing here
    /// *is* the socket: the framing, the newline, the flush, and reading a
    /// reply that arrives after two frames the pool pushed in front of it.
    /// Nothing leaves the machine, so this belongs in the default suite in a
    /// way the live test below does not.
    ///
    /// Returns the address to connect to and a handle yielding every line the
    /// client sent, in order — which is how the handshake's *order* is
    /// asserted rather than just its outcome.
    fn scripted_pool(
        script: impl Fn(&Value) -> Vec<String> + Send + 'static,
    ) -> (String, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the loopback should be bindable");
        let address = listener.local_addr().expect("a bound port").to_string();

        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("the client should connect");
            let mut writer = stream.try_clone().expect("the socket should clone");
            let mut reader = BufReader::new(stream);
            let mut sent = Vec::new();

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let frame: Value = match serde_json::from_str(line.trim()) {
                    Ok(frame) => frame,
                    Err(_) => break,
                };
                sent.push(line.trim().to_string());
                for answer in script(&frame) {
                    if writeln!(writer, "{answer}").is_err() {
                        return sent;
                    }
                }
            }
            sent
        });

        (address, handle)
    }

    /// Pool A's own answers, by method, including the two frames it pushes
    /// between the subscribe reply and the authorize reply.
    fn pool_a_script(frame: &Value) -> Vec<String> {
        let id = &frame["id"];
        match frame["method"].as_str() {
            Some("mining.configure") => vec![format!(
                r#"{{"id":{id},"result":{{"version-rolling":true,"version-rolling.mask":"1fffe000"}},"error":null}}"#
            )],
            Some("mining.subscribe") => vec![format!(
                r#"{{"id":{id},"result":[[["mining.set_difficulty","10086bd1"],["mining.notify","10086bd1"]],"10086bd1",8],"error":null}}"#
            )],
            // Acted on, never answered — exactly what Pool B does.
            Some("mining.suggest_difficulty") => vec![],
            Some("mining.authorize") => vec![
                r#"{"id":null,"method":"mining.set_difficulty","params":[1]}"#.to_string(),
                r#"{"id":null,"method":"mining.notify","params":["682bcc4527a38","98ccd6c190d927b95a692b4a65b6d5137f93c9c2000228520000000000000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff","ffffffff0100f2052a01000000160014329649f03db93aef2cf873e9b8544a446d38316d00000000",[],"20000000","1702355e","6aac80b6",true]}"#.to_string(),
                format!(r#"{{"id":{id},"result":true,"error":null}}"#),
            ],
            _ => vec![],
        }
    }

    #[test]
    fn a_handshake_survives_the_frames_a_pool_pushes_through_it() {
        // The reason `call` returns an id rather than an answer. Pool A
        // sends the first set_difficulty and the first notify *before* the
        // authorize reply, and a client that read until it saw its reply would
        // have thrown both away — starting its first search at the default
        // difficulty against the wrong job.
        let (address, pool) = scripted_pool(pool_a_script);
        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        let done = handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0)
            .expect("the scripted handshake completes");

        assert_eq!(done.subscribed.extranonce1, vec![0x10, 0x08, 0x6b, 0xd1]);
        assert_eq!(done.subscribed.extranonce2_size, 8);

        let difficulty = done
            .pushed
            .iter()
            .find_map(|frame| match frame {
                Incoming::SetDifficulty(d) => Some(*d),
                _ => None,
            })
            .expect("the set_difficulty pushed mid-handshake is kept");
        assert_eq!(difficulty, 1.0);

        let notify = done
            .pushed
            .iter()
            .find_map(|frame| match frame {
                Incoming::Notify(notify) => Some(notify),
                _ => None,
            })
            .expect("the notify pushed mid-handshake is kept");
        assert_eq!(notify.job_id, "682bcc4527a38");
        assert!(notify.clean_jobs);

        drop(conn);
        let sent = pool.join().expect("the pool thread should finish");
        let methods: Vec<String> = sent
            .iter()
            .map(|line| {
                let frame: Value = serde_json::from_str(line).expect("the client sends JSON");
                frame["method"].as_str().expect("with a method").to_string()
            })
            .collect();

        assert_eq!(
            methods,
            vec![
                "mining.configure",
                "mining.subscribe",
                "mining.suggest_difficulty",
                "mining.authorize",
            ],
            "configure precedes subscribe, per BIP310"
        );
    }

    #[test]
    fn the_difficulty_is_asked_for_both_ways() {
        // Three live pools showed that neither lever works everywhere: `d=` on one
        // pool in three, suggest_difficulty on two, minimum-difficulty on none.
        // Sending both costs one frame, and this is the assertion that keeps
        // someone from tidying one of them away.
        let (address, pool) = scripted_pool(pool_a_script);
        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        handshake(&mut conn, "puntominer/0.1", USER, "d=512", 512.0).expect("it completes");
        drop(conn);

        let sent = pool.join().expect("the pool thread should finish");
        let frames: Vec<Value> = sent
            .iter()
            .map(|line| serde_json::from_str(line).expect("the client sends JSON"))
            .collect();

        let suggest = frames
            .iter()
            .find(|frame| frame["method"] == "mining.suggest_difficulty")
            .expect("the lever that works on two pools in three");
        assert_eq!(suggest["params"][0], 512.0);
        // **With a real id.** Pool B validates it and refuses a null one,
        // leaving the session at its floor — which is what a notification looks like from the
        // outside: a pool that ignored the request. Measured 18 September 2026.
        // Nothing waits on the answer either way; the handshake returns on the
        // authorize reply.
        assert!(
            suggest["id"].as_u64().is_some(),
            "a null id is refused by at least one real pool: {}",
            suggest["id"]
        );

        let authorize = frames
            .iter()
            .find(|frame| frame["method"] == "mining.authorize")
            .expect("the lever that works on one pool in three");
        assert_eq!(authorize["params"][1], "d=512");
    }

    #[test]
    fn the_first_call_is_id_one_and_never_id_zero() {
        // Measured against Pool A on 18 September 2026: a frame sent with
        // `"id": null` comes back answered under `"id": 0`. The pool coerces
        // the null rather than treating the frame as a notification, so a
        // client that numbered its calls from zero would read that
        // acknowledgement as the answer to its first call. Ours never does.
        let (address, pool) = scripted_pool(pool_a_script);
        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0).expect("it completes");
        drop(conn);

        let ids: Vec<Value> = pool
            .join()
            .expect("the pool thread should finish")
            .iter()
            .map(|line| {
                serde_json::from_str::<Value>(line).expect("the client sends JSON")["id"].clone()
            })
            .collect();

        assert_eq!(
            ids,
            vec![json!(1), json!(2), json!(3), json!(4)],
            "every call is numbered, from one"
        );
        assert!(
            !ids.contains(&json!(0)),
            "id 0 is what a pool answers a null id with, not something to issue"
        );
        assert!(
            !ids.contains(&Value::Null),
            "a null id is refused outright by at least one real pool"
        );
    }

    #[test]
    fn a_refused_authorize_is_fatal_and_names_the_address() {
        // The worst available failure is the silent one: a run that mines for
        // hours and is credited to nobody. No pool says which field it
        // disliked, so the message carries the address a human can check.
        let refuse = |frame: &Value| -> Vec<String> {
            let id = &frame["id"];
            match frame["method"].as_str() {
                Some("mining.authorize") => {
                    vec![format!(r#"{{"id":{id},"result":false,"error":null}}"#)]
                }
                _ => pool_a_script(frame),
            }
        };

        let (address, pool) = scripted_pool(refuse);
        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        let why = handshake(&mut conn, "puntominer/0.1", MINER_ADDRESS, "d=1", 1.0)
            .expect_err("a refused authorize ends the handshake");
        drop(conn);
        let _ = pool.join();

        assert!(
            why.contains(MINER_ADDRESS),
            "the message names the address: {why}"
        );
        assert!(why.contains("refused"), "and says what happened: {why}");
    }

    #[test]
    fn a_pool_that_hangs_up_mid_handshake_says_so() {
        // Reconnect is normal rather than exceptional — pools drop idle sockets
        // and restart — so the run loop has to be able to tell this apart from
        // a protocol error. It can only do that if this error says what it is.
        let listener = TcpListener::bind("127.0.0.1:0").expect("the loopback should be bindable");
        let address = listener.local_addr().expect("a bound port").to_string();
        let pool = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("the client should connect");
            // Read the handshake it sent, then go away without answering — a
            // pool restarting mid-session, which is the common case.
            let mut reader = BufReader::new(&stream);
            for _ in 0..4 {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
            }
            drop(reader);
            drop(stream);
        });

        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        let why = handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0)
            .expect_err("a silent pool is not a handshake");
        pool.join().expect("the pool thread should finish");

        assert!(
            why.contains("closed the connection"),
            "an unhelpful error is worse than none: {why}"
        );
    }

    #[test]
    fn an_unreachable_pool_names_what_it_tried() {
        let why = Conn::connect("127.0.0.1:1").expect_err("nothing listens on port 1");
        assert!(why.contains("127.0.0.1:1"), "{why}");

        // The resolution branch, reached without a resolver: a hostname with
        // no port is rejected before any lookup happens. Asserted this way
        // rather than against a `.invalid` name on purpose — that costs ten
        // seconds of DNS timeout on this host, and the default suite runs at
        // every step boundary.
        let why = Conn::connect("pool.example.com")
            .expect_err("a hostname without a port is not an address");
        assert!(why.contains("pool.example.com"), "{why}");
        assert!(why.contains("resolve"), "{why}");
    }

    #[test]
    fn the_configure_reply_is_read_for_a_mask_and_nothing_else() {
        // All three pools measured in development answer `1fffe000`, which
        // is a measurement of three pools rather than a rule — so it is read
        // off the reply.
        let (address, pool) = scripted_pool(pool_a_script);
        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        let done = handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0).expect("it completes");
        drop(conn);
        let _ = pool.join();
        assert_eq!(done.version_mask, Some(0x1fff_e000));
    }

    #[test]
    fn half_an_agreement_is_no_agreement() {
        // Rolling bits a pool did not name produces a header it cannot
        // reconstruct, and every share under it is rejected — which looks
        // exactly like a byte-order bug and is the worst way to discover this.
        // So both halves of the reply are required.
        let refusals = [
            r#"{"version-rolling":false,"version-rolling.mask":"1fffe000"}"#,
            r#"{"version-rolling":true}"#,
            r#"{"version-rolling":true,"version-rolling.mask":"00000000"}"#,
            r#"{"version-rolling":true,"version-rolling.mask":"not hex"}"#,
            r#"{}"#,
            r#"true"#,
        ];

        for refusal in refusals {
            let script = move |frame: &Value| -> Vec<String> {
                let id = &frame["id"];
                match frame["method"].as_str() {
                    Some("mining.configure") => {
                        vec![format!(r#"{{"id":{id},"result":{refusal},"error":null}}"#)]
                    }
                    _ => pool_a_script(frame),
                }
            };
            let (address, pool) = scripted_pool(script);
            let mut conn = Conn::connect(&address).expect("the scripted pool is up");
            let done =
                handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0).expect("it completes");
            drop(conn);
            let _ = pool.join();
            assert_eq!(
                done.version_mask, None,
                "{refusal} is not an agreement to roll anything"
            );
        }
    }

    #[test]
    fn a_mask_wider_than_bip320_is_clamped_to_it() {
        // A pool answering more than it was asked is answering outside the
        // question, and the bits outside BIP320 make headers no block can use.
        for (answer, expected) in [
            ("ffffffff", Some(0x1fff_e000)),
            ("e0000000", None),
            ("00001fff", None),
            ("1fffe000", Some(0x1fff_e000)),
            ("00ffe000", Some(0x00ff_e000)),
        ] {
            let script = move |frame: &Value| -> Vec<String> {
                let id = &frame["id"];
                match frame["method"].as_str() {
                    Some("mining.configure") => vec![format!(
                        r#"{{"id":{id},"result":{{"version-rolling":true,"version-rolling.mask":"{answer}"}},"error":null}}"#
                    )],
                    _ => pool_a_script(frame),
                }
            };
            let (address, pool) = scripted_pool(script);
            let mut conn = Conn::connect(&address).expect("the scripted pool is up");
            let done =
                handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0).expect("it completes");
            drop(conn);
            let _ = pool.join();
            assert_eq!(done.version_mask, expected, "an answer of {answer}");
            assert_eq!(
                done.offered_mask,
                Some(u32::from_str_radix(answer, 16).unwrap()),
                "and the answer itself is kept for the log"
            );
        }
    }

    #[test]
    fn a_pool_that_refuses_mining_configure_is_still_a_pool() {
        // Mining without version rolling is what every pool did until 2018, and
        // cpuminer 2.5.1 still does. A client that treated the refusal as fatal
        // would refuse to work against anything that predates BIP310.
        let refuse = |frame: &Value| -> Vec<String> {
            let id = &frame["id"];
            match frame["method"].as_str() {
                Some("mining.configure") => vec![format!(
                    r#"{{"id":{id},"result":null,"error":[20,"Unknown method",null]}}"#
                )],
                _ => pool_a_script(frame),
            }
        };

        let (address, pool) = scripted_pool(refuse);
        let mut conn = Conn::connect(&address).expect("the scripted pool is up");
        let done = handshake(&mut conn, "puntominer/0.1", USER, "d=1", 1.0)
            .expect("a refused configure is not a refused handshake");
        drop(conn);
        let _ = pool.join();

        assert_eq!(done.version_mask, None);
        assert_eq!(
            done.subscribed.extranonce2_size, 8,
            "the rest still happened"
        );
        assert!(
            done.pushed.iter().any(|frame| matches!(
                frame,
                Incoming::Unknown(note) if note.contains("mining.configure refused")
            )),
            "the refusal is recorded rather than swallowed"
        );
    }

    #[test]
    fn only_a_pool_on_this_machine_counts_as_loopback() {
        assert!(resolves_to_loopback("127.0.0.1:3333").expect("a literal address"));
        assert!(resolves_to_loopback("[::1]:3333").expect("a literal address"));
        assert!(!resolves_to_loopback("1.1.1.1:3333").expect("a literal address"));
        // A public address that happens to be reachable is still not local.
        assert!(!resolves_to_loopback("8.8.8.8:3350").expect("a literal address"));
        assert!(resolves_to_loopback("not-an-address").is_err());
    }

    /// The live check, run by hand and never in the default suite.
    ///
    /// ```sh
    /// cargo test --release stratum::conn::tests::a_live -- --ignored --nocapture
    /// ```
    ///
    /// It asserts the one property the cross-pool measurements say decides whether
    /// this client is usable at all: that the pool's first `set_difficulty`
    /// arrives, and arrives at 1 rather than at its 512 default, before there
    /// is any work to do. A difficulty of 512 on this hardware is 49 minutes
    /// per share, which is indistinguishable from a hung socket.
    #[test]
    #[ignore = "needs the network and a live pool"]
    fn a_live_pool_sets_the_difficulty_before_it_sends_work() {
        let mut conn =
            Conn::connect("stratum.puntohunter.com:3333").expect("the pool is reachable");
        println!("connected to {}", conn.peer());

        let user = format!("{MINER_ADDRESS}.puntominer");
        let done = handshake(&mut conn, "puntominer/0.1", &user, "d=1", 1.0)
            .expect("the pool authorizes a payout address");
        println!(
            "extranonce1 {}, extranonce2_size {}",
            done.subscribed
                .extranonce1
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            done.subscribed.extranonce2_size
        );

        let mut difficulty = None;
        let mut frames = done.pushed;
        loop {
            for frame in frames.drain(..) {
                match frame {
                    Incoming::SetDifficulty(value) => {
                        println!("set_difficulty {value}");
                        difficulty = Some(value);
                    }
                    Incoming::Notify(notify) => {
                        println!("notify {} clean_jobs {}", notify.job_id, notify.clean_jobs);
                        assert_eq!(
                            difficulty,
                            Some(1.0),
                            "the pool should set difficulty 1 before the first job"
                        );
                        return;
                    }
                    other => println!("ignored {other:?}"),
                }
            }
            frames.push(conn.read().expect("the pool keeps talking"));
        }
    }
}
