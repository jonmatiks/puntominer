//! The socket, the Noise tunnel, and the framing on top of it.
//!
//! [`conn.rs`](super::super::conn)'s opposite number, and the same shape: a
//! held connection, a read half that one thread parks on and a write half
//! another thread uses, with no dependency doing the protocol work. What is
//! different is that every byte in both directions goes through a cipher
//! state, and **a cipher state is a counter as well as a key.**
//!
//! That one fact decides most of this file's structure:
//!
//! - **The write half owns its cipher state behind a mutex, and encrypts
//!   inside the lock.** V1 can get away with a bare `write_all` per frame,
//!   because two frames written in either order are both valid. Here the
//!   nonce that encrypted a frame has to be the nonce the far end is on when
//!   it arrives, so encrypting and writing are one critical section. Two
//!   threads that encrypted concurrently and then wrote would produce two
//!   frames the pool cannot decrypt, and the session would be over.
//! - **A read cannot be abandoned half way.** A reader that consumed nine
//!   bytes of a 22-byte header and gave up would have to resynchronise, and a
//!   Noise stream cannot be resynchronised. So the partly-read frame is kept
//!   here between calls, and [`Conn::read_timed`] returns `None` for "nothing
//!   more yet" without ever losing what it already has.
//!
//! The framing itself is spec §4.6 and is described in
//! [`frame`](super::frame): a 6-byte header encrypted on its own to 22 bytes,
//! then the payload in 65,519-byte chunks each growing a 16-byte MAC. The
//! `msg_length` in the header is the **plaintext** length, so the number of
//! bytes to read off the socket is [`ct_len`] of it and never it.
//!
//! **`MINER_POOL_CAPTURE` is recorded here, and only here.** Under Noise
//! there is no wire capture to take — `tcpdump` yields ciphertext — so the
//! one plaintext boundary this client has is the one this file draws: an
//! inbound frame is recorded after its tag has verified and before
//! [`Incoming::parse`] sees it, and an outbound one after it was written. A
//! capture taken inside `messages.rs` would be correlated with the parser it
//! exists to check; one taken here holds the pool's encoder's bytes, which a
//! wrong `noise.rs` cannot forge, because they would not authenticate. See
//! [`Capture`].

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

use bitcoin::secp256k1::XOnlyPublicKey;

use super::{
    frame::{self, ENCRYPTED_HEADER_LEN, HEADER_LEN, Header, MAX_CT_CHUNK, MAX_PT_CHUNK, ct_len},
    messages::{Incoming, Outgoing},
    noise::{CipherState, Handshake, PART_2_LEN},
};

/// A `MINER_POOL_CAPTURE` file: every frame of a session, in plaintext.
///
/// One frame per line, `recv` or `send`, the hex of the six-byte header and
/// the payload, and the message's name in a comment column:
///
/// ```text
/// # connected to 127.0.0.1:3334 at 1793990000
/// recv 0000011600000002000000000000 # SetupConnection.Success
/// send 00801b2a0000… # SubmitSharesExtended
/// ```
///
/// A `#` line opens each connection, so a capture that spans a reconnect
/// says where the second session's job ids and sequence numbers start again.
///
/// **What it holds, stated because it is committed as a fixture.** Nothing
/// from the handshake — the ephemeral keys and the certificate are not
/// frames and never reach this file — and nothing secret. The `send` lines
/// are this client's own and are there for one reason: rebuilding a share
/// needs what was submitted. A parser test reads only the `recv` lines,
/// because every message this client sends is already asserted
/// byte-identical to SRI's encoder.
///
/// Shared between the read half and the write half, which run on different
/// threads; each line is one write under the lock, so lines never interleave.
#[derive(Clone, Debug)]
pub struct Capture(Arc<Mutex<File>>);

impl Capture {
    /// Open `path` for appending, creating it if it is not there.
    ///
    /// Appending rather than truncating, because a run reconnects and a
    /// capture that started again at every session would keep only the last.
    pub fn open(path: &str) -> Result<Self, String> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(|file| Self(Arc::new(Mutex::new(file))))
            .map_err(|error| format!("could not open MINER_POOL_CAPTURE {path}: {error}"))
    }

    /// A `#` line, for what is not a frame.
    fn note(&self, text: &str) -> Result<(), String> {
        self.line(format!("# {text}\n"))
    }

    /// One frame, `recv` or `send`.
    fn frame(&self, direction: &str, header: Header, payload: &[u8]) -> Result<(), String> {
        let mut hex = String::with_capacity(2 * (HEADER_LEN + payload.len()));
        for byte in header.to_bytes().iter().chain(payload) {
            hex.push_str(&format!("{byte:02x}"));
        }
        self.line(format!("{direction} {hex} # {}\n", frame::name(header)))
    }

    fn line(&self, line: String) -> Result<(), String> {
        let mut file = self.0.lock().map_err(|_| "the capture file is poisoned")?;
        file.write_all(line.as_bytes())
            .map_err(|error| format!("could not write to MINER_POOL_CAPTURE: {error}"))
    }
}

/// How long to wait for the TCP handshake before giving up on an address.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the Noise handshake may take once the socket is open.
///
/// The pool owes an answer at that point, so silence is a dead socket rather
/// than a quiet pool. Short, because nothing useful is happening yet.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Open a connection and complete the Noise handshake on it.
///
/// Returns the two halves, because the write half has to take the outgoing
/// cipher state with it and a cipher state cannot be copied.
pub fn connect(
    address: &str,
    authority: Option<XOnlyPublicKey>,
    now: u32,
    capture: Option<Capture>,
) -> Result<(Conn, Writer), String> {
    let resolved: Vec<_> = address
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve the pool address {address}: {error}"))?
        .collect();
    if resolved.is_empty() {
        return Err(format!("the pool address {address} resolved to nothing"));
    }

    let mut last = String::new();
    for candidate in &resolved {
        let stream = match TcpStream::connect_timeout(candidate, CONNECT_TIMEOUT) {
            Ok(stream) => stream,
            Err(error) => {
                last = format!("{candidate}: {error}");
                continue;
            }
        };

        // Nagle batches small writes, and every frame this client sends is a
        // small write the pool is waiting on. Same reason as V1's.
        stream
            .set_nodelay(true)
            .map_err(|error| format!("could not disable Nagle: {error}"))?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("could not set a read timeout: {error}"))?;

        let peer = format!("{candidate}");
        return handshake(stream, peer, authority, now, capture);
    }

    Err(format!(
        "could not connect to the pool at {address} ({} address{}): {last}",
        resolved.len(),
        if resolved.len() == 1 { "" } else { "es" }
    ))
}

/// `-> e` then `<- e, ee, s, es`, and the certificate check in between.
fn handshake(
    mut stream: TcpStream,
    peer: String,
    authority: Option<XOnlyPublicKey>,
    now: u32,
    capture: Option<Capture>,
) -> Result<(Conn, Writer), String> {
    let (handshake, first) = Handshake::start()?;
    stream
        .write_all(&first)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("could not send the Noise handshake to {peer}: {error}"))?;

    let mut second = [0u8; PART_2_LEN];
    stream.read_exact(&mut second).map_err(|error| {
        format!(
            "the pool at {peer} did not answer the Noise handshake with {PART_2_LEN} bytes: \
             {error}. A pool speaking Stratum V1 on this port would be waiting for JSON, \
             which is what MINER_POOL_PROTOCOL is for"
        )
    })?;

    let (outgoing, incoming) = handshake.finish(&second, authority, now)?;

    let write_half = stream
        .try_clone()
        .map_err(|error| format!("could not clone the pool socket: {error}"))?;

    // Only once the handshake has completed, so a capture never opens a
    // session that did not happen.
    if let Some(capture) = &capture {
        capture.note(&format!("connected to {peer} at {now}"))?;
    }

    Ok((
        Conn {
            stream,
            incoming,
            peer,
            partial: Vec::with_capacity(ENCRYPTED_HEADER_LEN),
            want: ENCRYPTED_HEADER_LEN,
            header: None,
            capture: capture.clone(),
        },
        Writer {
            half: Mutex::new(WriteHalf {
                stream: write_half,
                cipher: outgoing,
                capture,
            }),
        },
    ))
}

/// The read half: the socket, the incoming cipher state, and a partly-read
/// frame.
#[derive(Debug)]
pub struct Conn {
    stream: TcpStream,
    incoming: CipherState,
    peer: String,
    /// What has been read of the current stage, header or payload.
    partial: Vec<u8>,
    /// How many bytes that stage needs in total.
    want: usize,
    /// The decrypted header, once there is one, which is what says how long
    /// the payload is.
    header: Option<Header>,
    capture: Option<Capture>,
}

impl Conn {
    /// Which address this connection actually reached, for the log.
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Bound how long the next read blocks.
    pub fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), String> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("could not set a read timeout: {error}"))
    }

    /// Read one message, blocking until it arrives.
    pub fn read(&mut self) -> Result<Incoming, String> {
        loop {
            if let Some(message) = self.read_timed()? {
                return Ok(message);
            }
        }
    }

    /// Read one message, reporting "nothing more yet" as `None`.
    ///
    /// **Never loses a partly-read frame.** The socket's timeout can fire in
    /// the middle of a header or a payload, and there is no way to put those
    /// bytes back — a Noise stream has no resynchronisation point. So what
    /// has been read stays in `self.partial` and the next call carries on
    /// from there.
    pub fn read_timed(&mut self) -> Result<Option<Incoming>, String> {
        loop {
            if !self.fill()? {
                return Ok(None);
            }

            match self.header {
                None => {
                    let header = self.take_header()?;
                    if header.length == 0 {
                        // A message with no payload — none of the ones this
                        // client handles, but a well-formed frame. Nothing
                        // more is read for it.
                        self.reset();
                        self.record(header, &[])?;
                        return Incoming::parse(header, &[]).map(Some);
                    }
                    self.header = Some(header);
                    self.want = ct_len(header.length as usize);
                    self.partial.clear();
                }
                Some(header) => {
                    let payload = self.take_payload(header)?;
                    self.reset();
                    self.record(header, &payload)?;
                    return Incoming::parse(header, &payload).map(Some);
                }
            }
        }
    }

    /// Read towards `want`. `false` means the socket had nothing more to give
    /// right now.
    fn fill(&mut self) -> Result<bool, String> {
        while self.partial.len() < self.want {
            let need = self.want - self.partial.len();
            let at = self.partial.len();
            self.partial.resize(self.want, 0);

            match self.stream.read(&mut self.partial[at..at + need]) {
                Ok(0) => {
                    self.partial.truncate(at);
                    return Err("the pool closed the connection".into());
                }
                Ok(read) => self.partial.truncate(at + read),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    self.partial.truncate(at);
                    return Ok(false);
                }
                Err(error) => {
                    self.partial.truncate(at);
                    return Err(format!("could not read from the pool: {error}"));
                }
            }
        }
        Ok(true)
    }

    fn take_header(&mut self) -> Result<Header, String> {
        let plaintext = self.incoming.decrypt_with_ad(&[], &self.partial)?;
        let bytes: [u8; HEADER_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| format!("a frame header decrypted to {} bytes", plaintext.len()))?;
        Header::parse(bytes)
    }

    /// Decrypt the payload, one Noise chunk at a time.
    ///
    /// **The chunk boundaries are on the ciphertext**, not the plaintext:
    /// every chunk but the last is exactly `MAX_CT_CHUNK` bytes on the wire
    /// and decrypts to `MAX_PT_CHUNK`. Reconstructing them from the plaintext
    /// length would work too and would be a second way to compute the same
    /// thing, which is a second thing to get wrong.
    fn take_payload(&mut self, header: Header) -> Result<Vec<u8>, String> {
        let mut payload = Vec::with_capacity(header.length as usize);
        for chunk in self.partial.chunks(MAX_CT_CHUNK) {
            payload.extend_from_slice(&self.incoming.decrypt_with_ad(&[], chunk)?);
        }

        if payload.len() != header.length as usize {
            return Err(format!(
                "the pool's frame header announced a {}-byte payload and it decrypted to {}",
                header.length,
                payload.len()
            ));
        }
        Ok(payload)
    }

    /// Write one decrypted frame to the capture, if there is one.
    ///
    /// **Called between the tag and the parser, and nowhere else.** A frame
    /// that failed to authenticate never gets here; a frame `messages.rs`
    /// cannot parse already has.
    fn record(&self, header: Header, payload: &[u8]) -> Result<(), String> {
        match &self.capture {
            Some(capture) => capture.frame("recv", header, payload),
            None => Ok(()),
        }
    }

    fn reset(&mut self) {
        self.partial.clear();
        self.want = ENCRYPTED_HEADER_LEN;
        self.header = None;
    }
}

/// The write half, usable from another thread.
///
/// `&self` throughout, because the grinding thread's share callback has only
/// a shared borrow to give it — and the mutex is not an optimisation to be
/// removed later, it is what keeps the nonce counter and the byte order on
/// the socket in step. See this module's header.
#[derive(Debug)]
pub struct Writer {
    half: Mutex<WriteHalf>,
}

#[derive(Debug)]
struct WriteHalf {
    stream: TcpStream,
    cipher: CipherState,
    capture: Option<Capture>,
}

impl Writer {
    /// Encrypt one frame and put it on the socket.
    ///
    /// Header and payload are separate AEAD messages consuming consecutive
    /// nonces, and both are written with one `write_all` so that
    /// nothing can interleave between them.
    pub fn send(&self, frame: &Outgoing) -> Result<(), String> {
        let mut half = self
            .half
            .lock()
            .map_err(|_| "the pool writer is poisoned")?;
        let WriteHalf {
            stream,
            cipher,
            capture,
        } = &mut *half;

        let mut out = Vec::with_capacity(ENCRYPTED_HEADER_LEN + ct_len(frame.payload.len()));
        out.extend_from_slice(&cipher.encrypt_with_ad(&[], &frame.header.to_bytes())?);
        for chunk in frame.payload.chunks(MAX_PT_CHUNK) {
            out.extend_from_slice(&cipher.encrypt_with_ad(&[], chunk)?);
        }
        debug_assert_eq!(
            out.len(),
            ENCRYPTED_HEADER_LEN + ct_len(frame.payload.len()),
            "the frame this client wrote is not the length its own arithmetic predicts"
        );

        stream
            .write_all(&out)
            .and_then(|()| stream.flush())
            .map_err(|error| format!("could not write to the pool: {error}"))?;

        // Inside the lock, so the capture's order is the socket's.
        match capture {
            Some(capture) => capture.frame("send", frame.header, &frame.payload),
            None => Ok(()),
        }
    }
}

/// How many ciphertext bytes one plaintext payload becomes, MACs included.
///
/// Re-exported from [`frame`] through this module's own name so that callers
/// reasoning about the socket do not have to reach past it.
pub fn wire_len(payload: usize) -> usize {
    ENCRYPTED_HEADER_LEN + ct_len(payload)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
        thread,
    };

    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    use super::{
        super::{
            frame::{CHANNEL_MSG, MAC_LEN},
            messages,
        },
        *,
    };

    /// A pool that completes the handshake with `noise_sv2` and then speaks
    /// the framing under test.
    ///
    /// Half of an independent implementation and half of this one, which is
    /// the only arrangement available: `noise_sv2` produces the session keys
    /// and its own `NoiseEngine` does the AEAD, but the **framing** on top —
    /// the separate 22-byte header, the chunking, the plaintext length in an
    /// encrypted header — is `codec_sv2`'s rather than `noise_sv2`'s and is
    /// not pulled in here. So the frames this fixture writes are built from
    /// the spec's §4.6 description directly, which at least means they are
    /// written twice, from the spec, in two places that do not share code.
    struct Pool {
        stream: TcpStream,
        engine: noise_sv2::NoiseEngine,
    }

    impl Pool {
        /// Listen, complete a handshake, and hand back the client's halves
        /// alongside the pool's own end.
        fn start() -> (Self, Conn, Writer, XOnlyPublicKey) {
            Self::start_capturing(None)
        }

        /// The same, with the client writing a `MINER_POOL_CAPTURE`.
        fn start_capturing(capture: Option<Capture>) -> (Self, Conn, Writer, XOnlyPublicKey) {
            let secp = Secp256k1::new();
            let secret = SecretKey::from_slice(&[13u8; 32]).unwrap();
            let authority = Keypair::from_secret_key(&secp, &secret);
            let pinned = authority.x_only_public_key().0;

            let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
            let address = listener.local_addr().expect("its address").to_string();

            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("the client connects");
                let mut responder = noise_sv2::Responder::from_authority_kp(
                    &pinned.serialize(),
                    &secret.secret_bytes(),
                    Duration::from_secs(3600),
                )
                .expect("the responder takes its keypair");

                let mut first = [0u8; 64];
                stream
                    .read_exact(&mut first)
                    .expect("the client's ephemeral key");
                let (second, engine) = responder.step_1(first).expect("the handshake");
                stream.write_all(&second).expect("the answer");
                Pool { stream, engine }
            });

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            let (conn, writer) =
                connect(&address, Some(pinned), now, capture).expect("the client connects");
            (
                server.join().expect("the pool thread"),
                conn,
                writer,
                pinned,
            )
        }

        /// Write one frame the way §4.6 describes it.
        fn send(&mut self, header: Header, payload: &[u8]) {
            let mut sealed = header.to_bytes().to_vec();
            self.engine.encrypt(&mut sealed).expect("the header");
            self.stream.write_all(&sealed).expect("the header goes out");

            for chunk in payload.chunks(MAX_PT_CHUNK) {
                let mut sealed = chunk.to_vec();
                self.engine.encrypt(&mut sealed).expect("a payload chunk");
                self.stream.write_all(&sealed).expect("the chunk goes out");
            }
            self.stream.flush().expect("flushed");
        }

        /// Read one frame the same way.
        fn recv(&mut self) -> (Header, Vec<u8>) {
            let mut sealed = vec![0u8; ENCRYPTED_HEADER_LEN];
            self.stream.read_exact(&mut sealed).expect("a header");
            self.engine.decrypt(&mut sealed).expect("it decrypts");
            let header = Header::parse(sealed.as_slice().try_into().unwrap()).expect("a header");

            let mut payload = Vec::new();
            let mut remaining = header.length as usize;
            while remaining > 0 {
                let plain = remaining.min(MAX_PT_CHUNK);
                let mut sealed = vec![0u8; plain + MAC_LEN];
                self.stream.read_exact(&mut sealed).expect("a chunk");
                self.engine.decrypt(&mut sealed).expect("it decrypts");
                payload.extend_from_slice(&sealed);
                remaining -= plain;
            }
            (header, payload)
        }
    }

    #[test]
    fn a_session_carries_real_frames_both_ways_over_the_tunnel() {
        let (mut pool, mut conn, writer, _) = Pool::start();

        // Out: the two frames a session opens with, read back at the far end
        // and checked against what this client meant to send.
        let setup = messages::setup_connection("host", 3350, "PuntoMiner/0.1").unwrap();
        writer.send(&setup).expect("the setup goes out");
        let (header, payload) = pool.recv();
        assert_eq!(header, setup.header);
        assert_eq!(payload, setup.payload);

        let open =
            messages::open_extended_mining_channel(1, "worker", 430e6, &[0x7f; 32], 8).unwrap();
        writer.send(&open).expect("the channel open goes out");
        let (header, payload) = pool.recv();
        assert_eq!(header, open.header);
        assert_eq!(payload, open.payload);

        // In: a `SetTarget`, which is the smallest channel message, parsed
        // all the way through to an `Incoming`.
        let mut target = [0u8; 32];
        target[28] = 0xff;
        target[29] = 0xff;
        let mut body = 42u32.to_le_bytes().to_vec();
        body.extend_from_slice(&target);
        pool.send(
            Header::new(CHANNEL_MSG, super::super::frame::msg::SET_TARGET, 36),
            &body,
        );

        assert_eq!(
            conn.read().expect("a frame arrives"),
            messages::Incoming::SetTarget {
                channel_id: 42,
                maximum_target: target,
            },
        );
    }

    #[test]
    fn a_payload_past_one_noise_chunk_is_split_and_rejoined() {
        // **The case `pt_len + 16` would get wrong**, and the reason `ct_len`
        // exists: a payload of more than 65,519 bytes is two AEAD messages,
        // two MACs and two nonces, and the header still announces the
        // plaintext length.
        let (mut pool, mut conn, writer, _) = Pool::start();

        for size in [MAX_PT_CHUNK - 1, MAX_PT_CHUNK, MAX_PT_CHUNK + 1] {
            // Out, using a real message so the length is not invented: a
            // coinbase prefix long enough to push the frame past a chunk.
            let payload = vec![0x5au8; size];
            let frame = Outgoing {
                header: Header::new(CHANNEL_MSG, 0x7f, size as u32),
                payload: payload.clone(),
            };
            writer.send(&frame).expect("a long frame goes out");
            let (header, received) = pool.recv();
            assert_eq!(header.length as usize, size, "the plaintext length");
            assert_eq!(received, payload);

            // In, the same size, and it comes back as an `Unknown` because
            // `0x7f` is not a message — which is exactly right: the framing
            // worked and the message did not exist.
            pool.send(Header::new(CHANNEL_MSG, 0x7f, size as u32), &payload);
            assert!(matches!(
                conn.read().expect("a long frame arrives"),
                messages::Incoming::Unknown { msg_type: 0x7f, .. }
            ));
        }
    }

    #[test]
    fn a_frame_that_arrives_in_pieces_is_not_lost_between_polls() {
        // The property that makes `read_timed` safe to call in a loop: a
        // Noise stream cannot be resynchronised, so a reader that dropped
        // nine bytes of a header would end the session.
        let (mut pool, mut conn, _writer, _) = Pool::start();
        conn.set_read_timeout(Duration::from_millis(20)).unwrap();

        let mut target = [0u8; 32];
        target[28] = 0xff;
        let mut body = 42u32.to_le_bytes().to_vec();
        body.extend_from_slice(&target);

        let mut sealed = Header::new(CHANNEL_MSG, super::super::frame::msg::SET_TARGET, 36)
            .to_bytes()
            .to_vec();
        pool.engine.encrypt(&mut sealed).unwrap();
        let mut sealed_body = body.clone();
        pool.engine.encrypt(&mut sealed_body).unwrap();
        sealed.extend_from_slice(&sealed_body);

        // One byte at a time, with a poll between each, which is the worst
        // case a real socket can produce.
        for byte in &sealed[..sealed.len() - 1] {
            pool.stream.write_all(&[*byte]).unwrap();
            pool.stream.flush().unwrap();
            assert!(
                conn.read_timed()
                    .expect("a partial frame is not an error")
                    .is_none(),
                "nothing is complete yet"
            );
        }

        pool.stream.write_all(&sealed[sealed.len() - 1..]).unwrap();
        pool.stream.flush().unwrap();
        assert!(matches!(
            conn.read().expect("the last byte completes it"),
            messages::Incoming::SetTarget { channel_id: 42, .. }
        ));
    }

    #[test]
    fn a_pool_that_hangs_up_says_so_rather_than_looping() {
        let (pool, mut conn, _writer, _) = Pool::start();
        drop(pool);

        let why = conn.read().expect_err("the far end is gone");
        assert!(why.contains("closed the connection"), "{why}");
    }

    #[test]
    fn a_tampered_frame_ends_the_session_rather_than_being_skipped() {
        // There is no recovery from a MAC failure on a Noise stream, and
        // pretending otherwise would mean carrying on with a counter that no
        // longer matches the far end's.
        let (mut pool, mut conn, _writer, _) = Pool::start();

        let mut sealed = Header::new(CHANNEL_MSG, super::super::frame::msg::SET_TARGET, 36)
            .to_bytes()
            .to_vec();
        pool.engine.encrypt(&mut sealed).unwrap();
        sealed[3] ^= 1;
        pool.stream.write_all(&sealed).unwrap();
        pool.stream.flush().unwrap();

        let why = conn.read().expect_err("the header does not authenticate");
        assert!(why.contains("did not authenticate"), "{why}");
    }

    #[test]
    fn a_handshake_against_the_wrong_authority_key_never_reaches_the_framing() {
        // The gate that makes the rest of this file worth having. The socket
        // opens, the ECDHs agree, and the session is still refused.
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[13u8; 32]).unwrap();
        let authority = Keypair::from_secret_key(&secp, &secret);
        let pinned = authority.x_only_public_key().0;

        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("its address").to_string();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("the client connects");
            let mut responder = noise_sv2::Responder::from_authority_kp(
                &pinned.serialize(),
                &secret.secret_bytes(),
                Duration::from_secs(3600),
            )
            .unwrap();
            let mut first = [0u8; 64];
            stream.read_exact(&mut first).unwrap();
            let (second, _) = responder.step_1(first).unwrap();
            let _ = stream.write_all(&second);
        });

        let somebody_else =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[14u8; 32]).unwrap())
                .x_only_public_key()
                .0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let why = connect(&address, Some(somebody_else), now, None)
            .expect_err("the certificate is signed by an authority this run did not pin");
        assert!(why.contains("pinned"), "{why}");
        let _ = server.join();
    }

    /// A capture file under the system's temp directory, unique to the test.
    fn capture_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "puntominer-capture-{}-{name}.hex",
            std::process::id()
        ))
    }

    #[test]
    fn the_capture_sits_after_the_tag_and_before_the_parser() {
        // **The position the whole fixture depends on.** Three frames, one
        // for each side of each boundary: one that authenticates and parses,
        // one that authenticates and does *not* parse, which must be
        // recorded anyway, and one that does not authenticate, which must
        // not be.
        let path = capture_path("position");
        let _ = std::fs::remove_file(&path);
        let capture = Capture::open(path.to_str().unwrap()).expect("the capture opens");
        let (mut pool, mut conn, writer, _) = Pool::start_capturing(Some(capture));

        let setup = messages::setup_connection("host", 3350, "PuntoMiner/0.1").unwrap();
        writer.send(&setup).expect("the setup goes out");
        pool.recv();

        let mut target = [0u8; 32];
        target[28] = 0xff;
        let mut good = 42u32.to_le_bytes().to_vec();
        good.extend_from_slice(&target);
        let set_target = Header::new(CHANNEL_MSG, super::super::frame::msg::SET_TARGET, 36);
        pool.send(set_target, &good);
        conn.read().expect("a SetTarget parses");

        // Three bytes where 36 belong: authenticated, and wrong.
        let short = Header::new(CHANNEL_MSG, super::super::frame::msg::SET_TARGET, 3);
        pool.send(short, &[1, 2, 3]);
        conn.read()
            .expect_err("a three-byte SetTarget does not parse");

        // And one that fails its tag. The session is over after this, which
        // is the point; the capture must not have it.
        let mut sealed = set_target.to_bytes().to_vec();
        pool.engine.encrypt(&mut sealed).unwrap();
        sealed[3] ^= 1;
        pool.stream.write_all(&sealed).unwrap();
        pool.stream.flush().unwrap();
        conn.read().expect_err("a tampered header");

        let text = std::fs::read_to_string(&path).expect("the capture reads back");
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = text.lines().collect();

        let hex = |header: Header, payload: &[u8]| -> String {
            header
                .to_bytes()
                .iter()
                .chain(payload)
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };
        assert_eq!(lines.len(), 4, "{text}");
        assert!(lines[0].starts_with("# connected to 127.0.0.1:"), "{text}");
        assert_eq!(
            lines[1],
            format!(
                "send {} # SetupConnection",
                hex(setup.header, &setup.payload)
            )
        );
        assert_eq!(
            lines[2],
            format!("recv {} # SetTarget", hex(set_target, &good))
        );
        assert_eq!(
            lines[3],
            format!("recv {} # SetTarget", hex(short, &[1, 2, 3]))
        );
    }

    #[test]
    fn the_wire_length_is_the_header_plus_the_payloads_ciphertext() {
        assert_eq!(wire_len(0), 22, "a header and no payload");
        assert_eq!(wire_len(36), 22 + 52, "a SetTarget");
        assert_eq!(wire_len(MAX_PT_CHUNK), 22 + MAX_CT_CHUNK);
        assert_eq!(wire_len(MAX_PT_CHUNK + 1), 22 + MAX_CT_CHUNK + 1 + MAC_LEN);
    }
}
