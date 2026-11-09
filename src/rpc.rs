//! Minimal JSON-RPC client for a local Bitcoin Core node.
//!
//! Mining needs live calls (`getblocktemplate`, `submitblock`), so this speaks
//! HTTP/1.1 to a node on the loopback interface and nothing more, rather than
//! adding an HTTP client dependency. Authentication is the datadir
//! cookie, never a configured password, so no credential is ever read from or
//! written to this repository.

use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use serde_json::{Value, json};

use crate::constants::RPC_TIMEOUT_SECONDS;

/// Networks this client knows how to reach, with the RPC port and datadir
/// subdirectory Bitcoin Core uses for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Main,
    Testnet4,
    Signet,
    Regtest,
}

impl Chain {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "main" | "mainnet" => Ok(Self::Main),
            "testnet4" => Ok(Self::Testnet4),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(format!(
                "MINER_CHAIN must be main, testnet4, signet or regtest, got {value}"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// Default RPC port for the chain.
    pub fn rpc_port(self) -> u16 {
        match self {
            Self::Main => 8332,
            Self::Testnet4 => 48332,
            Self::Signet => 38332,
            Self::Regtest => 18443,
        }
    }

    /// Subdirectory of the datadir holding this chain's state, empty for
    /// mainnet, which lives in the datadir root.
    pub fn datadir_subdir(self) -> &'static str {
        match self {
            Self::Main => "",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// The compact target a min-difficulty block carries, for the chains that
    /// have such a rule.
    ///
    /// Testnet4 keeps testnet3's exception: twenty minutes without a block and
    /// the next one may be mined at the proof-of-work limit, difficulty 1. That
    /// is 2^32 expected hashes — ten seconds of the GPU — and it is the only
    /// circumstance in which this hardware can win a block on a public network.
    ///
    /// The value is the chain's `powLimit`, so comparing a template's `bits`
    /// against it is exact rather than a guess about how much easier is easy
    /// enough. `None` for the chains where the question does not arise: mainnet
    /// has no such rule, signet's difficulty is set by its challenge, and every
    /// regtest block is already at the limit.
    pub fn min_difficulty_bits(self) -> Option<bitcoin::CompactTarget> {
        match self {
            Self::Testnet4 => Some(bitcoin::CompactTarget::from_consensus(0x1d00_ffff)),
            Self::Main | Self::Signet | Self::Regtest => None,
        }
    }

    /// Blocks between subsidy halvings. Regtest halves every 150 blocks, which
    /// is why a regtest chain a few hundred blocks long is already several
    /// halvings in and its coinbase value is nothing like 50 BTC.
    pub fn halving_interval(self) -> i64 {
        match self {
            Self::Main | Self::Testnet4 | Self::Signet => 210_000,
            Self::Regtest => 150,
        }
    }

    /// The address form a payout for this chain must decode to.
    pub fn network(self) -> bitcoin::Network {
        match self {
            Self::Main => bitcoin::Network::Bitcoin,
            Self::Testnet4 => bitcoin::Network::Testnet4,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }
}

/// A JSON-RPC connection to one node.
///
/// Each call opens a connection and closes it, which costs a loopback
/// handshake per request. That is irrelevant next to the hashing, and it keeps
/// the client to one short function with no connection state to get wrong.
///
/// Holding no connection is also what makes this cheap to clone, which the
/// longpoll watcher needs: it keeps a call open for a minute at a time, and a
/// shared client would block every other call behind it.
#[derive(Clone)]
pub struct Rpc {
    chain: Chain,
    address: String,
    authorization: String,
}

impl Rpc {
    /// Connect using the cookie Bitcoin Core wrote into the chain's datadir.
    pub fn new(chain: Chain, datadir: &str) -> Result<Self, String> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok();
        let datadir = expand_home(datadir, home.as_deref());
        let subdir = chain.datadir_subdir();
        let cookie_path = if subdir.is_empty() {
            format!("{datadir}/.cookie")
        } else {
            format!("{datadir}/{subdir}/.cookie")
        };

        let cookie = fs::read_to_string(&cookie_path).map_err(|error| {
            format!(
                "could not read {cookie_path}: {error} (is the {} node running?)",
                chain.name()
            )
        })?;

        Ok(Self {
            chain,
            address: format!("127.0.0.1:{}", chain.rpc_port()),
            authorization: base64(cookie.trim().as_bytes()),
        })
    }

    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// Issue a JSON-RPC call against the node itself.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        self.request(
            "/",
            method,
            params,
            Duration::from_secs(RPC_TIMEOUT_SECONDS),
        )
    }

    /// Issue a call the node is expected to hold open.
    ///
    /// Only `getblocktemplate` with a `longpollid` does this: the node answers
    /// when there is better work, which can be a minute away. The default
    /// timeout would read that as a dead node.
    pub fn call_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.request("/", method, params, timeout)
    }

    /// Issue a JSON-RPC call against a loaded wallet.
    pub fn wallet_call(&self, wallet: &str, method: &str, params: Value) -> Result<Value, String> {
        self.request(
            &format!("/wallet/{wallet}"),
            method,
            params,
            Duration::from_secs(RPC_TIMEOUT_SECONDS),
        )
    }

    fn request(
        &self,
        path: &str,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "bitcoin-in-depth",
            "method": method,
            "params": params,
        })
        .to_string();

        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Authorization: Basic {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            self.authorization,
            body.len()
        );

        let mut stream = TcpStream::connect(&self.address)
            .map_err(|error| format!("could not connect to {}: {error}", self.address))?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|error| format!("could not set RPC timeouts: {error}"))?;

        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("could not send {method}: {error}"))?;

        // `Connection: close` makes end-of-stream the end of the response, so
        // neither Content-Length nor chunked encoding has to be parsed.
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| format!("could not read the {method} response: {error}"))?;

        let response = String::from_utf8_lossy(&response);
        let (head, body) = response
            .split_once("\r\n\r\n")
            .ok_or_else(|| format!("malformed HTTP response to {method}"))?;

        let parsed: Value = serde_json::from_str(body.trim()).map_err(|error| {
            let status = head.lines().next().unwrap_or("no status line");
            format!("{method} returned no JSON ({status}): {error}")
        })?;

        // A node-level error arrives with an HTTP 500 and a populated `error`
        // object; the code and message are what make a rejection debuggable, so
        // both are carried through.
        match parsed.get("error") {
            Some(Value::Null) | None => (),
            Some(error) => {
                let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no message");
                return Err(format!("{method} failed ({code}): {message}"));
            }
        }

        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method} returned no result field"))
    }
}

/// Standard base64, for the HTTP Basic authorization header.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let value = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        for index in 0..4 {
            if index <= chunk.len() {
                let position = (value >> (18 - index * 6)) & 0x3f;
                encoded.push(ALPHABET[position as usize] as char);
            } else {
                encoded.push('=');
            }
        }
    }
    encoded
}

/// Expand a leading `~` in a datadir to the home directory.
///
/// A shell expands `~` on a command line, but not in a config file, an
/// environment variable set with quotes, or the compiled-in default — and a
/// literal `~` would be read as a directory of that name under the working
/// directory. Only `~` alone and `~/...` are expanded; `~user` is left as
/// written, as is everything when no home directory is known.
fn expand_home(path: &str, home: Option<&str>) -> String {
    match (path.strip_prefix('~'), home) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            format!("{home}{rest}")
        }
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leading_tilde_expands_to_the_home_directory() {
        let home = Some("/home/miner");
        assert_eq!(expand_home("~/.bitcoin", home), "/home/miner/.bitcoin");
        assert_eq!(expand_home("~", home), "/home/miner");
        assert_eq!(expand_home("/srv/bitcoin", home), "/srv/bitcoin");
        assert_eq!(expand_home("data/~/x", home), "data/~/x");
        assert_eq!(expand_home("~other/.bitcoin", home), "~other/.bitcoin");
        assert_eq!(expand_home("~/.bitcoin", None), "~/.bitcoin");
    }

    #[test]
    fn base64_matches_the_known_vectors() {
        // RFC 4648 section 10, which covers all three padding cases.
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_encodes_a_cookie_shaped_credential() {
        assert_eq!(base64(b"__cookie__:secret"), "X19jb29raWVfXzpzZWNyZXQ=");
    }

    #[test]
    fn only_testnet4_eases_its_difficulty() {
        let eased = Chain::Testnet4
            .min_difficulty_bits()
            .expect("testnet4 keeps the twenty-minute exception");
        assert_eq!(eased.to_consensus(), 0x1d00_ffff);

        // The whole point of the rule: the eased target is difficulty 1, which
        // is 2^32 expected hashes and about ten seconds of the GPU.
        assert_eq!(bitcoin::Target::from_compact(eased).difficulty_float(), 1.0);

        for chain in [Chain::Main, Chain::Signet, Chain::Regtest] {
            assert!(
                chain.min_difficulty_bits().is_none(),
                "{} has no min-difficulty rule to detect",
                chain.name()
            );
        }
    }

    #[test]
    fn chains_carry_their_ports_and_subdirectories() {
        assert_eq!(Chain::parse("regtest").unwrap().rpc_port(), 18443);
        assert_eq!(Chain::parse("main").unwrap().datadir_subdir(), "");
        assert_eq!(
            Chain::parse("testnet4").unwrap().datadir_subdir(),
            "testnet4"
        );
        assert!(Chain::parse("testnet3").is_err());
    }
}
