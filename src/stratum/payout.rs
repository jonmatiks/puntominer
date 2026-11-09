//! Who a pool's coinbase pays, reported and never enforced.
//!
//! **The one thing either client reads in a coinbase it otherwise only
//! splices.** Against a solo pool, the whole value of a found block is the
//! output that pays `MINER_POOL_USER`, and a pool that paid itself instead
//! would be indistinguishable from an honest one until the block was found.
//! So both clients decode the coinbase they were handed, name its outputs in
//! the log, and warn when none of them pays the address the worker name
//! carries.
//!
//! **A warning, not a refusal.** On a pooled (PPLNS or FPPS) pool the coinbase
//! legitimately pays the pool, and the warning says so. Nothing else in the
//! coinbase is checked: the pool is still the authority on everything except
//! the proof of work, and there is still no share equivalent of
//! `check_block`.
//!
//! **Scripts are compared, not strings**, so no network has to be assumed —
//! the same bytes are the same payee whichever chain the pool is on.

use std::str::FromStr;

use bitcoin::{
    Address, Network, ScriptBuf, Transaction, address::NetworkUnchecked, consensus::deserialize,
};

use crate::block::Extranonce;

/// The extranonce the coinbase is decoded under.
///
/// Any would do: the extranonce sits in the scriptSig, and the outputs are the
/// same bytes whichever one fills it.
pub const DECODED_AT: Extranonce = Extranonce::ZERO;

/// The payout check for one run: the payee, and what the log last said.
#[derive(Debug)]
pub struct Payout {
    user: String,
    /// The script `MINER_POOL_USER`'s address pays to, or `None` when the
    /// username is not an address — which is normal for an account-based pool.
    payee: Option<ScriptBuf>,
    /// The network the username's address is valid on, used only to spell the
    /// other outputs as addresses in the log.
    network: Option<Network>,
    /// The scripts the last coinbase paid, or why it did not decode.
    ///
    /// **Scripts, not amounts, and no `OP_RETURN`.** The value moves with the
    /// fees on nearly every template, and so does the witness commitment's
    /// `OP_RETURN`, so either would make a line on every notify. Who is paid
    /// is what this is watching, and an `OP_RETURN` pays nobody.
    last: Option<Result<Vec<ScriptBuf>, String>>,
}

impl Payout {
    /// The check for `user`, read as `<address>` or `<address>.<worker>`.
    pub fn new(user: &str) -> Self {
        let address = user.split('.').next().unwrap_or_default();
        let parsed = Address::<NetworkUnchecked>::from_str(address).ok();
        let network = parsed.as_ref().and_then(|address| {
            [Network::Bitcoin, Network::Testnet, Network::Regtest]
                .into_iter()
                .find(|network| address.is_valid_for_network(*network))
        });
        Self {
            user: user.to_string(),
            payee: parsed.map(|address| address.assume_checked().script_pubkey()),
            network,
            last: None,
        }
    }

    /// The lines to log for one job's coinbase, and none when nothing changed.
    pub fn check(&mut self, coinbase: &[u8]) -> Vec<String> {
        let decoded = deserialize::<Transaction>(coinbase)
            .map_err(|why| why.to_string())
            .map(|tx| tx.output);
        let scripts = decoded.as_ref().map(|outputs| {
            outputs
                .iter()
                .filter(|output| !output.script_pubkey.is_op_return())
                .map(|output| output.script_pubkey.clone())
                .collect::<Vec<_>>()
        });
        let scripts = scripts.map_err(Clone::clone);
        if self.last.as_ref() == Some(&scripts) {
            return Vec::new();
        }
        let first = self.last.is_none();
        self.last = Some(scripts);

        let mut lines = Vec::new();
        if first && self.payee.is_none() {
            lines.push(format!(
                "MINER_POOL_USER {} is not an address, so the coinbase payout is reported and \
                 not checked; that is normal for an account-based pool",
                self.user
            ));
        }

        let outputs = match decoded {
            Ok(outputs) => outputs,
            Err(why) => {
                lines.push(format!(
                    "the pool's coinbase does not decode as a transaction, so its payout \
                     cannot be reported: {why}"
                ));
                return lines;
            }
        };

        let paid = outputs
            .iter()
            .map(|output| {
                let ours = self.payee.as_ref() == Some(&output.script_pubkey);
                format!(
                    "{} to {}{}",
                    output.value,
                    self.describe(&output.script_pubkey),
                    if ours { " (MINER_POOL_USER)" } else { "" },
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("the coinbase pays {paid}"));

        if let Some(payee) = &self.payee
            && !outputs.iter().any(|output| &output.script_pubkey == payee)
        {
            lines.push(format!(
                "WARNING: the coinbase pays nothing to {}, the address in MINER_POOL_USER. \
                 Against a solo pool a block found here pays someone else; against a pooled \
                 (PPLNS or FPPS) pool the coinbase paying the pool is normal and this can be \
                 ignored",
                self.describe(payee),
            ));
        }
        lines
    }

    /// An output's script as an address when it is one, and as hex when not.
    fn describe(&self, script: &ScriptBuf) -> String {
        if script.is_op_return() {
            return "OP_RETURN".into();
        }
        self.network
            .and_then(|network| Address::from_script(script, network).ok())
            .map(|address| address.to_string())
            .unwrap_or_else(|| format!("script {}", script.to_hex_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            fixture,
            job::{Job, ShareTarget},
            messages::{Incoming, Subscribed},
        },
        *,
    };
    use crate::constants::MINER_ADDRESS;

    /// The first job of the Pool A capture.
    fn captured_job() -> Job {
        let frames = fixture::load(fixture::POOL_A);
        let subscribed = Subscribed::parse(
            frames
                .iter()
                .find(|frame| !frame.is_send() && frame.json["id"] == 1)
                .expect("a subscribe reply")
                .result()
                .expect("a result"),
        )
        .expect("a subscribe reply parses");
        let notify = frames
            .iter()
            .find_map(|frame| match Incoming::parse(&frame.line) {
                Ok(Incoming::Notify(notify)) => Some(notify),
                _ => None,
            })
            .expect("the capture has notifies");
        Job::new(
            notify,
            &subscribed,
            ShareTarget::from_difficulty(1.0).unwrap(),
        )
    }

    /// The script `MINER_ADDRESS` pays to.
    fn our_script() -> ScriptBuf {
        Address::<NetworkUnchecked>::from_str(MINER_ADDRESS)
            .unwrap()
            .assume_checked()
            .script_pubkey()
    }

    #[test]
    fn the_captured_coinbase_pays_the_address_in_constants() {
        // The capture was taken as `MINER_ADDRESS.puntominer`, against a solo
        // pool, so its coinbase pays that address and nothing warns.
        let job = captured_job();
        let mut payout = Payout::new(&format!("{MINER_ADDRESS}.puntominer"));
        let lines = payout.check(&job.coinbase(DECODED_AT));

        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(&format!("to {MINER_ADDRESS} (MINER_POOL_USER)")),
            "{lines:?}"
        );
        assert!(lines[0].contains("OP_RETURN"), "the witness commitment");

        let tx: Transaction = deserialize(&job.coinbase(DECODED_AT)).expect("it decodes");
        assert!(
            tx.output
                .iter()
                .any(|output| output.script_pubkey == our_script())
        );
    }

    #[test]
    fn a_coinbase_that_pays_someone_else_warns_and_says_why_it_may_be_fine() {
        let job = captured_job();
        let mut payout = Payout::new("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.rig");
        let lines = payout.check(&job.coinbase(DECODED_AT));

        let warning = lines
            .iter()
            .find(|line| line.starts_with("WARNING"))
            .expect("the capture does not pay this address");
        assert!(
            warning.contains("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            "{warning}"
        );
        assert!(warning.contains("PPLNS"), "{warning}");
    }

    #[test]
    fn the_same_payees_are_said_once_however_often_the_job_is_seen() {
        let job = captured_job();
        let mut payout = Payout::new(MINER_ADDRESS);
        assert!(!payout.check(&job.coinbase(DECODED_AT)).is_empty());
        assert!(payout.check(&job.coinbase(DECODED_AT)).is_empty());
        // Another extranonce is the same outputs.
        assert!(payout.check(&job.coinbase(Extranonce(7))).is_empty());

        // And so is the next template, whose amount and witness commitment
        // both moved — which Pool A's jobs do every thirty seconds.
        let mut next: Transaction = deserialize(&job.coinbase(DECODED_AT)).unwrap();
        next.output[0].value += bitcoin::Amount::from_sat(1_000);
        let commitment = next
            .output
            .iter_mut()
            .find(|output| output.script_pubkey.is_op_return())
            .expect("the capture carries a witness commitment");
        let mut script = commitment.script_pubkey.to_bytes();
        *script.last_mut().unwrap() ^= 0xff;
        commitment.script_pubkey = ScriptBuf::from_bytes(script);
        assert!(
            payout
                .check(&bitcoin::consensus::serialize(&next))
                .is_empty()
        );
    }

    #[test]
    fn a_username_that_is_not_an_address_is_reported_and_not_checked() {
        let job = captured_job();
        let mut payout = Payout::new("alice.rig1");
        let lines = payout.check(&job.coinbase(DECODED_AT));

        assert!(lines[0].contains("not an address"), "{lines:?}");
        assert!(lines[1].starts_with("the coinbase pays "), "{lines:?}");
        assert!(
            !lines.iter().any(|line| line.starts_with("WARNING")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_coinbase_that_does_not_decode_says_so_once() {
        let mut payout = Payout::new(MINER_ADDRESS);
        let lines = payout.check(&[0x01, 0x02, 0x03]);
        assert!(lines[0].contains("does not decode"), "{lines:?}");
        assert!(payout.check(&[0x01, 0x02, 0x03]).is_empty());
    }
}
