//! The block template a node hands out, parsed into the values a miner needs.

use bitcoin::{
    BlockHash, CompactTarget, ScriptBuf, Target, Transaction, consensus::encode::deserialize,
    hex::FromHex,
};

use serde_json::{Value, json};

use super::rpc::Rpc;

/// One `getblocktemplate` response.
///
/// Only the fields a block actually commits to are kept, plus the two the
/// search loop needs to stay honest: `longpollid`, so a stale template can be
/// abandoned, and the fee total, so what was mined can be reported.
#[derive(Debug, Clone)]
pub struct Template {
    pub version: i32,
    pub previous_block_hash: BlockHash,
    pub transactions: Vec<Transaction>,
    pub coinbase_value: u64,
    pub bits: CompactTarget,
    pub target: Target,
    pub curtime: u32,
    pub mintime: u32,
    pub height: i64,
    /// The commitment output Core computed for exactly this transaction set.
    /// Valid only while the set is unmodified — dropping or reordering any
    /// transaction means computing the witness merkle root here instead.
    pub witness_commitment: Option<ScriptBuf>,
    pub longpollid: Option<String>,
    /// The OR of the version bits `vbavailable` assigns to deployments the
    /// node knows of in their started or locked-in states, or `None` when the
    /// template has no `vbavailable` at all — in which case those deployments
    /// are unknown and nothing may be rolled. See [`Self::rollable_bits`].
    pub vbavailable: Option<u32>,
    /// Sum of the template's transaction fees, in satoshis.
    pub fees: u64,
    /// How many templates this run has already ground at this height, which is
    /// the half of the coinbase tag's rotation index the height does not
    /// supply — see [`crate::block::coinbase_tag_name_for`].
    ///
    /// Not a field of the node's answer: `getblocktemplate` knows nothing about
    /// what this run has already tried, so a parsed template is always the
    /// first attempt and the run loop raises it when it takes another template
    /// at a height it is already on. It lives here rather than being threaded
    /// through `build_coinbase` because it has to be fixed for the life of one
    /// template: every rebuild of that coinbase, once per extranonce, has to
    /// agree about the tag or the merkle root moves for a reason the search did
    /// not intend.
    pub attempt: u64,
}

impl Template {
    /// Fetch and parse a template, declaring segwit support as every modern
    /// miner must.
    pub fn fetch(rpc: &Rpc) -> Result<Self, String> {
        let value = rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}]))?;
        Self::parse(&value)
    }

    pub fn parse(value: &Value) -> Result<Self, String> {
        let version = field(value, "version")?
            .as_i64()
            .ok_or("version is not a number")? as i32;

        let previous_block_hash = field(value, "previousblockhash")?
            .as_str()
            .ok_or("previousblockhash is not a string")?
            .parse::<BlockHash>()
            .map_err(|error| format!("invalid previousblockhash: {error}"))?;

        let bits_hex = field(value, "bits")?
            .as_str()
            .ok_or("bits is not a string")?
            .to_string();
        let bits_bytes = <[u8; 4]>::from_hex(&bits_hex)
            .map_err(|error| format!("invalid bits {bits_hex}: {error}"))?;
        let bits = CompactTarget::from_consensus(u32::from_be_bytes(bits_bytes));
        let target = Target::from_compact(bits);

        let mut transactions = Vec::new();
        let mut fees: u64 = 0;
        for entry in field(value, "transactions")?
            .as_array()
            .ok_or("transactions is not an array")?
        {
            let data = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or("a template transaction has no data")?;
            let bytes = Vec::<u8>::from_hex(data)
                .map_err(|error| format!("a template transaction is not hex: {error}"))?;
            let transaction: Transaction = deserialize(&bytes)
                .map_err(|error| format!("could not decode a template transaction: {error}"))?;
            transactions.push(transaction);
            fees = fees.saturating_add(entry.get("fee").and_then(Value::as_u64).unwrap_or(0));
        }

        let witness_commitment = match value.get("default_witness_commitment") {
            Some(Value::String(hex)) => Some(
                ScriptBuf::from_hex(hex)
                    .map_err(|error| format!("invalid default_witness_commitment: {error}"))?,
            ),
            _ => None,
        };

        let vbavailable = match value.get("vbavailable") {
            None => None,
            Some(deployments) => {
                let mut bits = 0u32;
                for (name, bit) in deployments
                    .as_object()
                    .ok_or("vbavailable is not an object")?
                {
                    let bit = bit
                        .as_u64()
                        .filter(|bit| *bit < 32)
                        .ok_or_else(|| format!("vbavailable's {name} is not a version bit"))?;
                    bits |= 1 << bit;
                }
                Some(bits)
            }
        };

        Ok(Self {
            version,
            previous_block_hash,
            transactions,
            coinbase_value: field(value, "coinbasevalue")?
                .as_u64()
                .ok_or("coinbasevalue is not a number")?,
            bits,
            target,
            curtime: field(value, "curtime")?
                .as_u64()
                .ok_or("curtime is not a number")? as u32,
            mintime: field(value, "mintime")?
                .as_u64()
                .ok_or("mintime is not a number")? as u32,
            height: field(value, "height")?
                .as_i64()
                .ok_or("height is not a number")?,
            witness_commitment,
            longpollid: value
                .get("longpollid")
                .and_then(Value::as_str)
                .map(str::to_string),
            vbavailable,
            fees,
            attempt: 0,
        })
    }

    /// The version bits a solo search may roll on this template.
    ///
    /// BIP320's bits 13–28, minus every bit the template's version sets, minus
    /// every bit `vbavailable` assigns to a deployment. **"The BIP320 bits are
    /// free" is not assumed**: Bitcoin Core never adopted BIP320's carve-out,
    /// and regtest's `testdummy` sits on bit 28, inside it. A bit the template
    /// sets is the node signalling, and one `vbavailable` lists is a deployment
    /// it knows of and is not signalling for, so neither is this miner's to
    /// move.
    ///
    /// Zero — nothing rolls — when the template has no `vbavailable`, since the
    /// deployments the node knows of are then unknown, and when its version
    /// does not open with BIP9's top bits `001`, since a version that is not
    /// read as versionbits has no rollable bits to speak of.
    pub fn rollable_bits(&self) -> u32 {
        let version = self.version as u32;
        match self.vbavailable {
            Some(deployments) if version >> 29 == 0b001 => {
                crate::block::BIP320_MASK & !version & !deployments
            }
            _ => 0,
        }
    }

    /// The block subsidy this template implies, which is the coinbase value
    /// less the fees the node totalled.
    pub fn subsidy(&self) -> u64 {
        self.coinbase_value.saturating_sub(self.fees)
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("the template has no {name} field"))
}

/// A parsed template at a chosen height, for tests in other modules that need
/// one to hand around and have no node to fetch it from.
#[cfg(test)]
pub(crate) fn sample_at(height: i64) -> Template {
    let mut value = tests::sample();
    value["height"] = json!(height);
    Template::parse(&value).expect("the sample template should parse")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A trimmed mainnet template: one transaction, real bits, real
    /// commitment. Enough to prove every field lands where it belongs.
    pub(crate) fn sample() -> Value {
        json!({
            "version": 536870912,
            "previousblockhash": "00000000000000000001fbed1f4d8af3fc5b134961237f1ae2099c38eddfeacf",
            "transactions": [{
                "data": "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0401010101ffffffff0100f2052a01000000160014329649f03db93aef2cf873e9b8544a446d38316d0120000000000000000000000000000000000000000000000000000000000000000000000000",
                "txid": "0000000000000000000000000000000000000000000000000000000000000000",
                "fee": 512991,
                "sigops": 0,
                "weight": 400
            }],
            "coinbasevalue": 313012991u64,
            "target": "000000000000000000023ad40000000000000000000000000000000000000000",
            "mintime": 1785584526u64,
            "curtime": 1785588946u64,
            "bits": "17023ad4",
            "height": 960563,
            "longpollid": "00000000000000000001fbed1f4d8af3fc5b134961237f1ae2099c38eddfeacf2960",
            "default_witness_commitment": "6a24aa21a9edf1073880adb89653d6d74597eb73f143876ea094763ea24c49dffa3d3c3d9495"
        })
    }

    #[test]
    fn parses_every_field_a_block_commits_to() {
        let template = Template::parse(&sample()).expect("the sample template should parse");

        assert_eq!(template.version, 536870912);
        assert_eq!(template.height, 960563);
        assert_eq!(template.transactions.len(), 1);
        assert_eq!(template.coinbase_value, 313_012_991);
        assert_eq!(template.fees, 512_991);
        assert_eq!(template.bits.to_consensus(), 0x17023ad4);
        assert!(template.witness_commitment.is_some());
        assert!(template.longpollid.is_some());
    }

    #[test]
    fn the_expanded_target_matches_what_the_node_reported() {
        let template = Template::parse(&sample()).expect("the sample template should parse");
        let reported = <[u8; 32]>::from_hex(sample()["target"].as_str().unwrap())
            .expect("the sample target should be hex");

        // `bits` is the compact form of the same number the node prints, so
        // expanding it here has to reproduce those bytes exactly. This is the
        // check that catches a compact-target expansion bug before it can
        // silently accept a header that misses the real target.
        assert_eq!(template.target.to_be_bytes(), reported);
    }

    #[test]
    fn subsidy_is_the_coinbase_value_less_fees() {
        let template = Template::parse(&sample()).expect("the sample template should parse");
        // Height 960,563 is past four halvings: 3.125 BTC.
        assert_eq!(template.subsidy(), 312_500_000);
    }

    /// A `getblocktemplate` answer captured on 6 November 2026 — see
    /// `tests/fixtures/README.md`.
    fn captured(json: &str) -> Template {
        Template::parse(&serde_json::from_str(json).expect("the capture should be JSON"))
            .expect("the capture should parse")
    }

    #[test]
    fn mainnet_with_no_deployment_listed_rolls_all_of_bip320() {
        let template = captured(include_str!(
            "../tests/fixtures/template-mainnet-974833.json"
        ));
        assert_eq!(template.version, 0x2000_0000);
        assert_eq!(template.vbavailable, Some(0));
        assert_eq!(template.rollable_bits(), 0x1fff_e000);
    }

    #[test]
    fn a_fresh_regtest_chain_rolls_all_of_bip320() {
        let template = captured(include_str!("../tests/fixtures/template-regtest-1.json"));
        assert_eq!(template.rollable_bits(), 0x1fff_e000);
    }

    #[test]
    fn regtest_with_testdummy_listed_never_rolls_bit_28() {
        // From height 145 Core lists `testdummy` and signals for it itself, so
        // bit 28 is excluded twice over.
        let template = captured(include_str!(
            "../tests/fixtures/template-regtest-145-testdummy.json"
        ));
        assert_eq!(template.version, 0x3000_0000);
        assert_eq!(template.vbavailable, Some(1 << 28));
        assert_eq!(template.rollable_bits(), 0x0fff_e000);
    }

    #[test]
    fn an_announced_30000000_keeps_bit_28_and_never_rolls_it() {
        // `-blockversion=805306368`: bit 28 is set with nothing listed, so it
        // is excluded as a template bit rather than as a deployment.
        let template = captured(include_str!(
            "../tests/fixtures/template-regtest-1-blockversion.json"
        ));
        assert_eq!(template.version, 0x3000_0000);
        assert_eq!(template.vbavailable, Some(0));
        assert_eq!(template.rollable_bits(), 0x0fff_e000);
        let versions: Vec<u32> =
            crate::block::VersionRoll::new(template.version as u32, template.rollable_bits())
                .collect();
        assert!(versions.iter().all(|version| version & 0x1000_0000 != 0));
    }

    #[test]
    fn a_template_without_vbavailable_rolls_nothing() {
        let template = Template::parse(&sample()).expect("the sample template should parse");
        assert_eq!(template.vbavailable, None);
        assert_eq!(template.rollable_bits(), 0);
    }

    #[test]
    fn a_version_that_is_not_versionbits_rolls_nothing() {
        let mut value = sample();
        value["version"] = json!(4);
        value["vbavailable"] = json!({});
        let template = Template::parse(&value).expect("should parse");
        assert_eq!(template.rollable_bits(), 0);
    }

    #[test]
    fn a_malformed_vbavailable_is_rejected() {
        let mut value = sample();
        value["vbavailable"] = json!({"somefork": 40});
        assert!(Template::parse(&value).is_err());
        value["vbavailable"] = json!([28]);
        assert!(Template::parse(&value).is_err());
    }

    #[test]
    fn a_template_missing_a_field_is_rejected() {
        let mut value = sample();
        value.as_object_mut().unwrap().remove("bits");
        assert!(Template::parse(&value).is_err());
    }
}
