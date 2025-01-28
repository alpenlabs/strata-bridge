use std::io::{Error, ErrorKind, Read, Write};

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::{
    absolute::LockTime,
    address::NetworkUnchecked,
    consensus::{deserialize, serialize},
    hashes::Hash,
    transaction::Version,
    Address, Amount, Network, ScriptBuf, ScriptHash, Transaction, Txid, Witness,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{de, Deserialize, Deserializer, Serialize};

/// A wrapper around the [`bitcoin::Address<NetworkChecked>`] type.
///
/// This is created in order to couple addresses with the corresponding network and to preserve that
/// information across serialization/deserialization.
// TODO: implement [`arbitrary::Arbitrary`]?
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitcoinAddress {
    /// The [`bitcoin::Network`] that this address is valid in.
    network: Network,

    /// The actual [`Address`] that this type wraps.
    address: Address,
}

impl<'a> Arbitrary<'a> for BitcoinAddress {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate an arbitrary `Network`
        let network = *u
            .choose(&[
                Network::Bitcoin,
                Network::Testnet,
                Network::Regtest,
                Network::Signet,
            ])
            .map_err(|_| arbitrary::Error::NotEnoughData)?;

        // Generate an arbitrary `Address`
        // Create a random hash to use for the address payload
        let hash: [u8; 20] = u.arbitrary()?;
        let address = match network {
            Network::Bitcoin | Network::Testnet | Network::Signet | Network::Regtest => {
                // TODO: find ways to support other types of addresses
                Address::p2sh_from_hash(
                    ScriptHash::from_slice(&hash).expect("must have right number of bytes"),
                    network,
                )
            }
            new_network => unimplemented!("{new_network} not supported"),
        };

        Ok(Self { network, address })
    }
}

impl BitcoinAddress {
    pub fn parse(address_str: &str, network: Network) -> anyhow::Result<Self> {
        let address = address_str.parse::<Address<NetworkUnchecked>>()?;

        let checked_address = address.require_network(network)?;

        Ok(Self {
            network,
            address: checked_address,
        })
    }
}

impl BitcoinAddress {
    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn network(&self) -> &Network {
        &self.network
    }
}

impl<'de> Deserialize<'de> for BitcoinAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct BitcoinAddressShim {
            network: Network,
            address: String,
        }

        let shim = BitcoinAddressShim::deserialize(deserializer)?;
        let address = shim
            .address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|_| de::Error::custom("invalid bitcoin address"))?
            .require_network(shim.network)
            .map_err(|_| de::Error::custom("address invalid for given network"))?;

        Ok(BitcoinAddress {
            network: shim.network,
            address,
        })
    }
}
/// [Borsh](borsh)-friendly Bitcoin [`Transaction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinTx(Transaction);

impl From<Transaction> for BitcoinTx {
    fn from(value: Transaction) -> Self {
        Self(value)
    }
}

impl From<BitcoinTx> for Transaction {
    fn from(value: BitcoinTx) -> Self {
        value.0
    }
}

impl AsRef<Transaction> for BitcoinTx {
    fn as_ref(&self) -> &Transaction {
        &self.0
    }
}

/// Implement BorshSerialize using Bitcoin consensus serialization.
impl BorshSerialize for BitcoinTx {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Use bitcoin's consensus serialization
        let tx_bytes = serialize(&self.0);
        BorshSerialize::serialize(&(tx_bytes.len() as u32), writer)?;
        writer.write_all(&tx_bytes)
    }
}

/// Implement BorshDeserialize using Bitcoin consensus deserialization.
impl BorshDeserialize for BitcoinTx {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        // First, read a Vec<u8> using Borsh (this picks up the length)
        let tx_len = u32::deserialize_reader(reader)? as usize;
        let mut tx_bytes = vec![0u8; tx_len];
        reader.read_exact(&mut tx_bytes)?;

        // Now parse those bytes with bitcoin consensus
        let tx = deserialize(&tx_bytes).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

        Ok(BitcoinTx(tx))
    }
}

impl<'a> arbitrary::Arbitrary<'a> for BitcoinTx {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use bitcoin::{
            blockdata::transaction::{OutPoint, TxIn, TxOut},
            Sequence, Transaction,
        };

        // Random number of inputs and outputs (bounded for simplicity)
        let input_count = u.int_in_range::<usize>(0..=4)?;
        let output_count = u.int_in_range::<usize>(0..=4)?;

        // Build random inputs
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            // Random 32-byte TXID
            let mut txid_bytes = [0u8; 32];
            u.fill_buffer(&mut txid_bytes)?;

            // Random vout
            let vout = u32::arbitrary(u)?;

            // Random scriptSig (bounded size)
            let script_sig_size = u.int_in_range::<usize>(0..=50)?;
            let script_sig_bytes = u.bytes(script_sig_size)?;
            let script_sig = ScriptBuf::from_bytes(script_sig_bytes.to_vec());

            inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(txid_bytes),
                    vout,
                },
                script_sig,
                sequence: Sequence::MAX,
                witness: Witness::default(), // or generate random witness if desired
            });
        }

        // Build random outputs
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            // Random value (in satoshis)
            let value = Amount::from_sat(u64::arbitrary(u)?);

            // Random scriptPubKey (bounded size)
            let script_pubkey_size = u.int_in_range::<usize>(0..=50)?;
            let script_pubkey_bytes = u.bytes(script_pubkey_size)?;
            let script_pubkey = ScriptBuf::from(script_pubkey_bytes.to_vec());

            outputs.push(TxOut {
                value,
                script_pubkey,
            });
        }

        // Construct the transaction
        let tx = Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        Ok(BitcoinTx(tx))
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::arbitrary_generator::ArbitraryGenerator;

    use super::*;

    #[test]
    fn test_bitcoin_tx_serialize_deserialize() {
        let mut generator = ArbitraryGenerator::new();
        let tx: BitcoinTx = generator.generate();

        let serialized_tx = borsh::to_vec(&tx).expect("should be able to serialize BitcoinTx");
        let deseralized_tx: BitcoinTx =
            borsh::from_slice(&serialized_tx).expect("should be able to deserialize BitcoinTx");

        assert_eq!(
            tx, deseralized_tx,
            "original and deserialized tx must be the same"
        );
    }
}
