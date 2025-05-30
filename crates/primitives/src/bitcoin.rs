//! Bitcoin primitives.

use arbitrary::{Arbitrary, Unstructured};
use bitcoin::{self, address::NetworkUnchecked, hashes::Hash, Address, Network, ScriptHash};
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
    /// Parses a bitcoin address from a string and network.
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
    /// Returns the address.
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the network.
    pub const fn network(&self) -> &Network {
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
