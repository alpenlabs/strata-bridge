use std::path::Path;

use bitcoin::{
    bip32::{ChildNumber, Xpriv},
    secp256k1::SECP256K1,
    Network,
};
use musig2::{Ms2Signer, ServerFirstRound, ServerSecondRound};
use operator::Operator;
use p2p::ServerP2PSigner;
use rand::Rng;
use secret_service_proto::v1::traits::{SecretService, Server};
use stakechain::StakeChain;
use strata_key_derivation::operator::OperatorKeys;
use tokio::{fs, io};
use wots::SeededWotsSigner;

pub mod musig2;
pub mod operator;
pub mod p2p;
pub mod stakechain;
pub mod wots;

pub struct Service {
    keys: OperatorKeys,
}

const NETWORK: Network = Network::Signet;

impl Service {
    pub async fn load_from_seed(seed_path: &Path) -> io::Result<Self> {
        let mut seed = [0; 32];

        if let Some(parent) = seed_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        match fs::read(seed_path).await {
            Ok(vec) => seed.copy_from_slice(&vec),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut rng = rand::thread_rng();
                rng.fill(&mut seed);
                fs::write(seed_path, &seed).await?;
            }
            Err(e) => return Err(e),
        };

        let keys = OperatorKeys::new(&Xpriv::new_master(NETWORK, &seed).expect("valid xpriv"))
            .expect("valid keychain");
        Ok(Self { keys })
    }
}

impl SecretService<Server, ServerFirstRound, ServerSecondRound> for Service {
    type OperatorSigner = Operator;

    type P2PSigner = ServerP2PSigner;

    type Musig2Signer = Ms2Signer;

    type WotsSigner = SeededWotsSigner;

    type StakeChain = StakeChain;

    fn operator_signer(&self) -> Self::OperatorSigner {
        Operator::new(self.keys.wallet_xpriv().private_key)
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        ServerP2PSigner::new(self.keys.message_xpriv().private_key)
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        let xpriv = self
            .keys
            .base_xpriv()
            .derive_priv(
                SECP256K1,
                &[
                    ChildNumber::from_hardened_idx(20).unwrap(),
                    ChildNumber::from_hardened_idx(101).unwrap(),
                ],
            )
            .expect("valid key");
        Ms2Signer::new(xpriv.private_key)
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        SeededWotsSigner::new(self.keys.base_xpriv())
    }

    fn stake_chain(&self) -> Self::StakeChain {
        StakeChain::new(self.keys.base_xpriv())
    }
}
