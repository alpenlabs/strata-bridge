//! Basic, seeded implementation of a secret service

use std::path::Path;

use bitcoin::{bip32::Xpriv, Network};
use colored::Colorize;
use musig2::{Ms2Signer, ServerFirstRound, ServerSecondRound};
use p2p::ServerP2PSigner;
use rand::Rng;
use secret_service_proto::v1::traits::{SecretService, Server};
use stakechain::StakeChain;
use strata_key_derivation::operator::OperatorKeys;
use tokio::{fs, io};
use tracing::info;
use wallet::{GeneralWalletSigner, StakechainWalletSigner};
use wots::SeededWotsSigner;

pub mod musig2;
pub mod p2p;
pub mod paths;
pub mod stakechain;
pub mod wallet;
pub mod wots;

/// Secret data for the Secret Service.
#[derive(Debug)]
pub struct Service {
    /// Operator's keys.
    keys: OperatorKeys,
}

impl Service {
    /// Loads the operator's keys from a seed file.
    pub async fn load_from_seed(seed_path: &Path, network: Network) -> io::Result<Self> {
        let mut seed = [0; 32];

        if let Some(parent) = seed_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        match fs::read(seed_path).await {
            Ok(vec) => {
                seed.copy_from_slice(&vec);
                info!(
                    "Loaded seed from {}",
                    seed_path.display().to_string().bold()
                );
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut rng = rand::thread_rng();
                rng.fill(&mut seed);
                fs::write(seed_path, &seed).await?;
                info!(
                    "Generated new seed at {}",
                    seed_path.display().to_string().bold()
                );
            }
            Err(e) => return Err(e),
        };

        Ok(Self::new_with_seed(seed, network))
    }

    /// Deterministically creates a new service using a given seed
    pub fn new_with_seed(seed: [u8; 32], network: Network) -> Self {
        let keys = OperatorKeys::new(&Xpriv::new_master(network, &seed).expect("valid xpriv"))
            .expect("valid keychain");
        info!(
            "Master fingerprint: {}",
            keys.master_xpub().fingerprint().to_string().bold()
        );
        Self { keys }
    }
}

impl SecretService<Server, ServerFirstRound, ServerSecondRound> for Service {
    type GeneralWalletSigner = GeneralWalletSigner;

    type StakechainWalletSigner = StakechainWalletSigner;

    type P2PSigner = ServerP2PSigner;

    type Musig2Signer = Ms2Signer;

    type WotsSigner = SeededWotsSigner;

    type StakeChainPreimages = StakeChain;

    fn general_wallet_signer(&self) -> Self::GeneralWalletSigner {
        GeneralWalletSigner::new(self.keys.base_xpriv())
    }

    fn stakechain_wallet_signer(&self) -> Self::StakechainWalletSigner {
        StakechainWalletSigner::new(self.keys.base_xpriv())
    }

    fn p2p_signer(&self) -> Self::P2PSigner {
        ServerP2PSigner::new(self.keys.base_xpriv())
    }

    fn musig2_signer(&self) -> Self::Musig2Signer {
        Ms2Signer::new(self.keys.base_xpriv())
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        SeededWotsSigner::new(self.keys.base_xpriv())
    }

    fn stake_chain_preimages(&self) -> Self::StakeChainPreimages {
        StakeChain::new(self.keys.base_xpriv())
    }
}
