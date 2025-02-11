use std::path::{Path, PathBuf};

use bitcoin::{bip32::Xpriv, Network};
use musig2::{Ms2Signer, ServerFirstRound, ServerSecondRound, SledRoundPersist};
use operator::Operator;
use p2p::ServerP2PSigner;
use rand::Rng;
use secret_service_proto::v1::traits::{SecretService, Server};
use sled::Db;
use stakechain::StakeChain;
use strata_key_derivation::operator::OperatorKeys;
use tokio::{fs, io, task::spawn_blocking};
use wots::SeededWotsSigner;

pub mod musig2;
pub mod operator;
pub mod p2p;
pub mod stakechain;
pub mod wots;

pub struct Service {
    keys: OperatorKeys,
    db: Db,
}

const NETWORK: Network = Network::Signet;

impl Service {
    pub async fn load_from_seed_and_db(seed_path: &Path, db_path: PathBuf) -> io::Result<Self> {
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

        let db = spawn_blocking(move || sled::open(db_path))
            .await
            .expect("thread ok")?;

        let keys = OperatorKeys::new(&Xpriv::new_master(NETWORK, &seed).expect("valid xpriv"))
            .expect("valid keychain");
        Ok(Self { keys, db })
    }

    pub fn round_persister(&self) -> io::Result<SledRoundPersist> {
        Ok(SledRoundPersist::new(
            self.db.open_tree(b"musig2_first_rounds")?,
            self.db.open_tree(b"musig2_second_rounds")?,
        ))
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
        Ms2Signer::new(self.keys.wallet_xpriv().private_key)
    }

    fn wots_signer(&self) -> Self::WotsSigner {
        let seed = self.keys.base_xpriv().private_key.secret_bytes();
        SeededWotsSigner::new(seed)
    }

    fn stake_chain(&self) -> Self::StakeChain {
        let seed = self.keys.base_xpriv().private_key.secret_bytes();
        StakeChain::new(seed)
    }
}
