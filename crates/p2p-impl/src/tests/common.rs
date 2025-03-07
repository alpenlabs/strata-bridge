//! Helper functions for the P2P tests.

use std::{sync::Arc, time::Duration};

use anyhow::bail;
use bitcoin::{
    hashes::{sha256, Hash},
    Txid, XOnlyPublicKey,
};
use futures::future::join_all;
use libp2p::{
    build_multiaddr,
    identity::{secp256k1::Keypair as SecpKeypair, Keypair},
    Multiaddr, PeerId,
};
use strata_bridge_test_utils::musig2::{generate_partial_signature, generate_pubnonce};
use strata_p2p::{
    commands::{Command, UnsignedPublishMessage},
    events::Event,
    swarm::{self, handle::P2PHandle, P2PConfig, P2P},
};
use strata_p2p_db::sled::AsyncDB;
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use strata_p2p_wire::p2p::v1::{GossipsubMsg, UnsignedGossipsubMsg};
use threadpool::ThreadPool;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, trace};

pub(crate) struct Operator {
    pub(crate) p2p: P2P<AsyncDB>,
    pub(crate) handle: P2PHandle,
    pub(crate) kp: SecpKeypair,
    pub(crate) db: AsyncDB,
}

impl Operator {
    pub(crate) fn new(
        keypair: SecpKeypair,
        allowlist: Vec<PeerId>,
        connect_to: Vec<Multiaddr>,
        local_addr: Multiaddr,
        cancel: CancellationToken,
        signers_allowlist: Vec<P2POperatorPubKey>,
    ) -> anyhow::Result<Self> {
        let db = sled::Config::new().temporary(true).open()?;

        let config = P2PConfig {
            keypair: keypair.clone(),
            idle_connection_timeout: Duration::from_secs(30),
            listening_addr: local_addr,
            allowlist,
            connect_to,
            signers_allowlist,
        };

        let swarm = swarm::with_inmemory_transport(&config)?;
        let db = AsyncDB::new(ThreadPool::new(1), Arc::new(db));
        let (p2p, handle) = P2P::<AsyncDB>::from_config(config, cancel, db.clone(), swarm, None)?;

        Ok(Self {
            handle,
            p2p,
            kp: keypair,
            db,
        })
    }
}

/// Auxiliary structure to control operators from outside.
pub(crate) struct OperatorHandle {
    pub(crate) handle: P2PHandle,
    pub(crate) peer_id: PeerId,
    pub(crate) kp: SecpKeypair,
    pub(crate) db: AsyncDB, // We include DB here to manipulate internal data and flow mechanics.
}

pub(crate) struct Setup {
    pub(crate) cancel: CancellationToken,
    pub(crate) operators: Vec<OperatorHandle>,
    pub(crate) tasks: TaskTracker,
}

impl Setup {
    /// Spawn `n` operators that are connected "all-to-all" with handles to them, task tracker
    /// to stop control async tasks they are spawned in.
    pub(crate) async fn all_to_all(n: usize) -> anyhow::Result<Self> {
        let (keypairs, peer_ids, multiaddresses) = Self::setup_keys_ids_addrs_of_n_operators(n);
        trace!(?keypairs, ?peer_ids, ?multiaddresses, "setup nodes");

        let cancel = CancellationToken::new();
        let mut operators = Vec::new();
        let signers_allowlist: Vec<P2POperatorPubKey> = keypairs
            .clone()
            .into_iter()
            .map(|kp| kp.public().clone().into())
            .collect();

        for (idx, (keypair, addr)) in keypairs.iter().zip(&multiaddresses).enumerate() {
            let mut other_addrs = multiaddresses.clone();
            other_addrs.remove(idx);
            let mut other_peerids = peer_ids.clone();
            other_peerids.remove(idx);

            let operator = Operator::new(
                keypair.clone(),
                other_peerids,
                other_addrs,
                addr.clone(),
                cancel.child_token(),
                signers_allowlist.clone(),
            )?;

            operators.push(operator);
        }

        let (operators, tasks) = Self::start_operators(operators).await;

        Ok(Self {
            cancel,
            tasks,
            operators,
        })
    }

    /// Spawn `n` operators that are connected "all-to-all" with handles to them, task tracker
    /// to stop control async tasks they are spawned in with an extra signers allowlist.
    #[expect(dead_code)]
    pub(crate) async fn with_extra_signers(
        number: usize,
        extra_signers: Vec<P2POperatorPubKey>,
    ) -> anyhow::Result<Self> {
        let (keypairs, peer_ids, multiaddresses) =
            Self::setup_keys_ids_addrs_of_n_operators(number);

        let cancel = CancellationToken::new();
        let mut operators = Vec::new();
        let mut signers_allowlist: Vec<P2POperatorPubKey> = keypairs
            .clone()
            .into_iter()
            .map(|kp| kp.public().clone().into())
            .collect();

        // Add the extra signers to the allowlist
        signers_allowlist.extend(extra_signers);

        for (idx, (keypair, addr)) in keypairs.iter().zip(&multiaddresses).enumerate() {
            let mut other_addrs = multiaddresses.clone();
            other_addrs.remove(idx);
            let mut other_peerids = peer_ids.clone();
            other_peerids.remove(idx);

            let operator = Operator::new(
                keypair.clone(),
                other_peerids,
                other_addrs,
                addr.clone(),
                cancel.child_token(),
                signers_allowlist.clone(),
            )?;

            operators.push(operator);
        }

        let (operators, tasks) = Self::start_operators(operators).await;

        Ok(Self {
            cancel,
            tasks,
            operators,
        })
    }

    /// Create `n` random keypairs, peer ids from them and sequential in-memory
    /// addresses.
    fn setup_keys_ids_addrs_of_n_operators(
        n: usize,
    ) -> (Vec<SecpKeypair>, Vec<PeerId>, Vec<libp2p::Multiaddr>) {
        let keypairs = (0..n).map(|_| SecpKeypair::generate()).collect::<Vec<_>>();
        let peer_ids = keypairs
            .iter()
            .map(|key| PeerId::from_public_key(&Keypair::from(key.clone()).public()))
            .collect::<Vec<_>>();
        let multiaddresses = (1..(keypairs.len() + 1) as u16)
            .map(|idx| build_multiaddr!(Memory(idx)))
            .collect::<Vec<_>>();
        (keypairs, peer_ids, multiaddresses)
    }

    /// Wait until all operators established connections with other operators,
    /// and then spawn [`P2P::listen`]s in separate tasks using [`TaskTracker`].
    async fn start_operators(mut operators: Vec<Operator>) -> (Vec<OperatorHandle>, TaskTracker) {
        // wait until all of them established connections and subscriptions
        join_all(
            operators
                .iter_mut()
                .map(|op| op.p2p.establish_connections())
                .collect::<Vec<_>>(),
        )
        .await;

        let mut levers = Vec::new();
        let tasks = TaskTracker::new();
        for operator in operators {
            let peer_id = operator.p2p.local_peer_id();
            tasks.spawn(operator.p2p.listen());

            levers.push(OperatorHandle {
                handle: operator.handle,
                peer_id,
                kp: operator.kp,
                db: operator.db,
            });
        }

        tasks.close();
        (levers, tasks)
    }
}

pub(crate) fn mock_stake_chain_info(kp: &SecpKeypair, stake_chain_id: StakeChainId) -> Command {
    let kind = UnsignedPublishMessage::StakeChainExchange {
        stake_chain_id,
        pre_stake_txid: Txid::all_zeros(),
        pre_stake_vout: 0,
    };
    kind.sign_secp256k1(kp).into()
}

pub(crate) fn mock_deposit_setup(kp: &SecpKeypair, scope: Scope) -> Command {
    let mock_bytes = [0u8; 1_360 + 362_960];
    let unsigned = UnsignedPublishMessage::DepositSetup {
        scope,
        hash: sha256::Hash::const_hash(b"hash me!"),
        funding_txid: Txid::all_zeros(),
        funding_vout: 0,
        operator_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        wots_pks: WotsPublicKeys::from_flattened_bytes(&mock_bytes),
    };
    unsigned.sign_secp256k1(kp).into()
}

pub(crate) fn mock_deposit_nonces(kp: &SecpKeypair, session_id: SessionId) -> Command {
    let unsigned = UnsignedPublishMessage::Musig2NoncesExchange {
        session_id,
        pub_nonces: (0..5).map(|_| generate_pubnonce()).collect(),
    };
    unsigned.sign_secp256k1(kp).into()
}

pub(crate) fn mock_deposit_sigs(kp: &SecpKeypair, session_id: SessionId) -> Command {
    let unsigned = UnsignedPublishMessage::Musig2SignaturesExchange {
        session_id,
        partial_sigs: (0..5).map(|_| generate_partial_signature()).collect(),
    };
    unsigned.sign_secp256k1(kp).into()
}

pub(crate) async fn exchange_stake_chain_info(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    stake_chain_id: StakeChainId,
) -> anyhow::Result<()> {
    for operator in operators.iter() {
        operator
            .handle
            .send_command(mock_stake_chain_info(&operator.kp, stake_chain_id))
            .await;
    }
    for operator in operators.iter_mut() {
        // received stake chain info from other n-1 operators
        for _ in 0..operators_num - 1 {
            let event = operator.handle.next_event().await?;

            if !matches!(
                event,
                Event::ReceivedMessage(GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::StakeChainExchange { .. },
                    ..
                })
            ) {
                bail!("Got event other than 'stake_chain_info' - {:?}", event);
            }
        }

        assert!(operator.handle.events_is_empty());
    }

    Ok(())
}

pub(crate) async fn exchange_deposit_setup(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    scope: Scope,
) -> anyhow::Result<()> {
    for operator in operators.iter() {
        operator
            .handle
            .send_command(mock_deposit_setup(&operator.kp, scope))
            .await;
    }
    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let event = operator.handle.next_event().await.unwrap();
            if !matches!(
                event,
                Event::ReceivedMessage(GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::DepositSetup { .. },
                    ..
                })
            ) {
                bail!("Got event other than 'deposit_setup' - {:?}", event);
            }
            info!(to=%operator.peer_id, "Got deposit setup");
        }
        assert!(operator.handle.events_is_empty());
    }
    Ok(())
}

pub(crate) async fn exchange_deposit_nonces(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    session_id: SessionId,
) -> anyhow::Result<()> {
    for operator in operators.iter() {
        operator
            .handle
            .send_command(mock_deposit_nonces(&operator.kp, session_id))
            .await;
    }
    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let event = operator.handle.next_event().await.unwrap();
            if !matches!(
                event,
                Event::ReceivedMessage(GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::Musig2NoncesExchange { .. },
                    ..
                })
            ) {
                bail!("Got event other than 'deposit_nonces' - {:?}", event);
            }
            info!(to=%operator.peer_id, "Got deposit setup");
        }
        assert!(operator.handle.events_is_empty());
    }
    Ok(())
}

pub(crate) async fn exchange_deposit_sigs(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    session_id: SessionId,
) -> anyhow::Result<()> {
    for operator in operators.iter() {
        operator
            .handle
            .send_command(mock_deposit_sigs(&operator.kp, session_id))
            .await;
    }

    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let event = operator.handle.next_event().await.unwrap();
            if !matches!(
                event,
                Event::ReceivedMessage(GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::Musig2SignaturesExchange { .. },
                    ..
                })
            ) {
                bail!("Got event other than 'deposit_sigs' - {:?}", event);
            }
            info!(to=%operator.peer_id, "Got deposit sigs");
        }
        assert!(operator.handle.events_is_empty());
    }

    Ok(())
}
