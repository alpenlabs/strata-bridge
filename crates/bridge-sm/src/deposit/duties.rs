//! The duties that need to be performed in the Deposit State Machine in response to the state
//! transitions.

use std::collections::BTreeMap;

use bitcoin::{Amount, OutPoint, Transaction, Txid, secp256k1::XOnlyPublicKey};
use bitcoin_bosd::Descriptor;
use musig2::{AggNonce, PartialSignature, secp256k1::Message};
use strata_bridge_connectors::SigningInfo;
use strata_bridge_primitives::{
    scripts::taproot::TaprootTweak,
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx, P2POperatorPubKey},
};
use strata_bridge_tx_graph::transactions::prelude::CooperativePayoutTx;

/// The nag duties that can be emitted to remind operators of missing data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NagDuty {
    /// Nag an operator for their missing deposit nonce.
    NagDepositNonce {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// The index of the operator to nag.
        operator_idx: OperatorIdx,
        /// The P2P public key of the operator to nag.
        operator_pubkey: P2POperatorPubKey,
    },
    /// Nag an operator for their missing deposit partial signature.
    NagDepositPartial {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// The index of the operator to nag.
        operator_idx: OperatorIdx,
        /// The P2P public key of the operator to nag.
        operator_pubkey: P2POperatorPubKey,
    },
    /// Nag an operator for their missing payout nonce.
    NagPayoutNonce {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// The index of the operator to nag.
        operator_idx: OperatorIdx,
        /// The P2P public key of the operator to nag.
        operator_pubkey: P2POperatorPubKey,
    },
    /// Nag an operator for their missing payout partial signature.
    NagPayoutPartial {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// The index of the operator to nag.
        operator_idx: OperatorIdx,
        /// The P2P public key of the operator to nag.
        operator_pubkey: P2POperatorPubKey,
    },
}

impl std::fmt::Display for NagDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NagDuty::NagDepositNonce {
                deposit_idx,
                operator_idx,
                ..
            } => write!(
                f,
                "NagDepositNonce (deposit_idx: {}, operator_idx: {})",
                deposit_idx, operator_idx
            ),
            NagDuty::NagDepositPartial {
                deposit_idx,
                operator_idx,
                ..
            } => write!(
                f,
                "NagDepositPartial (deposit_idx: {}, operator_idx: {})",
                deposit_idx, operator_idx
            ),
            NagDuty::NagPayoutNonce {
                deposit_idx,
                operator_idx,
                ..
            } => write!(
                f,
                "NagPayoutNonce (deposit_idx: {}, operator_idx: {})",
                deposit_idx, operator_idx
            ),
            NagDuty::NagPayoutPartial {
                deposit_idx,
                operator_idx,
                ..
            } => write!(
                f,
                "NagPayoutPartial (deposit_idx: {}, operator_idx: {})",
                deposit_idx, operator_idx
            ),
        }
    }
}

/// The duties that need to be performed to drive the Deposit State Machine forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepositDuty {
    /// Publish this operator's nonce for spending the DRT
    PublishDepositNonce {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// DRT outpoint to ID the signing session
        drt_outpoint: OutPoint,
        /// Claim txids for this deposit. If any exists on chain, signing must be aborted.
        claim_txids: Vec<Txid>,
        /// Ordered public keys of all operators for MuSig2 signing
        ordered_pubkeys: Vec<XOnlyPublicKey>,
        /// The taproot tweak for the DRT output (merkle root of take-back script)
        drt_tweak: TaprootTweak,
    },
    /// Publish this operator's partial signature for spending the DRT
    PublishDepositPartial {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// DRT outpoint to resume the earlier signing session
        drt_outpoint: OutPoint,
        /// Claim txids for this deposit. If any exists on chain, signing must be aborted.
        claim_txids: Vec<Txid>,
        /// Signing info containing sighash and tweak for the DRT input
        signing_info: SigningInfo,
        /// aggregated nonce from all operators for this signing session
        deposit_agg_nonce: AggNonce,
        /// Ordered public keys of all operators for MuSig2 signing
        ordered_pubkeys: Vec<XOnlyPublicKey>,
    },
    /// Publish the deposit transaction to the Bitcoin network
    PublishDeposit {
        /// The fully signed deposit transaction ready to be broadcast.
        signed_deposit_transaction: Transaction,
    },
    /// Front the user by sending funds to the provided descriptor within the given deadline.
    FulfillWithdrawal {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// Block height deadline for fulfillment.
        deadline: BitcoinBlockHeight,
        /// The user's descriptor where funds are to be sent by the operator.
        recipient_desc: Descriptor,
        /// The fixed deposit amount expected by the bridge protocol.
        deposit_amount: Amount,
    },
    /// Request pubnonces from all operators for cooperative payout.
    RequestPayoutNonces {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// The index of the point-of-view operator.
        pov_operator_idx: OperatorIdx,
    },
    /// Publish the nonce for spending the deposit UTXO cooperatively.
    PublishPayoutNonce {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// Outpoint referencing the deposit UTXO.
        deposit_outpoint: OutPoint,
        /// Ordered public keys of all operators for MuSig2 signing.
        ordered_pubkeys: Vec<XOnlyPublicKey>,
    },
    /// Publish the partial signature for spending the deposit UTXO cooperatively.
    PublishPayoutPartial {
        /// The index of the deposit.
        deposit_idx: DepositIdx,
        /// Outpoint referencing the deposit UTXO.
        deposit_outpoint: OutPoint,
        /// Sighash to be signed for the payout transaction.
        payout_sighash: Message,
        /// Aggregated nonce for the payout transaction signing.
        agg_nonce: AggNonce,
        /// Ordered public keys of all operators for MuSig2 signing.
        ordered_pubkeys: Vec<XOnlyPublicKey>,
    },
    /// Publish the cooperative payout transaction to the Bitcoin network.
    /// This duty is also responsible for generating the partial signature by the assignee on the
    /// cooperative payout tx.
    PublishPayout {
        /// Outpoint referencing the deposit UTXO.
        deposit_outpoint: OutPoint,
        /// Aggregated nonce for signature generation.
        agg_nonce: AggNonce,
        /// Partial signatures collected from other operators (not including assignee).
        collected_partials: BTreeMap<OperatorIdx, PartialSignature>,
        /// The cooperative payout transaction for finalization.
        payout_coop_tx: Box<CooperativePayoutTx>,
        /// Ordered public keys of all operators for MuSig2 signing.
        ordered_pubkeys: Vec<XOnlyPublicKey>,
        /// The index of the point-of-view operator (the assignee).
        pov_operator_idx: OperatorIdx,
    },
    /// Nag other operators for missing information.
    Nag {
        /// The specific nag duty to perform.
        duty: NagDuty,
    },
}

impl std::fmt::Display for DepositDuty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let display_str = match self {
            DepositDuty::PublishDepositNonce {
                deposit_idx,
                drt_outpoint,
                ..
            } => {
                format!(
                    "PublishDepositNonce (deposit_idx: {}, outpoint: {})",
                    deposit_idx, drt_outpoint
                )
            }
            DepositDuty::PublishDepositPartial { drt_outpoint, .. } => {
                format!("PublishDepositPartial (outpoint: {})", drt_outpoint)
            }
            DepositDuty::PublishDeposit {
                signed_deposit_transaction,
            } => {
                format!(
                    "PublishDeposit (txn: {})",
                    signed_deposit_transaction.compute_txid()
                )
            }
            DepositDuty::FulfillWithdrawal { .. } => "FulfillWithdrawal".to_string(),
            DepositDuty::RequestPayoutNonces { .. } => "RequestPayoutNonces".to_string(),
            DepositDuty::PublishPayoutNonce { .. } => "PublishPayoutNonce".to_string(),
            DepositDuty::PublishPayoutPartial { .. } => "PublishPayoutPartial".to_string(),
            DepositDuty::PublishPayout { .. } => "PublishPayout".to_string(),
            DepositDuty::Nag { duty } => format!("Nag({})", duty),
        };
        write!(f, "{}", display_str)
    }
}
