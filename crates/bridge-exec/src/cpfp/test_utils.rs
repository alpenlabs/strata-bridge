//! Test doubles and fixtures that the CPFP test modules share.

use std::{
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey, absolute,
    hashes::Hash,
    secp256k1::{Keypair, Message, SECP256K1, schnorr::Signature},
    transaction::Version,
};
use bitcoind_async_client::error::ClientError;
use btc_tracker::cpfp::{BumpOutcome, CpfpStrategy};
use operator_wallet::{
    FundingInput, IncumbentChild, Lease, ReplacedChild, test_utils::empty_lease,
};

use super::{
    errors::*,
    handle::{CpfpHandle, HeldChild},
    interfaces::*,
    ladder::{CpfpContext, perform_bump},
    submitpackage::{SubmitPackageError, SubmitPackageSummary},
};
use crate::fees::{FeeSource, FeeSourceError, FeeTargetPolicy};

#[derive(Debug)]
pub(super) struct FakeFeeSource {
    pub(super) rate: Mutex<Result<FeeRate, FeeSourceError>>,
}
impl FakeFeeSource {
    pub(super) fn returning(rate: FeeRate) -> Self {
        Self {
            rate: Mutex::new(Ok(rate)),
        }
    }
    pub(super) fn failing() -> Self {
        Self {
            rate: Mutex::new(Err(FeeSourceError::NoEstimate)),
        }
    }
}
#[async_trait]
impl FeeSource for FakeFeeSource {
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
        self.rate.lock().unwrap().clone()
    }
}

/// A lease that appends its outpoints to a shared log when it drops.
///
/// The tests read that log to make sure that each path which stops the bumps returns the
/// funding inputs of the last child. A production lease returns them to the wallet. This
/// one records the same event.
#[derive(Debug)]
pub(super) struct FakeLease {
    pub(super) inputs: Vec<FundingInput>,
    pub(super) lease: Lease,
    pub(super) released: Arc<Mutex<Vec<OutPoint>>>,
}
impl FundingLease for FakeLease {
    fn inputs(&self) -> &[FundingInput] {
        &self.inputs
    }

    fn lease(&self) -> &Lease {
        &self.lease
    }
}
impl Drop for FakeLease {
    fn drop(&mut self) {
        self.released
            .lock()
            .unwrap()
            .extend(self.inputs.iter().map(|input| input.outpoint));
    }
}

/// What the ladder passed to one build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordedBuild {
    pub(super) target: FeeRate,
    pub(super) inputs: Vec<OutPoint>,
    pub(super) incumbent: Option<IncumbentChild>,
}

#[derive(Debug)]
pub(super) struct FakeWallet {
    pub(super) psbt_template: Mutex<Option<Psbt>>,
    pub(super) spent_template: Vec<OutPoint>,
    pub(super) error: Option<CpfpWalletError>,
    /// Every build the ladder asked for, in call order.
    pub(super) builds: Mutex<Vec<RecordedBuild>>,
    /// Outpoints of every lease that has dropped, in drop order.
    pub(super) released: Arc<Mutex<Vec<OutPoint>>>,
    /// The witness that the signer returns for each input it signs. Empty means that the
    /// signer holds no key.
    pub(super) signer_witnesses: Vec<(usize, Witness)>,
    /// Inputs that the ladder asked the signer to sign, per call.
    pub(super) sign_requests: Mutex<Vec<Vec<usize>>>,
    /// Error that the wallet signer reports, when set.
    pub(super) sign_error: Option<SignerError>,
    /// Whether the inputs of a child read as this wallet's own.
    pub(super) owns_children: bool,
    /// Whether the signer answers for one input too few.
    pub(super) drops_a_signature: bool,
    /// How many refreshes the ladder asked for.
    pub(super) refreshes: Mutex<usize>,
}
impl FakeWallet {
    pub(super) fn with(
        psbt: Option<Psbt>,
        spent: Vec<OutPoint>,
        error: Option<CpfpWalletError>,
    ) -> Self {
        Self {
            psbt_template: Mutex::new(psbt),
            spent_template: spent,
            error,
            builds: Mutex::new(Vec::new()),
            released: Arc::new(Mutex::new(Vec::new())),
            signer_witnesses: Vec::new(),
            sign_requests: Mutex::new(Vec::new()),
            sign_error: None,
            owns_children: false,
            drops_a_signature: false,
            refreshes: Mutex::new(0),
        }
    }
    pub(super) fn returning(psbt: Psbt, spent: Vec<OutPoint>) -> Self {
        Self::with(Some(psbt), spent, None)
    }
    pub(super) fn failing(msg: &str) -> Self {
        Self::with(
            None,
            Vec::new(),
            Some(CpfpWalletError::Transient(msg.to_string())),
        )
    }

    /// A wallet that reports a parent which can never carry a child.
    pub(super) fn unbumpable(msg: &str) -> Self {
        Self::with(
            None,
            Vec::new(),
            Some(CpfpWalletError::Unbumpable(msg.to_string())),
        )
    }

    /// A wallet that refuses a replacement above the cap.
    pub(super) fn above_cap() -> Self {
        Self::with(
            None,
            Vec::new(),
            Some(CpfpWalletError::AboveCap {
                needed: Amount::from_sat(2),
                ceiling: Amount::from_sat(1),
            }),
        )
    }

    /// The package rate of the last build.
    pub(super) fn target(&self) -> Option<FeeRate> {
        self.last_build().map(|build| build.target)
    }

    /// What the ladder passed to the last build.
    pub(super) fn last_build(&self) -> Option<RecordedBuild> {
        self.builds.lock().unwrap().last().cloned()
    }

    /// Builds a lease over `outpoints` that reports its own drop to this wallet.
    pub(super) fn lease(&self, outpoints: Vec<OutPoint>) -> Arc<dyn FundingLease> {
        Arc::new(FakeLease {
            inputs: outpoints
                .into_iter()
                .map(|outpoint| FundingInput {
                    outpoint,
                    txout: TxOut::NULL,
                })
                .collect(),
            lease: empty_lease(),
            released: Arc::clone(&self.released),
        })
    }
}
#[async_trait]
impl CpfpWallet for FakeWallet {
    async fn build_cpfp_child(
        &self,
        _parent: &Transaction,
        _strategy: &CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        _max_package_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<WalletFundedPsbt, CpfpWalletError> {
        self.builds.lock().unwrap().push(RecordedBuild {
            target: target_pkg_fee_rate,
            inputs: replaced
                .prior
                .iter()
                .flat_map(|child| child.inputs)
                .map(|i| i.outpoint)
                .collect(),
            incumbent: replaced.incumbent,
        });
        if let Some(e) = &self.error {
            return Err(match e {
                CpfpWalletError::Unbumpable(m) => CpfpWalletError::Unbumpable(m.clone()),
                CpfpWalletError::AboveCap { needed, ceiling } => CpfpWalletError::AboveCap {
                    needed: *needed,
                    ceiling: *ceiling,
                },
                CpfpWalletError::Transient(m) => CpfpWalletError::Transient(m.clone()),
            });
        }
        let psbt = self.psbt_template.lock().unwrap().clone();
        Ok(WalletFundedPsbt {
            psbt: psbt.expect("test must seed a psbt template"),
            lease: self.lease(self.spent_template.clone()),
        })
    }

    async fn adopt_child(
        &self,
        _parent: Txid,
        inputs: Vec<FundingInput>,
    ) -> Option<Arc<dyn FundingLease>> {
        self.owns_children
            .then(|| self.lease(inputs.into_iter().map(|i| i.outpoint).collect()))
    }

    async fn refresh(&self) -> Result<(), CpfpWalletError> {
        *self.refreshes.lock().unwrap() += 1;
        Ok(())
    }

    async fn sign_owned_inputs(
        &self,
        _tx: &Transaction,
        input_indices: &[usize],
        _prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, SignerError> {
        self.sign_requests
            .lock()
            .unwrap()
            .push(input_indices.to_vec());
        if let Some(e) = &self.sign_error {
            return Err(e.clone());
        }
        let answered = input_indices.len() - usize::from(self.drops_a_signature);
        Ok(input_indices[..answered]
            .iter()
            .map(|index| {
                self.signer_witnesses
                    .iter()
                    .find(|(signed, _)| signed == index)
                    .map(|(_, witness)| witness.clone())
            })
            .collect())
    }
}

/// How a [`FakeMempool`] answers a submission.
#[derive(Debug, Clone)]
pub(super) enum SubmitResult {
    Accepted,
    Rejected(String),
    /// The RPC call failed, so the result is unknown.
    Unknown,
}

#[derive(Debug)]
pub(super) struct FakeMempool {
    pub(super) result: Mutex<SubmitResult>,
    /// Per-tx error strings attached to a rejection.
    pub(super) tx_errors: Mutex<Vec<(Txid, String)>>,
    pub(super) captured: Mutex<Vec<Vec<Transaction>>>,
    pub(super) parent_probe: Mutex<ParentProbe>,
    /// Error the probe reports, when set.
    pub(super) probe_error: Mutex<Option<String>>,
    /// Whether a lookup of the inputs of a child fails.
    pub(super) inputs_fail: bool,
    /// The answer of [`CpfpMempool::min_fee_rate`]. `None` fails the call.
    pub(super) min_fee_rate: Option<FeeRate>,
    /// How often the ladder read the minimum.
    pub(super) min_fee_reads: Mutex<u32>,
}
impl FakeMempool {
    pub(super) fn with_result(result: SubmitResult) -> Self {
        Self {
            result: Mutex::new(result),
            tx_errors: Mutex::new(Vec::new()),
            captured: Mutex::new(Vec::new()),
            parent_probe: Mutex::new(ParentProbe::NoChild),
            probe_error: Mutex::new(None),
            inputs_fail: false,
            min_fee_rate: Some(FeeRate::ZERO),
            min_fee_reads: Mutex::new(0),
        }
    }
    pub(super) fn ok() -> Self {
        Self::with_result(SubmitResult::Accepted)
    }
    pub(super) fn failing(reason: &str) -> Self {
        Self::with_result(SubmitResult::Rejected(reason.to_string()))
    }
    pub(super) fn with_probe(self, probe: ParentProbe) -> Self {
        *self.parent_probe.lock().unwrap() = probe;
        self
    }
    /// Sets what later probes report.
    pub(super) fn report(&self, probe: ParentProbe) {
        *self.parent_probe.lock().unwrap() = probe;
    }
    /// Makes the probe fail, so a test exercises the build-on-probe-error path.
    pub(super) fn with_failing_probe(self, reason: &str) -> Self {
        *self.probe_error.lock().unwrap() = Some(reason.to_string());
        self
    }
    /// How many packages reached this fake.
    pub(super) fn submissions(&self) -> usize {
        self.captured.lock().unwrap().len()
    }
    /// Attaches a per-tx error string to the rejection that this fake reports.
    pub(super) fn with_tx_error(self, txid: Txid, err: &str) -> Self {
        self.tx_errors.lock().unwrap().push((txid, err.to_string()));
        self
    }
}
#[async_trait]
impl CpfpMempool for FakeMempool {
    async fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> Result<SubmitPackageSummary, SubmitPackageError> {
        self.captured.lock().unwrap().push(txs.to_vec());
        match self.result.lock().unwrap().clone() {
            SubmitResult::Accepted => Ok(SubmitPackageSummary {
                replaced: Vec::new(),
            }),
            SubmitResult::Rejected(message) => Err(SubmitPackageError::Rejected {
                message,
                tx_errors: self.tx_errors.lock().unwrap().clone(),
            }),
            SubmitResult::Unknown => Err(SubmitPackageError::Rpc(ClientError::Timeout)),
        }
    }

    /// Reports the configured probe, or the configured probe error. The default is a parent
    /// with no child, so tests exercise the build path.
    async fn probe(&self, _parent: Txid) -> Result<ParentProbe, MempoolError> {
        if let Some(err) = self.probe_error.lock().unwrap().clone() {
            return Err(MempoolError(err));
        }
        Ok(*self.parent_probe.lock().unwrap())
    }

    async fn child_inputs(&self, _child: Txid) -> Result<Vec<FundingInput>, MempoolError> {
        if self.inputs_fail {
            return Err(MempoolError("child lookup failed".to_string()));
        }
        Ok(vec![FundingInput {
            outpoint: OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0),
            txout: TxOut::NULL,
        }])
    }

    async fn min_fee_rate(&self) -> Result<FeeRate, MempoolError> {
        *self.min_fee_reads.lock().unwrap() += 1;
        self.min_fee_rate
            .ok_or_else(|| MempoolError("no minimum".to_string()))
    }
}

pub(super) fn fake_input_signer_ok() -> InputSigner {
    Arc::new(|_msg: Message| {
        Box::pin(async move {
            // Schnorr signature is 64 bytes; bytes don't have to verify for unit tests of
            // the bump-loop control flow.
            let sig = Signature::from_slice(&[7u8; 64]).expect("64 bytes is a valid sig");
            Ok::<_, SignerError>(sig)
        })
    })
}

pub(super) fn fake_input_signer_failing(message: &'static str) -> InputSigner {
    Arc::new(move |_msg: Message| {
        let m = message.to_string();
        Box::pin(async move { Err(SignerError(m)) })
    })
}

/// Runs one attempt and reads its result.
pub(super) async fn run_bump(
    ctx: &CpfpContext,
    parent: &Transaction,
    strategy: &CpfpStrategy,
    handle: &mut CpfpHandle,
) -> Result<BumpOutcome, CpfpError> {
    perform_bump(ctx, parent, strategy, handle).await.outcome()
}

// ── Test fixtures ────────────────────────────────────────────────────────

pub(super) fn test_keypair_and_xonly() -> (Keypair, XOnlyPublicKey) {
    let kp = Keypair::from_seckey_slice(SECP256K1, &[5u8; 32]).unwrap();
    let (x, _parity) = kp.x_only_public_key();
    (kp, x)
}

/// Build a synthetic parent with a keyed-Taproot anchor at vout 0.
pub(super) fn synthetic_parent(
    anchor_internal_key: XOnlyPublicKey,
    anchor_value: Amount,
) -> Transaction {
    let addr = Address::p2tr(SECP256K1, anchor_internal_key, None, Network::Regtest);
    Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: anchor_value,
            script_pubkey: addr.script_pubkey(),
        }],
    }
}

/// Build a synthetic child PSBT with the right shape: anchor input + funding input + change.
/// Inputs carry only `witness_utxo`; `perform_bump` is responsible for signing both inputs
/// via its caller-provided signers.
pub(super) fn synthetic_child_psbt(parent: &Transaction, anchor_vout: u32) -> Psbt {
    let anchor_outpoint = OutPoint {
        txid: parent.compute_txid(),
        vout: anchor_vout,
    };
    let funding_outpoint = OutPoint {
        txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
        vout: 0,
    };
    let wallet_script = Address::p2tr(
        SECP256K1,
        test_keypair_and_xonly().1,
        None,
        Network::Regtest,
    )
    .script_pubkey();
    let child_tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: anchor_outpoint,
                ..Default::default()
            },
            TxIn {
                previous_output: funding_outpoint,
                ..Default::default()
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(49_500),
            script_pubkey: wallet_script.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(child_tx).expect("unsigned tx must convert");
    psbt.inputs[0].witness_utxo = Some(parent.output[anchor_vout as usize].clone());
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: wallet_script,
    });
    psbt
}

/// Build a synthetic child PSBT for an owned spend: parent output + funding input + change.
/// Both inputs carry only `witness_utxo`; `perform_bump` signs them via
/// `wallet_input_signer`.
pub(super) fn owned_output_child_psbt(
    payout_outpoint: OutPoint,
    wallet_script: bitcoin::ScriptBuf,
) -> Psbt {
    let funding_outpoint = OutPoint {
        txid: bitcoin::Txid::from_slice(&[2u8; 32]).unwrap(),
        vout: 0,
    };
    let child_tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: payout_outpoint,
                ..Default::default()
            },
            TxIn {
                previous_output: funding_outpoint,
                ..Default::default()
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: wallet_script.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(child_tx).expect("unsigned tx must convert");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: wallet_script.clone(),
    });
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: wallet_script,
    });
    psbt
}

pub(super) fn context(
    fee_source: Arc<dyn FeeSource>,
    wallet: Arc<dyn CpfpWallet>,
    mempool: Arc<dyn CpfpMempool>,
    anchor_signer: InputSigner,
    wallet_signer: InputSigner,
    max_fee_rate: FeeRate,
) -> CpfpContext {
    CpfpContext {
        wallet,
        fee_source,
        multi_anchor_signer: anchor_signer.clone(),
        anchor_input_signer: anchor_signer,
        wallet_input_signer: wallet_signer,
        // Neutral fee settings: the premium and floor stay off, so that the target is the raw
        // estimate. The fee-setting tests build their own context.
        policy: FeeTargetPolicy {
            premium_percent: 0,
            min_package_fee_rate: FeeRate::ZERO,
            max_fee_rate,
        },
        mempool,
    }
}

/// A probe that reports a child of 200 vB that pays 500 sat, in a package at `rate`.
pub(super) fn child_at(txid: Txid, rate: FeeRate) -> ParentProbe {
    ParentProbe::Child(MempoolChild {
        txid,
        fee: Amount::from_sat(500),
        vbytes: NonZeroU64::new(200).unwrap(),
        pkg_fee_rate: rate,
    })
}

pub(super) fn seeded_handle(
    wallet: &FakeWallet,
    inputs: &[OutPoint],
    our_child: Txid,
) -> CpfpHandle {
    CpfpHandle {
        accepted: Some(HeldChild {
            txid: our_child,
            lease: wallet.lease(inputs.to_vec()),
        }),
        ..CpfpHandle::default()
    }
}
