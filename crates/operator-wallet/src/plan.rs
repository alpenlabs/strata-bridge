//! Pure transaction planning for the general wallet.
//!
//! Every function here reads only its arguments, so the wallet and the tests run one body.
//! The caller decides which outputs are candidates. This module decides which of them a
//! transaction spends, what it pays, and how the unsigned transaction looks.
//!
//! Input size comes from [`InputWeightPrediction`], so the planned fee matches the signed
//! transaction for every script type a custody holds.

use std::{cmp::Reverse, iter, num::NonZeroU64};

use bdk_wallet::{
    bitcoin::{
        absolute::LockTime,
        consensus::serialize,
        psbt,
        transaction::{predict_weight, InputWeightPrediction, Version},
        Amount, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Weight, Witness,
    },
    coin_selection::{
        BranchAndBoundCoinSelection, CoinSelectionAlgorithm, InsufficientFunds, SingleRandomDraw,
    },
    Utxo, WeightedUtxo,
};

/// An output that a transaction spends, and everything a plan needs to know about it.
///
/// This type has no confirmation count: the count has no meaning for the output of an unbroadcast
/// parent or for a stored input of a replaced child, and the caller filters on it before a plan
/// starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingInput {
    /// The output.
    pub outpoint: OutPoint,
    /// Its value and script.
    pub txout: TxOut,
}

/// Fee that a replacement child adds per vbyte on top of the fee it replaces. A node with a higher
/// `incrementalfee` rejects a small replacement, so startup checks the node against this value.
pub const REPLACEMENT_INCREMENT_SAT_PER_VB: u64 = 1;

/// BIP-431 caps a v3 transaction that has an unconfirmed v3 ancestor at this size. A CPFP child
/// always has one: the parent it pays for.
const TRUC_CHILD_MAX_VBYTES: u64 = 1000;

/// The candidates cannot pay for the planned transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Shortfall {
    /// Value of the inputs that the planner reached.
    pub(crate) available: Amount,
    /// Value those inputs must reach for the transaction to work.
    pub(crate) needed: Amount,
}

/// Why a CPFP child cannot be planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildPlanError {
    /// The candidates cannot pay for the child.
    Shortfall(Shortfall),
    /// The child is past the TRUC size limit before it takes any funding. The spend of the parent
    /// output decides that size, and a signed parent does not change.
    TooLarge {
        /// Size of the child with no funding.
        vbytes: u64,
    },
    /// The package passes the cap.
    AboveCap {
        /// Fee of the (parent, child) package with the replacement.
        needed: Amount,
        /// Most that the package may pay at its size.
        ceiling: Amount,
    },
}

/// The live child that a new child must replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncumbentChild {
    /// Absolute fee of the live child.
    pub fee: Amount,
    /// Size of the live child.
    pub vbytes: NonZeroU64,
}

impl IncumbentChild {
    /// Lowest fee that a child of `vbytes` needs to replace this child.
    ///
    /// BIP-125 rule 4 asks for this fee plus [`REPLACEMENT_INCREMENT_SAT_PER_VB`] over the new
    /// child. Bitcoin Core before v31 also asks for an own fee rate above that of the replaced
    /// child (rule 6). That second bound binds when the new child is the larger of the two.
    fn replacement_floor(&self, vbytes: u64) -> u64 {
        let fee = self.fee.to_sat();
        let same_rate = u128::from(fee) * u128::from(vbytes) / u128::from(self.vbytes.get());
        let rule_6 = u64::try_from(same_rate + 1).unwrap_or(u64::MAX);
        fee.saturating_add(vbytes.saturating_mul(REPLACEMENT_INCREMENT_SAT_PER_VB))
            .max(rule_6)
    }
}

/// What a CPFP child must do.
#[derive(Debug)]
pub(crate) struct ChildRequest<'a> {
    /// Size of the parent.
    pub(crate) parent_vbytes: u64,
    /// Fee that the parent pays.
    pub(crate) parent_fee: Amount,
    /// Fee rate that the (parent, child) package must reach.
    pub(crate) target: FeeRate,
    /// Fee rate that the (parent, child) package must not pass.
    pub(crate) max_package_rate: FeeRate,
    /// The live child that this child replaces, when there is one.
    pub(crate) incumbent: Option<IncumbentChild>,
    /// Value of the parent output that the child spends.
    pub(crate) spent_value: Amount,
    /// Size of the input that spends the parent output.
    pub(crate) spent_input: InputWeightPrediction,
    /// Size of one wallet input.
    pub(crate) wallet_input: InputWeightPrediction,
    /// Script of the single output of the child.
    pub(crate) drain_script: &'a Script,
}

impl ChildRequest<'_> {
    /// Size of the signed child with `n_funding` wallet inputs.
    fn vbytes(&self, n_funding: usize) -> u64 {
        let inputs =
            iter::once(self.spent_input).chain(iter::repeat_n(self.wallet_input, n_funding));
        predict_weight(inputs, [self.drain_script.len()]).to_vbytes_ceil()
    }

    /// Fee of the child with `n_funding` wallet inputs.
    ///
    /// Three floors apply. The package shortfall lifts the package to the target. The vbytes
    /// floor keeps the child relayable on its own at 1 sat/vB, ten times Core's default
    /// `minrelaytxfee`, so older peers relay it too. The replacement floor is what the incumbent
    /// asks for, see [`IncumbentChild::replacement_floor`].
    fn fee(&self, n_funding: usize) -> Amount {
        let vbytes = self.vbytes(n_funding);
        let shortfall = self
            .package_fee_at(self.target, n_funding)
            .saturating_sub(self.parent_fee.to_sat());
        let replacement_floor = self
            .incumbent
            .map_or(0, |incumbent| incumbent.replacement_floor(vbytes));
        Amount::from_sat(shortfall.max(vbytes).max(replacement_floor))
    }

    /// Fee in sats of the package with `n_funding` wallet inputs at `rate`.
    ///
    /// Rounds up. A fractional target that truncates pays under the target, and an underpaid
    /// package sits exactly on the acceptance boundary of the node.
    fn package_fee_at(&self, rate: FeeRate, n_funding: usize) -> u64 {
        let package_vbytes = self.parent_vbytes.saturating_add(self.vbytes(n_funding));
        rate.to_sat_per_kwu()
            .saturating_mul(package_vbytes.saturating_mul(4))
            .div_ceil(1000)
    }

    /// Refuses a child that lifts the package past the cap.
    fn check_cap(&self, n_funding: usize) -> Result<(), ChildPlanError> {
        let needed = saturating_sum(self.parent_fee, self.fee(n_funding));
        let ceiling = Amount::from_sat(self.package_fee_at(self.max_package_rate, n_funding));
        if needed > ceiling {
            return Err(ChildPlanError::AboveCap { needed, ceiling });
        }
        Ok(())
    }

    /// Value of the child output with `n_funding` wallet inputs worth `funding_total`, or `None`
    /// when that output does not clear dust.
    fn drain(&self, n_funding: usize, funding_total: Amount) -> Option<Amount> {
        self.spent_value
            .checked_add(funding_total)?
            .checked_sub(self.fee(n_funding))
            .filter(|drain| *drain >= self.drain_script.minimal_non_dust())
    }
}

/// The inputs of a CPFP child and the value of its output. The fee is what the inputs leave.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ChildPlan {
    /// Wallet inputs, in addition to the parent output. Empty when the parent output pays for
    /// the child alone.
    pub(crate) funding: Vec<FundingInput>,
    /// Value of the single output of the child.
    pub(crate) drain: Amount,
}

/// Plans a CPFP child from `candidates`.
///
/// The child's fee depends on its size and its size depends on its input count, so the input
/// count is fixed first and the fee follows from the exact size. The parent output alone is
/// tried first. See [`select`] for the funding order.
///
/// The child stays inside the TRUC size limit. A child past it cannot enter any mempool, so a
/// shortfall is the better outcome when the funding is what the limit stops.
///
/// The cap outranks a shortfall: funds cannot make a child above the cap possible.
pub(crate) fn plan_child(
    request: &ChildRequest<'_>,
    candidates: Vec<FundingInput>,
) -> Result<ChildPlan, ChildPlanError> {
    let vbytes = request.vbytes(0);
    if vbytes > TRUC_CHILD_MAX_VBYTES {
        return Err(ChildPlanError::TooLarge { vbytes });
    }
    let plan = match request.drain(0, Amount::ZERO) {
        Some(drain) => ChildPlan {
            funding: Vec::new(),
            drain,
        },
        None => {
            let max_inputs = (1..)
                .take_while(|n_funding| request.vbytes(*n_funding) <= TRUC_CHILD_MAX_VBYTES)
                .count();
            let (funding, drain) = select(candidates, max_inputs, |n_funding, total| {
                request.drain(n_funding, total)
            })
            .map_err(|(n_funding, total)| {
                request.check_cap(n_funding).err().unwrap_or_else(|| {
                    ChildPlanError::Shortfall(Shortfall {
                        available: saturating_sum(request.spent_value, total),
                        needed: saturating_sum(
                            request.fee(n_funding),
                            request.drain_script.minimal_non_dust(),
                        ),
                    })
                })
            })?;
            ChildPlan { funding, drain }
        }
    };
    request.check_cap(plan.funding.len())?;
    Ok(plan)
}

/// Keeps the outputs of `inputs` that pay `script`.
pub(crate) fn owned_by(inputs: Vec<FundingInput>, script: &Script) -> Vec<FundingInput> {
    inputs
        .into_iter()
        .filter(|input| input.txout.script_pubkey == *script)
        .collect()
}

/// What a funded transaction must pay.
#[derive(Debug)]
pub(crate) struct FundingRequest<'a> {
    /// Recipient outputs, which keep their order and come first.
    pub(crate) outputs: &'a [TxOut],
    /// Script of the change output.
    pub(crate) change_script: &'a Script,
    /// Fee rate of the transaction.
    pub(crate) fee_rate: FeeRate,
    /// Size of one wallet input.
    pub(crate) wallet_input: InputWeightPrediction,
}

impl FundingRequest<'_> {
    fn recipient_total(&self) -> Amount {
        self.outputs.iter().map(|output| output.value).sum()
    }

    fn weight(&self, n_inputs: usize, with_change: bool) -> Weight {
        let outputs = self
            .outputs
            .iter()
            .map(|output| output.script_pubkey.len())
            .chain(with_change.then_some(self.change_script.len()));
        predict_weight(iter::repeat_n(self.wallet_input, n_inputs), outputs)
    }

    fn fee(&self, n_inputs: usize, with_change: bool) -> Amount {
        self.fee_rate
            .fee_wu(self.weight(n_inputs, with_change))
            .unwrap_or(Amount::MAX)
    }

    /// The fee of the transaction header and the recipient outputs, which is what bdk_wallet's
    /// coin selection takes in its target. The two weight units are the segwit marker and flag,
    /// which [`predict_weight`] counts only once an input exists.
    fn base_fee(&self) -> Amount {
        self.fee_rate
            .fee_wu(self.weight(0, false) + Weight::from_wu(2))
            .unwrap_or(Amount::MAX)
    }

    /// The fee of the change output alone, as bdk_wallet's coin selection prices it.
    fn change_fee(&self) -> Amount {
        let vbytes = (serialize(self.change_script).len() + 8) as u64;
        self.fee_rate.fee_vb(vbytes).unwrap_or(Amount::MAX)
    }

    /// `input` as bdk_wallet's coin selection reads it. The selection adds the 41-byte base of
    /// an input itself, and [`InputWeightPrediction::weight`] counts only the script and the
    /// witness, so the prediction is the satisfaction weight. The four weight units of the
    /// script-length byte are counted twice, which prices an input high and not low.
    fn weighted(&self, input: &FundingInput) -> WeightedUtxo {
        WeightedUtxo {
            satisfaction_weight: self.wallet_input.weight(),
            utxo: Utxo::Foreign {
                outpoint: input.outpoint,
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                psbt_input: Box::new(psbt::Input {
                    witness_utxo: Some(input.txout.clone()),
                    ..Default::default()
                }),
            },
        }
    }

    /// Runs `algorithm` over `candidates` for `target`, and returns the chosen candidates.
    fn select_with(
        &self,
        algorithm: &impl CoinSelectionAlgorithm,
        candidates: &[FundingInput],
        target: Amount,
    ) -> Result<Vec<FundingInput>, InsufficientFunds> {
        let weighted = candidates
            .iter()
            .map(|input| self.weighted(input))
            .collect();
        let result = algorithm.coin_select(
            Vec::new(),
            weighted,
            self.fee_rate,
            target,
            self.change_script,
            &mut rand::thread_rng(),
        )?;
        Ok(result
            .selected
            .iter()
            .filter_map(|utxo| {
                candidates
                    .iter()
                    .find(|input| input.outpoint == utxo.outpoint())
                    .cloned()
            })
            .collect())
    }

    /// The change of a transaction with `n_inputs` inputs worth `total`. The outer `None` means
    /// that the inputs do not pay for the transaction. The inner `None` means that the remainder
    /// is below dust, so it joins the fee.
    fn change(&self, n_inputs: usize, total: Amount) -> Option<Option<Amount>> {
        let remainder = total.checked_sub(self.recipient_total())?;
        let change = remainder
            .checked_sub(self.fee(n_inputs, true))
            .filter(|change| *change >= self.change_script.minimal_non_dust());
        if change.is_some() {
            return Some(change);
        }
        (remainder >= self.fee(n_inputs, false)).then_some(None)
    }

    fn shortfall(&self, n_inputs: usize, total: Amount) -> Shortfall {
        Shortfall {
            available: total,
            needed: saturating_sum(self.recipient_total(), self.fee(n_inputs, false)),
        }
    }
}

/// The inputs of a funded transaction and its change.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FundingPlan {
    /// The inputs of the transaction.
    pub(crate) inputs: Vec<FundingInput>,
    /// Value of the change output. [`plan_funding`] always sets it. [`plan_explicit_funding`]
    /// leaves `None` when the given inputs leave a remainder below dust, which joins the fee.
    pub(crate) change: Option<Amount>,
}

/// Plans a transaction that pays `request` from `candidates`.
///
/// Selection is bdk_wallet's [`BranchAndBoundCoinSelection`] with [`SingleRandomDraw`] as its
/// fallback, which is what the bdk_wallet transaction builder runs by default.
///
/// The transaction always has a change output, because the change output is the bump path of a
/// funded transaction. When the first selection leaves a remainder below dust, a second selection
/// with [`SingleRandomDraw`] adds a change output at the dust limit, and its fee, to the target.
/// Candidates that cannot pay for that are a [`Shortfall`].
pub(crate) fn plan_funding(
    request: &FundingRequest<'_>,
    candidates: Vec<FundingInput>,
) -> Result<FundingPlan, Shortfall> {
    let shortfall = |short: InsufficientFunds| Shortfall {
        available: short.available,
        needed: short.needed,
    };
    let planned = |inputs: Vec<FundingInput>| {
        let total = inputs.iter().map(|input| input.txout.value).sum();
        match request.change(inputs.len(), total) {
            Some(Some(change)) => Ok(FundingPlan {
                inputs,
                change: Some(change),
            }),
            _ => Err((inputs.len(), total)),
        }
    };

    // `bitcoin_units::FeeRate: Mul<Weight>` panics on overflow, and bdk_wallet's coin selection
    // multiplies the rate by each input weight (`OutputGroup::new`), so a rate that saturates the
    // fee of the whole transaction stops here and reports.
    if request.fee(candidates.len(), true) == Amount::MAX {
        return Err(Shortfall {
            available: candidates.iter().map(|input| input.txout.value).sum(),
            needed: Amount::MAX,
        });
    }

    let target = saturating_sum(request.recipient_total(), request.base_fee());
    let change_size = (serialize(request.change_script).len() + 8) as u64;
    let bnb = BranchAndBoundCoinSelection::new(change_size, SingleRandomDraw);
    let inputs = request
        .select_with(&bnb, &candidates, target)
        .map_err(shortfall)?;
    let (n_inputs, total) = match planned(inputs) {
        Ok(plan) => return Ok(plan),
        Err(reached) => reached,
    };

    let with_change = saturating_sum(
        target,
        saturating_sum(
            request.change_script.minimal_non_dust(),
            request.change_fee(),
        ),
    );
    let (n_inputs, total) = match request.select_with(&SingleRandomDraw, &candidates, with_change) {
        Ok(inputs) => match planned(inputs) {
            Ok(plan) => return Ok(plan),
            Err(reached) => reached,
        },
        Err(_) => (n_inputs, total),
    };
    Err(Shortfall {
        available: total,
        needed: saturating_sum(
            saturating_sum(request.recipient_total(), request.fee(n_inputs, true)),
            request.change_script.minimal_non_dust(),
        ),
    })
}

/// Plans a transaction that pays `request` from exactly `inputs`.
pub(crate) fn plan_explicit_funding(
    request: &FundingRequest<'_>,
    inputs: Vec<FundingInput>,
) -> Result<FundingPlan, Shortfall> {
    let total = inputs.iter().map(|input| input.txout.value).sum();
    match request.change(inputs.len(), total) {
        Some(change) => Ok(FundingPlan { inputs, change }),
        None => Err(request.shortfall(inputs.len(), total)),
    }
}

/// `a + b`, or [`Amount::MAX`] on overflow. A fee saturates at that value when the rate is out of
/// range, and a shortfall report must still build.
fn saturating_sum(a: Amount, b: Amount) -> Amount {
    a.checked_add(b).unwrap_or(Amount::MAX)
}

/// Picks inputs from `candidates` so that `fit` accepts them.
///
/// `fit` takes an input count and the total value of those inputs. The order is:
///
/// 1. The smallest single candidate that fits. One input keeps the transaction small, and the
///    smallest fit leaves large outputs for the transactions that need them.
/// 2. Otherwise candidates largest first, until they fit or `max_inputs` stops them. Largest first
///    keeps the input count down.
///
/// Equal values tie-break by outpoint, so the choice does not depend on the order of
/// `candidates`. An unchanged request therefore rebuilds the same transaction, and the node
/// deduplicates a resubmission by txid.
///
/// The error carries the input count and the value that the walk reached.
fn select<T>(
    mut candidates: Vec<FundingInput>,
    max_inputs: usize,
    fit: impl Fn(usize, Amount) -> Option<T>,
) -> Result<(Vec<FundingInput>, T), (usize, Amount)> {
    if max_inputs == 0 {
        return Err((0, Amount::ZERO));
    }
    candidates.sort_by_key(|candidate| (candidate.txout.value, candidate.outpoint));
    let single = candidates
        .iter()
        .position(|candidate| fit(1, candidate.txout.value).is_some());
    if let Some(index) = single {
        let chosen = candidates.swap_remove(index);
        let fitted = fit(1, chosen.txout.value).expect("this candidate fit above");
        return Ok((vec![chosen], fitted));
    }

    candidates.sort_by_key(|candidate| (Reverse(candidate.txout.value), candidate.outpoint));
    let mut chosen = Vec::new();
    let mut total = Amount::ZERO;
    for candidate in candidates.into_iter().take(max_inputs) {
        // The values of real outputs cannot sum past the supply, which `Amount` holds.
        total += candidate.txout.value;
        chosen.push(candidate);
        if let Some(fitted) = fit(chosen.len(), total) {
            return Ok((chosen, fitted));
        }
    }
    Err((chosen.len(), total))
}

/// Builds the unsigned v3 PSBT that spends `inputs` and pays `outputs`.
///
/// Every input carries `witness_utxo`, which is what a signer and [`Psbt::fee`] read. A funded
/// transaction takes the tip height as `lock_time`, as BDK does. A child takes zero: a locktime
/// that follows the tip moves the txid on every block, and a new block is the most common reason
/// to rebuild a child.
pub(crate) fn unsigned_psbt(
    inputs: &[FundingInput],
    outputs: Vec<TxOut>,
    lock_time: LockTime,
) -> Psbt {
    let tx = Transaction {
        version: Version(3),
        lock_time,
        input: inputs
            .iter()
            .map(|input| TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("inputs carry no script or witness");
    for (psbt_input, input) in psbt.inputs.iter_mut().zip(inputs) {
        psbt_input.witness_utxo = Some(input.txout.clone());
    }
    psbt
}

/// The outpoints of `inputs`.
pub(crate) fn outpoints(inputs: &[FundingInput]) -> Vec<OutPoint> {
    inputs.iter().map(|input| input.outpoint).collect()
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::{hashes::Hash, Txid};

    use super::*;

    /// A P2WPKH script.
    fn wpkh() -> ScriptBuf {
        ScriptBuf::from_hex("00140000000000000000000000000000000000000001").unwrap()
    }

    fn input(sats: u64, seed: u8) -> FundingInput {
        FundingInput {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: wpkh(),
            },
        }
    }

    fn pays(sats: u64) -> Vec<TxOut> {
        vec![TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: wpkh(),
        }]
    }

    fn funding<'a>(outputs: &'a [TxOut], change_script: &'a Script) -> FundingRequest<'a> {
        FundingRequest {
            outputs,
            change_script,
            fee_rate: FeeRate::from_sat_per_vb(2).unwrap(),
            wallet_input: InputWeightPrediction::P2WPKH_MAX,
        }
    }

    /// A child of a 150 vB zero-fee parent, spending an output of `spent_sat` that pays the
    /// wallet's own P2WPKH script.
    fn child(spent_sat: u64, target_sat_vb: u64, drain_script: &Script) -> ChildRequest<'_> {
        ChildRequest {
            parent_vbytes: 150,
            parent_fee: Amount::ZERO,
            target: FeeRate::from_sat_per_vb(target_sat_vb).unwrap(),
            max_package_rate: FeeRate::from_sat_per_vb(1_000_000).unwrap(),
            incumbent: None,
            spent_value: Amount::from_sat(spent_sat),
            spent_input: InputWeightPrediction::P2WPKH_MAX,
            wallet_input: InputWeightPrediction::P2WPKH_MAX,
            drain_script,
        }
    }

    #[test]
    fn a_covering_candidate_funds_alone_and_pays_change() {
        let spk = wpkh();
        let outputs = pays(40_000);
        let request = funding(&outputs, &spk);
        let candidates = vec![input(100_000, 1)];
        let plan = plan_funding(&request, candidates.clone()).expect("selection succeeds");
        assert_eq!(plan.inputs.len(), 1);
        assert_funded(&request, &candidates, &plan);
    }

    #[test]
    fn a_child_takes_the_smallest_output_that_pays_alone() {
        let spk = wpkh();
        let candidates = vec![input(1_000_000, 1), input(9_000, 2), input(1_500, 3)];
        let plan = plan_child(&child(330, 20, &spk), candidates).expect("funded");
        assert_eq!(outpoints(&plan.funding), outpoints(&[input(9_000, 2)]));
    }

    /// The plan pays the recipients and the fee for its own shape, and its change clears dust.
    fn assert_funded(
        request: &FundingRequest<'_>,
        candidates: &[FundingInput],
        plan: &FundingPlan,
    ) {
        assert!(!plan.inputs.is_empty());
        for input in &plan.inputs {
            assert!(candidates.contains(input), "{input:?} is not a candidate");
        }
        let total: Amount = plan.inputs.iter().map(|input| input.txout.value).sum();
        let change = plan.change.expect("a funded transaction has change");
        assert!(change >= request.change_script.minimal_non_dust());
        assert_eq!(
            total,
            request.recipient_total() + request.fee(plan.inputs.len(), true) + change
        );
    }

    #[test]
    fn candidates_join_when_none_fits_alone() {
        let spk = wpkh();
        let outputs = pays(45_000);
        let request = funding(&outputs, &spk);
        let candidates = vec![input(10_000, 1), input(30_000, 2), input(30_000, 3)];
        let plan = plan_funding(&request, candidates.clone()).expect("selection succeeds");
        assert!(plan.inputs.len() >= 2);
        assert_funded(&request, &candidates, &plan);
    }

    #[test]
    fn a_shortfall_reports_what_the_candidates_hold() {
        let spk = wpkh();
        let outputs = pays(10_000);
        let shortfall = plan_funding(&funding(&outputs, &spk), vec![input(5_000, 3)]).unwrap_err();
        assert_eq!(shortfall.available, Amount::from_sat(5_000));
        assert!(shortfall.needed > Amount::from_sat(10_000));
    }

    /// An exact match leaves no change, and the change output is the bump path, so the plan
    /// passes it over for a selection with change.
    #[test]
    fn a_funded_transaction_always_has_change() {
        let spk = wpkh();
        let outputs = pays(40_000);
        let request = funding(&outputs, &spk);
        let exact = 40_000 + request.fee(1, false).to_sat();
        let candidates = vec![input(exact, 4), input(100_000, 5)];
        for _ in 0..20 {
            let plan = plan_funding(&request, candidates.clone()).expect("a candidate pays change");
            assert_funded(&request, &candidates, &plan);
        }
    }

    /// A candidate set that covers the recipients and the fee, but leaves a remainder below dust,
    /// cannot build a transaction with a change output.
    #[test]
    fn a_remainder_below_dust_is_a_shortfall() {
        let spk = wpkh();
        let outputs = pays(40_000);
        let request = funding(&outputs, &spk);
        let fee = request.fee(1, false).to_sat();
        let shortfall = plan_funding(&request, vec![input(40_000 + fee + 10, 4)]).unwrap_err();
        assert_eq!(shortfall.available, Amount::from_sat(40_000 + fee + 10));
        assert!(shortfall.needed > shortfall.available);
    }

    #[test]
    fn change_exactly_at_dust_is_kept() {
        let spk = wpkh();
        let outputs = pays(40_000);
        let request = funding(&outputs, &spk);
        let dust = spk.minimal_non_dust();
        let fee = request.fee(1, true).to_sat();
        let plan = plan_funding(&request, vec![input(40_000 + fee + dust.to_sat(), 5)])
            .expect("covers recipient + fee + dust change");
        assert_eq!(plan.change, Some(dust));
    }

    #[test]
    fn explicit_change_at_and_below_the_dust_boundary() {
        let spk = wpkh();
        let outputs = pays(40_000);
        let request = funding(&outputs, &spk);
        let dust = spk.minimal_non_dust();
        let fee = request.fee(1, true).to_sat();

        let at = plan_explicit_funding(&request, vec![input(40_000 + fee + dust.to_sat(), 1)])
            .expect("covers recipient + fee + dust");
        assert_eq!(at.change, Some(dust));

        let below =
            plan_explicit_funding(&request, vec![input(40_000 + fee + dust.to_sat() - 1, 2)])
                .expect("covers recipient + fee");
        assert_eq!(below.change, None, "the remainder joins the fee");
    }

    #[test]
    fn explicit_inputs_that_cannot_pay_are_a_shortfall() {
        let spk = wpkh();
        let outputs = pays(10_000);
        assert!(plan_explicit_funding(&funding(&outputs, &spk), vec![input(5_000, 1)]).is_err());
    }

    #[test]
    fn the_spent_output_alone_can_pay_for_the_child() {
        let spk = wpkh();
        let plan = plan_child(&child(100_000, 2, &spk), Vec::new())
            .expect("the spent output covers the fee");
        assert!(plan.funding.is_empty());
        assert!(plan.drain >= spk.minimal_non_dust());
    }

    #[test]
    fn a_short_spent_output_pulls_funding() {
        let spk = wpkh();
        let plan = plan_child(&child(400, 2, &spk), vec![input(50_000, 9)])
            .expect("a funding input covers the shortfall");
        assert_eq!(plan.funding.len(), 1);
        assert!(plan.drain >= spk.minimal_non_dust());
    }

    #[test]
    fn a_child_without_funding_is_a_shortfall() {
        let spk = wpkh();
        let Err(ChildPlanError::Shortfall(shortfall)) =
            plan_child(&child(330, 5, &spk), Vec::new())
        else {
            panic!("a child with no funding is short");
        };
        assert_eq!(shortfall.available, Amount::from_sat(330));
    }

    #[test]
    fn equal_value_child_funding_picks_the_lowest_outpoint() {
        let spk = wpkh();
        let plan = plan_child(
            &child(400, 2, &spk),
            vec![input(50_000, 9), input(50_000, 1)],
        )
        .expect("a funding input covers the shortfall");
        assert_eq!(outpoints(&plan.funding), outpoints(&[input(50_000, 1)]));
    }

    #[test]
    fn a_spend_past_the_truc_size_limit_is_too_large() {
        let spk = wpkh();
        let request = ChildRequest {
            spent_input: InputWeightPrediction::new(0, [4_200]),
            ..child(100_000_000, 2, &spk)
        };
        assert_eq!(
            plan_child(&request, vec![input(100_000_000, 1)]),
            Err(ChildPlanError::TooLarge {
                vbytes: request.vbytes(0)
            })
        );
    }

    /// The spend fits the limit, and a funding input would take it past the limit.
    #[test]
    fn a_child_at_the_size_limit_takes_no_funding() {
        let spk = wpkh();
        let request = ChildRequest {
            spent_input: InputWeightPrediction::new(0, [3_600]),
            ..child(400, 2, &spk)
        };
        assert!(request.vbytes(0) <= TRUC_CHILD_MAX_VBYTES);
        assert!(request.vbytes(1) > TRUC_CHILD_MAX_VBYTES);
        assert!(matches!(
            plan_child(&request, vec![input(100_000_000, 1)]),
            Err(ChildPlanError::Shortfall(_))
        ));
    }

    /// A wallet of dust cannot fund past the TRUC size limit, which roughly 14 P2WPKH inputs
    /// exceed. A single large output under the same demand builds, so the size bound is the only
    /// difference under test.
    #[test]
    fn child_funding_stops_at_the_truc_size_limit() {
        let spk = wpkh();
        let dust_wallet: Vec<FundingInput> = (0..40).map(|i| input(3_000, i)).collect();
        assert!(plan_child(&child(500, 500, &spk), dust_wallet).is_err());
        assert!(plan_child(&child(500, 500, &spk), vec![input(10_000_000, 1)]).is_ok());
    }

    /// A rate past the range of `Amount` saturates the fee. The shortfall still reports.
    #[test]
    fn a_shortfall_at_the_top_of_the_amount_range_still_reports() {
        let spk = wpkh();
        let outputs = pays(10_000);
        let request = FundingRequest {
            fee_rate: FeeRate::MAX,
            ..funding(&outputs, &spk)
        };
        let shortfall = plan_funding(&request, vec![input(5_000, 1)]).unwrap_err();
        assert_eq!(shortfall.needed, Amount::MAX);
    }

    /// The child pays for each input it adds, so the fee follows the input count.
    #[test]
    fn the_fee_is_priced_for_the_planned_shape() {
        let spk = wpkh();
        let request = child(330, 20, &spk);
        let plan = plan_child(&request, vec![input(50_000, 1)]).expect("funded");
        let fee_of_two_inputs = 20 * (150 + request.vbytes(1));
        assert_eq!(
            plan.drain,
            Amount::from_sat(330 + 50_000 - fee_of_two_inputs),
            "input value minus the fee is the drain"
        );
    }

    fn incumbent(fee: u64, vbytes: u64) -> IncumbentChild {
        IncumbentChild {
            fee: Amount::from_sat(fee),
            vbytes: NonZeroU64::new(vbytes).unwrap(),
        }
    }

    #[test]
    fn a_replacement_floor_outranks_the_package_shortfall() {
        let spk = wpkh();
        let request = ChildRequest {
            incumbent: Some(incumbent(100_000, 1000)),
            ..child(1_000_000, 2, &spk)
        };
        assert_eq!(
            request.fee(0).to_sat(),
            100_000 + request.vbytes(0),
            "the replaced fee plus 1 sat/vB over this child"
        );
    }

    #[test]
    fn a_larger_child_pays_a_higher_own_rate_than_the_child_it_replaces() {
        let spk = wpkh();
        let request = ChildRequest {
            incumbent: Some(incumbent(10_000, 50)),
            ..child(1_000_000, 2, &spk)
        };
        let vbytes = request.vbytes(0);
        assert!(vbytes * 200 > 10_000 + vbytes, "the own rate binds here");
        assert_eq!(request.fee(0).to_sat(), vbytes * 200 + 1);
    }

    #[test]
    fn a_large_low_rate_incumbent_is_outbid_on_its_absolute_fee() {
        let spk = wpkh();
        let request = ChildRequest {
            incumbent: Some(incumbent(10_000, 1000)),
            ..child(1_000_000, 2, &spk)
        };
        assert_eq!(request.fee(0).to_sat(), 10_000 + request.vbytes(0));
    }

    #[test]
    fn a_replacement_at_the_cap_builds_and_one_sat_past_it_does_not() {
        let spk = wpkh();
        let cap_sat_vb = 100;
        let child_vbytes = child(1_000_000, 2, &spk).vbytes(0);
        let ceiling = cap_sat_vb * (150 + child_vbytes);
        let request_for = |fee| ChildRequest {
            max_package_rate: FeeRate::from_sat_per_vb(cap_sat_vb).unwrap(),
            incumbent: Some(incumbent(fee, 1000)),
            ..child(1_000_000, 2, &spk)
        };

        assert!(plan_child(&request_for(ceiling - child_vbytes), Vec::new()).is_ok());
        assert_eq!(
            plan_child(&request_for(ceiling - child_vbytes + 1), Vec::new()),
            Err(ChildPlanError::AboveCap {
                needed: Amount::from_sat(ceiling + 1),
                ceiling: Amount::from_sat(ceiling),
            })
        );
    }

    #[test]
    fn the_cap_counts_what_the_parent_pays() {
        let spk = wpkh();
        let cap_sat_vb = 100;
        let child_vbytes = child(1_000_000, 2, &spk).vbytes(0);
        let request = ChildRequest {
            parent_fee: Amount::from_sat(1),
            max_package_rate: FeeRate::from_sat_per_vb(cap_sat_vb).unwrap(),
            incumbent: Some(incumbent(
                cap_sat_vb * (150 + child_vbytes) - child_vbytes,
                1000,
            )),
            ..child(1_000_000, 2, &spk)
        };
        assert!(matches!(
            plan_child(&request, Vec::new()),
            Err(ChildPlanError::AboveCap { .. })
        ));
    }

    #[test]
    fn the_cap_holds_with_no_incumbent() {
        let spk = wpkh();
        let request = ChildRequest {
            parent_fee: Amount::from_sat(1_000_000),
            max_package_rate: FeeRate::from_sat_per_vb(1).unwrap(),
            ..child(1_000_000, 1, &spk)
        };
        assert!(matches!(
            plan_child(&request, Vec::new()),
            Err(ChildPlanError::AboveCap { .. })
        ));
    }

    #[test]
    fn a_replacement_above_the_cap_reads_as_such_when_funds_are_short_too() {
        let spk = wpkh();
        let request = ChildRequest {
            max_package_rate: FeeRate::from_sat_per_vb(2).unwrap(),
            incumbent: Some(incumbent(50_000, 1000)),
            ..child(330, 2, &spk)
        };
        assert!(matches!(
            plan_child(&request, vec![input(1_000, 1)]),
            Err(ChildPlanError::AboveCap { .. })
        ));
    }

    #[test]
    fn only_outputs_that_pay_the_script_count_as_owned() {
        let spk = wpkh();
        let ours = input(1_000, 1);
        let ours = FundingInput {
            txout: TxOut {
                script_pubkey: spk.clone(),
                ..ours.txout
            },
            ..ours
        };
        let theirs = FundingInput {
            txout: TxOut {
                script_pubkey: ScriptBuf::new(),
                ..ours.txout.clone()
            },
            ..input(2_000, 2)
        };
        assert_eq!(
            owned_by(vec![ours.clone(), theirs], &spk),
            vec![ours],
            "an input of another watchtower must not reach a lease"
        );
    }

    #[test]
    fn a_parent_that_overpays_still_leaves_the_child_its_own_relay_fee() {
        let spk = wpkh();
        let request = ChildRequest {
            parent_fee: Amount::from_sat(1_000_000),
            ..child(1_000_000, 2, &spk)
        };
        assert_eq!(request.fee(0).to_sat(), request.vbytes(0));
    }

    #[test]
    fn an_unsigned_psbt_is_v3_at_locktime_zero_and_carries_its_prevouts() {
        let psbt = unsigned_psbt(&[input(50_000, 1)], pays(40_000), LockTime::ZERO);
        assert_eq!(psbt.unsigned_tx.lock_time, LockTime::ZERO);
        assert_eq!(psbt.unsigned_tx.version, Version(3));
        assert!(psbt.inputs[0].witness_utxo.is_some());
    }
}
