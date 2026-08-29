//! Detection of a watchtower's [`CounterproofAckTx`] for a given claim.
//!
//! Reaching the ack means walking two edges of the graph: from the claim to the contest that
//! spends its contest connector, and from the contest to whatever spends its payout connector.
//! Both connectors are single-use outputs, so each edge has at most one successor and neither
//! step is a search.
//!
//! The second successor is not necessarily an ack. Three transactions can spend the contest
//! payout connector — the ack, the bridge proof timeout, and the contested payout — so the
//! transaction found there still has to be told apart from its two siblings. That is all
//! [`is_ack_of`] does.
//!
//! This module does no I/O. Callers supply a [`GraphTxSource`]; [`MapTxSource`] is a
//! self-contained one built from transactions already in hand.

use std::collections::HashMap;

use bitcoin::{
    absolute::LockTime, opcodes, script::Instruction, taproot::LeafVersion, transaction::Version,
    OutPoint, Transaction, Txid, XOnlyPublicKey,
};

use crate::{
    transactions::prelude::{ClaimTx, ContestTx, CounterproofAckTx},
    verify_contest::{verify_contest, GameId, VerifyError, VerifyParams},
};

/// Read access to confirmed transactions and to the spend status of their outputs.
///
/// An implementation backed by a node needs an index that can answer "what spent this
/// outpoint": a bare `bitcoind` cannot, since a spent output is no longer in the UTXO set.
pub trait GraphTxSource {
    /// Returns the transaction with this id, if it is known.
    fn tx(&self, txid: &Txid) -> Option<Transaction>;

    /// Returns the id of the transaction that spends this outpoint, if any does.
    fn outspend(&self, outpoint: &OutPoint) -> Option<Txid>;
}

/// A [`GraphTxSource`] over a fixed set of transactions.
///
/// Spends are resolved by scanning the inputs of the transactions it holds, so a caller only
/// has to supply the transactions themselves. Anything outside that set reads as absent, which
/// makes an incomplete set indistinguishable from an unspent output — fine for tests and for
/// working from a captured slice of the chain, not fine as a view of the live chain.
#[derive(Debug, Clone, Default)]
pub struct MapTxSource {
    by_txid: HashMap<Txid, Transaction>,
    spends: HashMap<OutPoint, Txid>,
}

impl MapTxSource {
    /// Builds a source over the given transactions.
    pub fn new(txs: impl IntoIterator<Item = Transaction>) -> Self {
        let mut source = Self::default();
        for tx in txs {
            source.insert(tx);
        }
        source
    }

    /// Adds one transaction and records the outpoints it spends.
    pub fn insert(&mut self, tx: Transaction) {
        let txid = tx.compute_txid();
        for input in &tx.input {
            self.spends.insert(input.previous_output, txid);
        }
        self.by_txid.insert(txid, tx);
    }
}

impl GraphTxSource for MapTxSource {
    fn tx(&self, txid: &Txid) -> Option<Transaction> {
        self.by_txid.get(txid).cloned()
    }

    fn outspend(&self, outpoint: &OutPoint) -> Option<Txid> {
        self.spends.get(outpoint).copied()
    }
}

/// Outcome of [`verify_ack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckReport {
    /// The contest that authenticated the claim.
    pub contest_txid: Txid,
    /// The game the claim belongs to, recovered from the contest.
    pub game: GameId,
    /// Whether a watchtower ack is on chain for this game.
    pub ack: bool,
}

/// Reasons [`verify_ack`] cannot produce a report.
///
/// Note that none of these are "there is no ack" — that is [`AckReport::ack`] being `false`.
/// These are cases where the question could not be answered at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckError {
    /// Nothing spends the claim's contest connector, so there is no contest to verify.
    ///
    /// The claim may simply be young: until a contest is posted there is nothing on chain that
    /// binds this claim to an operator.
    NoContest,
    /// A transaction is known to spend an outpoint, but the source cannot produce it.
    MissingTx(Txid),
    /// A contest was found and rejected.
    Contest(VerifyError),
}

/// Checks whether `tx` is the watchtower ack that spends `contest_txid`'s payout connector.
///
/// Assumes `tx` was reached by following that connector, and answers the only question that
/// remains: which of the connector's three possible spenders this is. The bridge proof timeout
/// is ruled out because it also spends the proof connector; the contested payout is ruled out
/// on input count, since it additionally spends the deposit, the claim payout connector and the
/// contest slash connector.
///
/// The shape checks alone authenticate nothing, so one more is applied: an ack's other input
/// spends the counterproof connector through its timeout leaf, which reveals
///
/// ```text
/// <n_of_n> OP_CHECKSIGVERIFY <delta_nack> OP_CSV
/// ```
///
/// For a confirmed transaction consensus has already validated that spend, so the configured
/// N/N key appearing there proves the covenant signed this transaction. The same caveat as
/// elsewhere applies: the argument holds only because the transaction is confirmed.
///
/// The contest payout connector input is a key path spend and reveals no script, so it cannot
/// carry this check.
pub fn is_ack_of(params: &VerifyParams, contest_txid: Txid, tx: &Transaction) -> bool {
    let spends = |vout: u32| {
        tx.input
            .iter()
            .any(|input| input.previous_output == OutPoint::new(contest_txid, vout))
    };

    let shape = tx.version == Version(3)
        && tx.lock_time == LockTime::ZERO
        && tx.input.len() == CounterproofAckTx::N_INPUTS
        && tx.output.len() == 1
        && tx.output[0].script_pubkey.is_p2tr()
        && spends(ContestTx::PAYOUT_VOUT)
        && !spends(ContestTx::PROOF_VOUT);

    // any input may carry the leaf; the payout connector one never does
    shape
        && tx.input.iter().any(|input| {
            input
                .witness
                .taproot_leaf_script()
                .filter(|leaf| leaf.version == LeafVersion::TapScript)
                .and_then(|leaf| timelocked_leaf_key(leaf.script))
                .is_some_and(|n_of_n| n_of_n == params.n_of_n_pubkey)
        })
}

/// Parses `<key> OP_CHECKSIGVERIFY <n> OP_CSV`, returning the key.
fn timelocked_leaf_key(leaf: &bitcoin::Script) -> Option<XOnlyPublicKey> {
    let mut instructions = leaf.instructions();

    let key = match instructions.next()? {
        Ok(Instruction::PushBytes(bytes)) => XOnlyPublicKey::from_slice(bytes.as_bytes()).ok()?,
        _ => return None,
    };
    match instructions.next()? {
        Ok(Instruction::Op(opcodes::all::OP_CHECKSIGVERIFY)) => {}
        _ => return None,
    }
    match instructions.next()? {
        Ok(Instruction::PushBytes(_)) | Ok(Instruction::Op(_)) => {}
        _ => return None,
    }
    match instructions.next()? {
        Ok(Instruction::Op(opcodes::all::OP_CSV)) => {}
        _ => return None,
    }
    if instructions.next().is_some() {
        return None;
    }

    Some(key)
}

/// Reports whether a watchtower ack exists on chain for the game that `claim_txid` belongs to.
///
/// Walks claim to contest, verifies the contest to recover the game, then walks the contest's
/// payout connector to whatever spends it. `candidate` is forwarded to [`verify_contest`]: pass
/// it to check a game you already believe in rather than searching for one.
pub fn verify_ack<S: GraphTxSource>(
    source: &S,
    params: &VerifyParams,
    claim_txid: Txid,
    candidate: Option<GameId>,
) -> Result<AckReport, AckError> {
    let contest_connector = OutPoint::new(claim_txid, ClaimTx::CONTEST_VOUT);
    let contest_txid = source
        .outspend(&contest_connector)
        .ok_or(AckError::NoContest)?;
    let contest = source
        .tx(&contest_txid)
        .ok_or(AckError::MissingTx(contest_txid))?;

    let game = verify_contest(params, &contest, candidate).map_err(AckError::Contest)?;

    let payout_connector = OutPoint::new(contest_txid, ContestTx::PAYOUT_VOUT);
    let ack = match source.outspend(&payout_connector) {
        // the connector is unspent, so the game has not reached an ack or either of its
        // siblings; the outcome is still open
        None => false,
        Some(spender_txid) => {
            let spender = source
                .tx(&spender_txid)
                .ok_or(AckError::MissingTx(spender_txid))?;
            is_ack_of(params, contest_txid, &spender)
        }
    };

    Ok(AckReport {
        contest_txid,
        game,
        ack,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::encode::deserialize_hex;

    use super::*;
    use crate::verify_contest::tests::{claim_tx, contest_tx, params, EXPECTED};

    /// Bridge proof timeout 29ac5eab17330569aba4bd82a481bd50ce03cc8d80f92d3a1689a5a0487bf779.
    /// It spends the contest's payout connector, so the walk finds it — and it is not an ack.
    /// This is the near-miss the whole discriminator exists for.
    const TIMEOUT_TX_HEX: &str = "0300000000010279089f3db185c1727ec4972a2dfbb7ecab6c53bc9ec0794ee0acfa0e6b9cebb900000000001800000079089f3db185c1727ec4972a2dfbb7ecab6c53bc9ec0794ee0acfa0e6b9cebb90100000000ffffffff019402000000000000225120d6fd91829128a15692b59f07543ffea5544a318dfd2fbd6cce16a35fc62c570a0340a41af4456b21dae5f8271bcca43b5d1da710fcbf08bd08d681c60d8b45963fcef2872240dc0d5d3365c605c9649675ac46abc95a1d19d659730adab4d64b6fdb2520e5b7273af014acd41112d67377be1543499a642e8891481141d578c7df698497ad0118b221c0d6ee70edb084d7d293d6f6c450817e7907437c4808896b9cab07ad6f602f12dc0140b0d28a4ba9ce6e0685aa973ba234a9c5ea9a70b8524a5b0872a008335335efca31ca4fb28580c7060b4388ac3dc81ed296457241a3ab4634c5f91c511f12b34100000000";

    fn tx(hex: &str) -> Transaction {
        deserialize_hex(hex).expect("valid transaction")
    }

    fn claim_txid() -> Txid {
        claim_tx().compute_txid()
    }

    /// The real game as it stands on chain: claim, contest, and a timeout rather than an ack.
    fn source() -> MapTxSource {
        MapTxSource::new([claim_tx(), contest_tx(), tx(TIMEOUT_TX_HEX)])
    }

    /// A second signet game, this one carrying a real watchtower ack.
    ///
    /// Claim eaf25a3ef1a0ada03f8864dd65adb8367333ac050aedd2e4a2f835cc2b607716, operator 2,
    /// deposit 0.
    const ACKED_CLAIM_TX_HEX: &str = "03000000000101a5f5684cd734610882237a127af5cb155218f64be438e0210b9a1b2ffcc9d8f20000000000fdffffff034266000000000000225120687a6e9f7bc979d7f57e36fd78383e6475f1a33cfbdb157de53ebecaf8c1a9f14a01000000000000225120a175f220e78d78b35471822caeafdb7b3be5daf10b611a81f728307af42ce3f64a01000000000000225120c6671e59d5298046ea92dccdb2c718bf49244ccdf3642ccbba00ac7637b9da6c0140ad25dc4c980ec866ba2e1ee3ca11c7d87233e7770a69b1431a3ad293290d1574ab7bec03f39168b3fee4ed583cf7ccda653340857c2e0aa7993d77852719240100000000";

    /// Contest 89d40b016f6ee3ec7aded6b0a64245307c38b195a66c46a85e5bcf102e1841c0, spending the
    /// contest connector of [`ACKED_CLAIM_TX_HEX`]. Its input leaf names operator 3 as the
    /// contesting watchtower.
    const ACKED_CONTEST_TX_HEX: &str = "030000000001011677602bcc35f8a2e4d2ed0a05ac337336b8ad65dd64883fa0ada0f13e5af2ea0000000000ffffffff08c002000000000000225120a1aa6a05b5fde40db8ceac87ee2c0d8b4171de9b17cc8acac69f2ed46213cfe54a0100000000000022512057103704b9c68101bc45af38eebb0893c6ecb759eded3cefaa922391e75b3b5b4a01000000000000225120ef989d20647dad6edf2afb84fbf977a8bd877358ce37596816c42c00b563fd6dfa1600000000000022512039edbe0a5bf8699d066a84f6208624d68415258bcaabeeaf13c26f2c7f0d889dfa160000000000002251206687b91eb1ddc55d1c23c14d449a59311523266bf6a9fc46a78068a598cb4fadfa16000000000000225120f785ecc8ef20816cc51e4b58b2462f95e00e22833fc74725f6e4d5c8bcbb1718fa16000000000000225120a72c83c5f4b41cd4510d465d5753d6f0cc959ea5f9e453e38385d9f43991e44f4a010000000000002251202ab0832cee7d05f1d2612566892a3760bd894629af88c726f66b4a0b003d92d3044072ab01667b721c75c27c53930655afa9a8f0f3092fe497163738cfe89afe2159724ee93e1427a45d496eadf10d3fc09e58248768567ec8bfb7327b027dbd203b40abe783561f052d55b5574896e4705b82fb13c5806155daaa5772b646116a03f85aaf2af70c771eefb2bc04955bc6bf620b5dc4fa720403aa10b977474404e86e4420e5b7273af014acd41112d67377be1543499a642e8891481141d578c7df698497ad2035be0db46188725d717ae159ba2b56c971d718b8c827d405664b987390091b90ac61c04a906a18d71fd75c14f0f0b8b5b748d614b55355f0be3512f2da7e8cb5d4092f74a5bfe51c964b00c56a87cce513e3a0599cf241dc3375bdfad0d4de902d3e514b968d44f773c0356c46a841c8381023334c81677e9cb76641652d2595e6c6b900000000";

    /// Watchtower ack 6508d324e9931fbb348bf225850a58de71af822b7e0438e0f92786bf8f30fdfb.
    ///
    /// It spends the contest payout connector and a counterproof output, and its counterproof
    /// input reveals the timeout leaf under the N/N key. The only genuine ack in these fixtures.
    const ACK_TX_HEX: &str = "030000000001023850e7d2d87b86d067e68073df5d8252e29494234653796a56b4a719ff6efa90000000000018000000c041182e10cf5b5ea8466ca695b1387c304542a6b0d6de7aece36e6f010bd4890100000000ffffffff0194020000000000002251202a53eb26b513b152a502c42d17167ba63aa33222dd29ddf29a3190cd1d0c958a0340565d0565ec2efe838316a18de77f837706ca621e6618f84cb1822dad0f25573ced6ac8c5fe5329fc904c80a3bab1d70f461d0c7fa9f25dbdda810b501709bcad2520e5b7273af014acd41112d67377be1543499a642e8891481141d578c7df698497ad0118b221c01e9f0a5a692f9e731ca6b318795c73cd53b17a926f671bcc232408b1e82aea92014034ef925aebb9b4a9859d4edc953ccec948c76ebbee3ca89677822a2aaad41191eb40d121c895f7cc3b240345e51306c13cc73a5d844e6904b62c97fe7ab7639900000000";

    /// The game that [`ACK_TX_HEX`] belongs to.
    const ACKED_GAME: GameId = GameId {
        operator_idx: 2,
        deposit_idx: 0,
    };

    fn acked_source() -> MapTxSource {
        MapTxSource::new([
            tx(ACKED_CLAIM_TX_HEX),
            tx(ACKED_CONTEST_TX_HEX),
            tx(ACK_TX_HEX),
        ])
    }

    #[test]
    fn recognises_a_real_ack() {
        let contest_txid = tx(ACKED_CONTEST_TX_HEX).compute_txid();
        assert!(is_ack_of(&params(), contest_txid, &tx(ACK_TX_HEX)));
    }

    #[test]
    fn reports_an_ack_for_an_acked_game() {
        let claim_txid = tx(ACKED_CLAIM_TX_HEX).compute_txid();
        let report = verify_ack(&acked_source(), &params(), claim_txid, None).expect("report");
        assert_eq!(report.contest_txid, tx(ACKED_CONTEST_TX_HEX).compute_txid());
        assert_eq!(report.game, ACKED_GAME);
        assert!(report.ack);
    }

    /// The ack of one game must not be accepted against another game's contest.
    #[test]
    fn ack_is_not_accepted_against_a_different_contest() {
        assert!(!is_ack_of(
            &params(),
            contest_tx().compute_txid(),
            &tx(ACK_TX_HEX)
        ));
    }

    #[test]
    fn timeout_is_not_an_ack() {
        let contest_txid = contest_tx().compute_txid();
        assert!(!is_ack_of(&params(), contest_txid, &tx(TIMEOUT_TX_HEX)));
    }

    #[test]
    fn reports_no_ack_for_a_timed_out_game() {
        let report = verify_ack(&source(), &params(), claim_txid(), None).expect("report");
        assert_eq!(report.contest_txid, contest_tx().compute_txid());
        assert_eq!(report.game, EXPECTED);
        assert!(!report.ack);
    }

    #[test]
    fn reports_no_ack_while_the_payout_connector_is_unspent() {
        let source = MapTxSource::new([claim_tx(), contest_tx()]);
        let report = verify_ack(&source, &params(), claim_txid(), None).expect("report");
        assert_eq!(report.game, EXPECTED);
        assert!(!report.ack);
    }

    #[test]
    fn fails_when_no_contest_spends_the_claim() {
        let source = MapTxSource::new([claim_tx()]);
        assert_eq!(
            verify_ack(&source, &params(), claim_txid(), None),
            Err(AckError::NoContest)
        );
    }

    #[test]
    fn forwards_a_rejected_candidate() {
        let wrong = GameId {
            operator_idx: EXPECTED.operator_idx,
            deposit_idx: EXPECTED.deposit_idx + 1,
        };
        assert_eq!(
            verify_ack(&source(), &params(), claim_txid(), Some(wrong)),
            Err(AckError::Contest(VerifyError::CandidateRejected(wrong)))
        );
    }
}
