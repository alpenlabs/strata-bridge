//! Verification of [`ContestTx`]s.
//!
//! The contest transaction is the only object in the graph that ties a claim to a specific
//! `(operator, deposit)` pair in a way that an outside observer can check. Its proof connector
//! is locked to the operator's public key tweaked by the game index, and the whole transaction
//! is presigned under the N/N key, so a contest that spends a given claim cannot be produced by
//! anyone else. This module recovers that pair from a contest transaction, or checks a pair that
//! the caller already believes to be correct.
//!
//! Nothing here reads the chain. The caller supplies the transaction.

use std::num::NonZero;

use bitcoin::{
    absolute::LockTime, opcodes, relative, script::Instruction, taproot::LeafVersion,
    transaction::Version, Amount, Network, Script, Transaction, Witness, XOnlyPublicKey,
};
use strata_bridge_connectors::{prelude::ContestProofConnector, Connector};

use crate::transactions::prelude::ContestTx;

/// Static protocol data needed to rebuild a contest's proof connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyParams {
    /// Network the graph is deployed on.
    pub network: Network,
    /// Aggregated N/N public key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Relative timelock on the proof connector's timeout leaf.
    pub proof_timelock: relative::Height,
    /// Operator public keys, indexed by operator index.
    ///
    /// This is the key that the proof connector tweaks by the game index, and the same key
    /// that funds the claim's CPFP anchor.
    pub operator_pubkeys: Vec<XOnlyPublicKey>,
    /// Highest deposit index considered when [`verify_contest`] is called without a candidate.
    pub max_deposit_idx: u32,
}

impl VerifyParams {
    /// Number of watchtowers, which are the operators other than the graph's owner.
    ///
    /// Returns `None` if no operators are configured.
    pub fn n_watchtowers(&self) -> Option<u32> {
        // cast safety: an operator table this large cannot be constructed in practice
        (self.operator_pubkeys.len() as u32).checked_sub(1)
    }
}

/// A game, identified by the operator that owns it and the deposit it settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GameId {
    /// Index of the operator that owns the graph.
    pub operator_idx: u32,
    /// Index of the deposit being withdrawn.
    pub deposit_idx: u32,
}

impl GameId {
    /// Game index of this game.
    ///
    /// In v1 the game index is the deposit index plus one, so that it is always non-zero.
    pub fn game_index(self) -> NonZero<u32> {
        NonZero::new(self.deposit_idx.saturating_add(1))
            .expect("a deposit index plus one is non-zero")
    }
}

/// Reasons a transaction fails to verify as a contest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// No operators are configured, so no contest can be recognised.
    NoOperators,
    /// The transaction does not have the shape of a contest.
    BadStructure,
    /// The caller supplied a candidate and the transaction does not belong to it.
    ///
    /// Deliberately distinct from [`VerifyError::NoMatch`]: a rejected candidate says the
    /// caller's belief was wrong, not that the transaction is unrecognised.
    CandidateRejected(GameId),
    /// The transaction has the shape of a contest but belongs to no configured game.
    NoMatch,
    /// The input does not reveal a tapscript leaf, so nothing about it is authenticated.
    ///
    /// A genuine contest spends the claim's contest connector through a tap leaf, which puts
    /// that leaf in the witness. A key path spend, or no witness at all, cannot be a contest.
    NotScriptSpend,
    /// The revealed tap leaf is not the claim contest connector's, or names a different N/N key.
    NotCovenantSigned,
}

/// Checks whether `tx` has the shape of a contest transaction.
///
/// This is a syntactic check only. It uses no keys and authenticates nothing: any of these
/// properties can be reproduced by an unrelated transaction. Use it to reject obvious
/// non-candidates cheaply, never as evidence.
pub fn has_contest_structure(tx: &Transaction, n_watchtowers: u32) -> bool {
    // proof, payout and slash connectors, one counterproof output per watchtower, one anchor.
    let expected_outputs = 4u32.saturating_add(n_watchtowers) as usize;

    tx.version == Version(3)
        && tx.lock_time == LockTime::ZERO
        && tx.input.len() == ContestTx::N_INPUTS
        && tx.output.len() == expected_outputs
        && tx.output.iter().all(|out| out.script_pubkey.is_p2tr())
}

/// Checks whether `tx`'s proof connector belongs to `game`.
///
/// Rebuilds the connector from `params` and compares script pubkeys. Performs no search: the
/// caller supplies the candidate. Returns `false` if the operator index is out of range.
pub fn matches_game(params: &VerifyParams, tx: &Transaction, game: GameId) -> bool {
    let Some(&operator_pubkey) = params.operator_pubkeys.get(game.operator_idx as usize) else {
        return false;
    };
    let Some(out) = tx.output.get(ContestTx::PROOF_VOUT as usize) else {
        return false;
    };

    let expected = ContestProofConnector::new(
        params.network,
        params.n_of_n_pubkey,
        operator_pubkey,
        game.game_index(),
        params.proof_timelock,
        // The surcharge contributes to the connector's value, never to its script pubkey.
        Amount::ZERO,
    )
    .script_pubkey();

    out.script_pubkey == expected
}

/// Checks that `tx`'s input reveals the claim contest connector's tap leaf under the configured
/// N/N key.
///
/// This is what authenticates a contest, and the only check here that an attacker cannot
/// satisfy. Everything else in this module runs on public data and can be reproduced by anyone.
///
/// A contest spends the claim's contest connector through the leaf
///
/// ```text
/// <n_of_n> OP_CHECKSIGVERIFY <watchtower_i> OP_CHECKSIG
/// ```
///
/// which a script path spend puts in the witness, along with a control block proving the leaf
/// was committed in the spent output. For a **confirmed** transaction consensus has already
/// checked both, so finding the configured N/N key in that leaf proves the covenant signed this
/// transaction. Forging it would require an N/N signature.
///
/// # Confirmed transactions only
///
/// The argument above rests entirely on consensus having validated the spend. Applied to an
/// unconfirmed or off-chain transaction this proves nothing, and the signature would have to be
/// verified directly — which additionally needs the prevout, for the sighash.
fn reveals_covenant_leaf(params: &VerifyParams, witness: &Witness) -> Result<(), VerifyError> {
    let leaf = witness
        .taproot_leaf_script()
        .filter(|leaf| leaf.version == LeafVersion::TapScript)
        .ok_or(VerifyError::NotScriptSpend)?;
    let (n_of_n, watchtower) =
        parse_covenant_leaf(leaf.script).ok_or(VerifyError::NotCovenantSigned)?;

    let known_watchtower = params.operator_pubkeys.contains(&watchtower);
    if n_of_n == params.n_of_n_pubkey && known_watchtower {
        Ok(())
    } else {
        Err(VerifyError::NotCovenantSigned)
    }
}

/// Parses `<key> OP_CHECKSIGVERIFY <key> OP_CHECKSIG`, returning both keys.
fn parse_covenant_leaf(leaf: &Script) -> Option<(XOnlyPublicKey, XOnlyPublicKey)> {
    let mut instructions = leaf.instructions();

    let first = match instructions.next()? {
        Ok(Instruction::PushBytes(bytes)) => XOnlyPublicKey::from_slice(bytes.as_bytes()).ok()?,
        _ => return None,
    };
    match instructions.next()? {
        Ok(Instruction::Op(opcodes::all::OP_CHECKSIGVERIFY)) => {}
        _ => return None,
    }
    let second = match instructions.next()? {
        Ok(Instruction::PushBytes(bytes)) => XOnlyPublicKey::from_slice(bytes.as_bytes()).ok()?,
        _ => return None,
    };
    match instructions.next()? {
        Ok(Instruction::Op(opcodes::all::OP_CHECKSIG)) => {}
        _ => return None,
    }
    if instructions.next().is_some() {
        return None;
    }

    Some((first, second))
}

/// Resolves the game that `tx` belongs to.
///
/// Checks the transaction's structure, then that its input reveals the covenant leaf, and only
/// then resolves the game. If `candidate` is supplied, only that game is checked. Otherwise
/// every configured operator is tried against every deposit index up to
/// [`VerifyParams::max_deposit_idx`].
///
/// The covenant check is the step that makes the result evidence rather than a guess — see
/// [`reveals_covenant_leaf`], including its restriction to confirmed transactions. Matching the
/// proof connector alone would accept a transaction anyone could have built, since every input
/// to that script pubkey is public.
pub fn verify_contest(
    params: &VerifyParams,
    tx: &Transaction,
    candidate: Option<GameId>,
) -> Result<GameId, VerifyError> {
    let n_watchtowers = params.n_watchtowers().ok_or(VerifyError::NoOperators)?;

    if !has_contest_structure(tx, n_watchtowers) {
        return Err(VerifyError::BadStructure);
    }

    let input = tx.input.first().ok_or(VerifyError::BadStructure)?;
    reveals_covenant_leaf(params, &input.witness)?;

    if let Some(game) = candidate {
        return match matches_game(params, tx, game) {
            true => Ok(game),
            false => Err(VerifyError::CandidateRejected(game)),
        };
    }

    // cast safety: guarded by the `n_watchtowers` check above
    (0..params.operator_pubkeys.len() as u32)
        .flat_map(|operator_idx| {
            (0..=params.max_deposit_idx).map(move |deposit_idx| GameId {
                operator_idx,
                deposit_idx,
            })
        })
        .find(|&game| matches_game(params, tx, game))
        .ok_or(VerifyError::NoMatch)
}

#[cfg(test)]
pub(crate) mod tests {
    use bitcoin::consensus::encode::deserialize_hex;

    use super::*;

    /// Contest transaction b9eb9c6b0efaace04e79c09ebc536cabecb7fb2d2a97c47e72c185b13d9f0879,
    /// confirmed on signet. It spends the claim contest connector of claim
    /// f599a16569f0ad0fdafb4fa0dabcb4be4776447afe327a14deff63f0a41671e9.
    pub(crate) const CONTEST_TX_HEX: &str = "03000000000101e97116a4f063ffde147a32fe7a447647beb4bcdaa04ffbda0fadf06965a199f50000000000ffffffff08c002000000000000225120cf4e638b4d2b3efc27437376f500354f6468c9815f826c3f9dfafe1d074320964a0100000000000022512057103704b9c68101bc45af38eebb0893c6ecb759eded3cefaa922391e75b3b5b4a01000000000000225120ef989d20647dad6edf2afb84fbf977a8bd877358ce37596816c42c00b563fd6dfa16000000000000225120fd927cb496276990fdd200d28d92994179fab1b806243584d717d3ddf2213b5afa16000000000000225120d309f2ea475fd04152ab3cb8b3e23972f950b2796fd7e2d9a4e50f28a1f48e25fa1600000000000022512087b9b399732782907fbacf5364de9caecd206c499037a776c6725b05aa7e45dcfa16000000000000225120c580e40fa826f91dc00189a355feb78d85968a3f7bd241d0c79cd238e27c2ac84a01000000000000225120d6fd91829128a15692b59f07543ffea5544a318dfd2fbd6cce16a35fc62c570a04406c5d20487f6caf6cb9d11c3b168becabb68bd11d80ada777cdc692d6950ba0e37d2e055fc7203d015f0ff615573a569b24250a52f5ba363efa13a41dbe335fcd40010c7d793dee963e35f3eb42d6c2bf8da6d23da21af59c629afdcbf80ab5ee1fb72e2588c6f6ca7734e88025b6ddd5a1ccfc6f61b877c7fdcb1d2a770363ffc64420e5b7273af014acd41112d67377be1543499a642e8891481141d578c7df698497ad207e2b01bdbc6925f103d2157f7494bc4feebc744066042d3618351b29991cfdceac61c14a906a18d71fd75c14f0f0b8b5b748d614b55355f0be3512f2da7e8cb5d4092f74a5bfe51c964b00c56a87cce513e3a0599cf241dc3375bdfad0d4de902d3e514b968d44f773c0356c46a841c8381023334c81677e9cb76641652d2595e6c6b900000000";

    /// N/N key of the deployment that produced [`CONTEST_TX_HEX`], read from the leaf script
    /// revealed in that transaction's input witness.
    const N_OF_N: &str = "e5b7273af014acd41112d67377be1543499a642e8891481141d578c7df698497";

    /// Operator keys of the same deployment. The graph belongs to index 3.
    const OPERATORS: [&str; 5] = [
        "ff79389655916a41e7f8278c1de678ed34c17171122afece179b8a7583a84450",
        "19ef09eaecff5c4cc875f9ac56c1849712ed4019d0280ad08c743a8635c796e3",
        "7e2b01bdbc6925f103d2157f7494bc4feebc744066042d3618351b29991cfdce",
        "35be0db46188725d717ae159ba2b56c971d718b8c827d405664b987390091b90",
        "72eb41053d4dfafe53f237cf37071220b54ffa782435dba94a2009063296c565",
    ];

    /// Proof timelock of the same deployment, read from the timeout leaf revealed when the
    /// proof connector was spent by transaction
    /// 29ac5eab17330569aba4bd82a481bd50ce03cc8d80f92d3a1689a5a0487bf779.
    const PROOF_TIMELOCK: u16 = 24;

    /// The game that [`CONTEST_TX_HEX`] belongs to.
    pub(crate) const EXPECTED: GameId = GameId {
        operator_idx: 3,
        deposit_idx: 1,
    };

    pub(crate) fn params() -> VerifyParams {
        VerifyParams {
            network: Network::Signet,
            n_of_n_pubkey: N_OF_N.parse().expect("valid n/n key"),
            proof_timelock: relative::Height::from(PROOF_TIMELOCK),
            operator_pubkeys: OPERATORS
                .iter()
                .map(|key| key.parse().expect("valid operator key"))
                .collect(),
            max_deposit_idx: 99,
        }
    }

    pub(crate) fn contest_tx() -> Transaction {
        deserialize_hex(CONTEST_TX_HEX).expect("valid transaction")
    }

    /// Claim f599a16569f0ad0fdafb4fa0dabcb4be4776447afe327a14deff63f0a41671e9, the claim whose
    /// contest connector [`CONTEST_TX_HEX`] spends.
    pub(crate) const CLAIM_TX_HEX: &str = "0300000000010121f4fa4ba3858890ed0a8386d8a16640a65d650c74d27e3be5d7ba97a32d82e30100000000fdffffff0342660000000000002251204e976bc0a131d8bb83a05ff23d25a84298877d8dfe6383c215f07503ed294b3e4a010000000000002251200e48cc38d2ab19d11edbde9903fa3cd879ff6dd0089f76e295254974c05502884a01000000000000225120a178c57bece4a8e0874bf89f6249a520f27b505a4d3fc64b32e3b975a78b80dc0140269a6cb878fbd831f534a406e33e0264ece173e2a436ffc734fed3440db266c9425edfcf64f4840cd96d1abfad6f2f10c1fede9ec86ab8c85b8df00a764d677400000000";

    pub(crate) fn claim_tx() -> Transaction {
        deserialize_hex(CLAIM_TX_HEX).expect("valid transaction")
    }

    #[test]
    fn recognises_contest_structure() {
        assert!(has_contest_structure(&contest_tx(), 4));
    }

    #[test]
    fn rejects_structure_with_wrong_watchtower_count() {
        assert!(!has_contest_structure(&contest_tx(), 3));
    }

    #[test]
    fn discovers_the_game() {
        assert_eq!(verify_contest(&params(), &contest_tx(), None), Ok(EXPECTED));
    }

    #[test]
    fn accepts_the_correct_candidate() {
        assert_eq!(
            verify_contest(&params(), &contest_tx(), Some(EXPECTED)),
            Ok(EXPECTED)
        );
    }

    #[test]
    fn rejects_a_wrong_candidate() {
        let wrong = GameId {
            operator_idx: EXPECTED.operator_idx,
            deposit_idx: EXPECTED.deposit_idx + 1,
        };
        assert_eq!(
            verify_contest(&params(), &contest_tx(), Some(wrong)),
            Err(VerifyError::CandidateRejected(wrong))
        );
    }

    #[test]
    fn rejects_an_unknown_operator_set() {
        let mut params = params();
        params
            .operator_pubkeys
            .remove(EXPECTED.operator_idx as usize);
        // one fewer operator changes the expected output count, so this fails on structure
        assert_eq!(
            verify_contest(&params, &contest_tx(), None),
            Err(VerifyError::BadStructure)
        );
    }

    #[test]
    fn rejects_when_no_operators_are_configured() {
        let params = VerifyParams {
            operator_pubkeys: Vec::new(),
            ..params()
        };
        assert_eq!(
            verify_contest(&params, &contest_tx(), None),
            Err(VerifyError::NoOperators)
        );
    }
}
