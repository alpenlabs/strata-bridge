//! Database types that are agnostic to the underlying database implementation.

use std::{collections::BTreeMap, fmt, sync::Arc};

use bitcoin::{
    OutPoint, Transaction, TxOut,
    hashes::{Hash, sha256},
};
use strata_asm_bridge_types::SafeHarborAddress;
use strata_bridge_primitives::{
    covenant::StakeKey,
    types::{DepositIdx, GraphIdx},
};
use strata_bridge_sm::{
    deposit::{config::DepositSMCfg, machine::DepositSM},
    graph::{config::GraphSMCfg, machine::GraphSM},
    operator_set::OperatorSetSM,
    stake::machine::StakeSM,
};

/// Identity of a stored config: the SHA-256 of the bytes it is stored as.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConfigId(pub [u8; 32]);

impl ConfigId {
    fn of(bytes: &[u8]) -> Self {
        Self(sha256::Hash::hash(bytes).to_byte_array())
    }
}

impl fmt::Display for ConfigId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for ConfigId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigId({self})")
    }
}

/// The deposit and graph configs a deposit and its graphs were created under.
///
/// Holds the exact bytes it is stored as. Re-encoding a loaded config would give different bytes
/// once the config types gain a field, so its stored row would stop matching its [`ConfigId`].
/// Changes to the stored layout must be handled by database migrations.
#[derive(Clone)]
pub struct PinnedConfig {
    id: ConfigId,
    bytes: Arc<[u8]>,
    deposit: Arc<DepositSMCfg>,
    graph: Arc<GraphSMCfg>,
}

impl PinnedConfig {
    /// Encodes the configs a new deposit is created under.
    pub fn new(deposit: Arc<DepositSMCfg>, graph: Arc<GraphSMCfg>) -> Self {
        let bytes = postcard::to_allocvec(&(&*deposit, &*graph))
            .expect("state machine configs always encode");
        Self {
            id: ConfigId::of(&bytes),
            bytes: bytes.into(),
            deposit,
            graph,
        }
    }

    /// Decodes a stored config, identifying it by the bytes as stored.
    pub fn decode(bytes: &[u8]) -> Result<Self, postcard::Error> {
        let (deposit, graph): (DepositSMCfg, GraphSMCfg) = postcard::from_bytes(bytes)?;
        Ok(Self {
            id: ConfigId::of(bytes),
            bytes: bytes.into(),
            deposit: Arc::new(deposit),
            graph: Arc::new(graph),
        })
    }

    /// Returns the identity this config is stored under.
    pub const fn id(&self) -> ConfigId {
        self.id
    }

    /// Returns the bytes this config is stored as.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the deposit state machine config.
    pub const fn deposit(&self) -> &Arc<DepositSMCfg> {
        &self.deposit
    }

    /// Returns the graph state machine config.
    pub const fn graph(&self) -> &Arc<GraphSMCfg> {
        &self.graph
    }
}

// The id commits to the bytes, which decode to the configs, so comparing ids is enough.
impl PartialEq for PinnedConfig {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PinnedConfig {}

impl fmt::Debug for PinnedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedConfig")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A persisted plan for an operator's stake funding transaction.
///
/// Pins the unsigned transaction and its prevouts so the same txid and signatures can be
/// reproduced without re-running input selection or fee estimation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeFundingReservation {
    /// The unsigned funding transaction.
    pub unsigned_tx: Transaction,

    /// The prevouts for the inputs of `unsigned_tx`, in input order.
    pub prevouts: Vec<TxOut>,

    /// Index of the reserved-wallet funding output in `unsigned_tx.output`.
    pub stake_output_vout: u32,
}

/// A reserved-wallet output committed to fund one graph's claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimFundingReservation {
    /// The reserved-wallet output the claim spends.
    pub outpoint: OutPoint,

    /// The output at `outpoint`, so that a reused reservation can be checked against the claim
    /// it funds.
    pub txout: TxOut,
}

/// Result of claiming a first-writer-wins funding assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingAssignment<T> {
    /// The caller created the assignment with the supplied value.
    Created(T),
    /// The assignment already existed and this value is the durable assignment.
    Existing(T),
}

impl<T> FundingAssignment<T> {
    /// Returns the assigned value, regardless of whether it was created or already existed.
    pub fn into_inner(self) -> T {
        match self {
            Self::Created(value) | Self::Existing(value) => value,
        }
    }

    /// Returns a reference to the assigned value.
    pub const fn as_ref(&self) -> &T {
        match self {
            Self::Created(value) | Self::Existing(value) => value,
        }
    }
}

/// Registry state read from bounded database transactions.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PersistedState {
    /// Deposit rows, including their durable identities.
    pub deposits: Vec<(DepositIdx, DepositSM)>,
    /// The config each deposit is pinned to. Deposits stored before configs were pinned have no
    /// entry.
    pub deposit_configs: BTreeMap<DepositIdx, ConfigId>,
    /// Every stored config, by identity.
    pub configs: BTreeMap<ConfigId, PinnedConfig>,
    /// Graph rows, including their durable identities.
    pub graphs: Vec<(GraphIdx, GraphSM)>,
    /// Historical and current stake rows, including their durable identities.
    pub stakes: Vec<(StakeKey, StakeSM)>,
    /// Public membership and its complete transition history.
    pub operator_set: Option<OperatorSetSM>,
    /// The frozen safe-harbour destination, if latched.
    pub safe_harbour: Option<SafeHarborAddress>,
}

/// A batch of state machine writes to persist atomically.
///
/// This can be used to persist causally-linked state machine updates in a single transaction,
/// ensuring consistency and atomicity. For example, when processing a deposit, you might want to
/// update both the deposit state machine and the associated graph state machines in a single batch.
#[derive(Debug, Default, Clone)]
pub struct WriteBatch {
    /// Deposit state machines to persist, each with the config it is pinned to.
    deposits: Vec<(DepositSM, PinnedConfig)>,
    /// Graph state machines to persist, keyed by graph index.
    graphs: Vec<GraphSM>,
    /// Stake state machines to persist, keyed by covenant and operator index.
    stakes: Vec<StakeSM>,
    operator_set: Option<OperatorSetSM>,
}

impl WriteBatch {
    /// Creates a new, empty `WriteBatch`.
    pub const fn new() -> Self {
        Self {
            deposits: Vec::new(),
            graphs: Vec::new(),
            stakes: Vec::new(),
            operator_set: None,
        }
    }

    /// Returns the deposit state machines in the batch, each with its pinned config.
    pub fn deposits(&self) -> &[(DepositSM, PinnedConfig)] {
        &self.deposits
    }

    /// Returns the graph state machines in the batch.
    pub fn graphs(&self) -> &[GraphSM] {
        &self.graphs
    }

    /// Returns the stake state machines in the batch.
    pub fn stakes(&self) -> &[StakeSM] {
        &self.stakes
    }

    /// Returns the membership state included in this transaction.
    pub const fn operator_set(&self) -> Option<&OperatorSetSM> {
        self.operator_set.as_ref()
    }

    /// Includes the membership state in this transaction.
    pub fn set_operator_set(&mut self, operator_set: OperatorSetSM) {
        self.operator_set = Some(operator_set);
    }

    /// Adds a deposit state machine to the batch, together with the config it is pinned to.
    ///
    /// The two are written in one transaction, so a stored deposit always has its config.
    pub fn add_deposit(&mut self, deposit_sm: DepositSM, config: PinnedConfig) {
        self.deposits.push((deposit_sm, config));
    }

    /// Adds a graph state machine to the batch.
    pub fn add_graph(&mut self, graph_sm: GraphSM) {
        self.graphs.push(graph_sm);
    }

    /// Adds a stake state machine to the batch.
    pub fn add_stake(&mut self, stake_sm: StakeSM) {
        self.stakes.push(stake_sm);
    }
}
