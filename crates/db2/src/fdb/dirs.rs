//! This FoundationDB layer is based on top of the standard FoundationDB
//! Directory layer.
//!
//! See:
//! - <https://apple.github.io/foundationdb/developer-guide.html#directories>
//! - <https://docs.rs/foundationdb/latest/foundationdb/directory/index.html>
//!
//! This is effectively the standard method to do keyspaces/subspaces in the
//! logical Unix-style hierarchical way. Each directory has an associated
//! subspace used to store its content. The directory layer maps each path to a
//! short prefix used for the corresponding subspace. In effect, directories
//! provide a level of indirection for access to subspaces. Directory operations
//! are transactional.
//!
//! The root directory name is configurable (defaulting to "strata-bridge-v1").
//! This allows multiple bridge deployments to share the same FDB cluster if
//! needed, and provides a versioning mechanism for future schema migrations.
//!
//! Within this directory, we have different subspaces for different purposes.
//! Generally, you can imagine these subspaces as similar to tables in a relational
//! database.
//!
//! Note that there is no automatic indexing in FoundationDB. If you want to
//! efficiently query data using fields other than a primary key, you will need
//! to create your own indexes. Since FDB is transactional, you can and SHOULD
//! update the index in the same transaction as the data itself - maintaining
//! consistency.
//!
//! Subspaces and directories should be mostly created once then reused as they
//! require database transactions to create or open.

use std::fmt::Display;

use foundationdb::{
    RetryableTransaction,
    directory::{Directory, DirectoryError, DirectoryLayer, DirectoryOutput, DirectorySubspace},
};

use crate::fdb::LAYER_ID;

/// Stores the key prefixes for different data types in the database.
#[derive(Debug)]
pub struct Directories {
    /// Root subspace for the database.
    pub root: DirectorySubspace,

    /// Subspace for storing Schnorr signatures.
    pub signatures: DirectorySubspace,

    /// Subspace for storing Deposit SM states, keyed by `DepositIdx`.
    pub deposits: DirectorySubspace,

    /// Subspace for storing Graph SM states, keyed by (`DepositIdx`, `OperatorIdx`).
    pub graphs: DirectorySubspace,

    /// Subspace for storing fund OutPoints, keyed by `Txid`.
    pub funds: DirectorySubspace,
}

impl Directories {
    pub(crate) async fn setup(
        txn: &RetryableTransaction,
        root_dir_name: &str,
    ) -> Result<Self, DirectoryError> {
        let dir = DirectoryLayer::default();
        let DirectoryOutput::DirectorySubspace(root) = dir
            .create_or_open(txn, &[root_dir_name.to_string()], None, Some(LAYER_ID))
            .await?
        else {
            panic!("should receive a root subspace")
        };

        let signatures = open_subdir(&root, txn, SubSpaceId::Signatures).await?;
        let deposits = open_subdir(&root, txn, SubSpaceId::Deposits).await?;
        let graphs = open_subdir(&root, txn, SubSpaceId::Graphs).await?;
        let funds = open_subdir(&root, txn, SubSpaceId::Funds).await?;

        Ok(Self {
            root,
            signatures,
            deposits,
            graphs,
            funds,
        })
    }

    /// Clears all data stored in the directories. Only available in test mode.
    #[cfg(test)]
    pub async fn clear(&self, txn: &RetryableTransaction) -> Result<bool, DirectoryError> {
        let dir = DirectoryLayer::default();
        dir.remove_if_exists(txn, self.root.get_path()).await
    }
}

/// Opens (or creates) a named subdirectory under `parent`, returning its
/// [`DirectorySubspace`].
async fn open_subdir(
    parent: &DirectorySubspace,
    txn: &RetryableTransaction,
    id: SubSpaceId,
) -> Result<DirectorySubspace, DirectoryError> {
    let DirectoryOutput::DirectorySubspace(sub) = parent
        .create_or_open(txn, &[id.to_string()], None, Some(LAYER_ID))
        .await?
    else {
        panic!("should receive a subspace for {id}")
    };
    Ok(sub)
}

/// Identifiers for the different subspaces in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubSpaceId {
    /// Subspace for storing Schnorr signatures.
    Signatures,
    /// Subspace for storing Deposit SM states, keyed by `DepositIdx`.
    Deposits,
    /// Subspace for storing Graph SM states, keyed by (`DepositIdx`, `OperatorIdx`).
    Graphs,
    /// Subspace for storing fund OutPoints, keyed by `Txid`.
    Funds,
}

impl From<SubSpaceId> for &'static str {
    fn from(value: SubSpaceId) -> Self {
        match value {
            SubSpaceId::Signatures => "signatures",
            SubSpaceId::Deposits => "deposits",
            SubSpaceId::Graphs => "graphs",
            SubSpaceId::Funds => "funds",
        }
    }
}

impl Display for SubSpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}
