//! This FoundationDB layer is based on top of the standard FoundationDB
//! Directory layer.
//!
//! See:
//! - https://apple.github.io/foundationdb/developer-guide.html#directories
//! - https://docs.rs/foundationdb/latest/foundationdb/directory/index.html
//!
//! This is effectively the standard method to do keyspaces/subspaces in the
//! logical Unix-style hierarchical way. Each directory has an associated
//! subspace used to store its content. The directory layer maps each path to a
//! short prefix used for the corresponding subspace. In effect, directories
//! provide a level of indirection for access to subspaces. Directory operations
//! are transactional.
//!
//! For each node, we create a directory named after the node's P2P public key.
//! This is a reasonably unique identifier (even inside of an operator) so that
//! multiple operators can share the same database if they so desired. This is
//! also valuable if running multiple versions of a bridge from a shared database.
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

use foundationdb::{
    RetryableTransaction,
    directory::{Directory, DirectoryError, DirectoryLayer, DirectoryOutput, DirectorySubspace},
};
use strata_p2p_types::P2POperatorPubKey;

use crate::fdb::LAYER_ID;

/// Stores the key prefixes for different data types in the database.
#[derive(Debug)]
pub struct Directories {
    /// Root subspace for the database.
    pub root: DirectorySubspace,

    /// Subspace for storing Schnorr signatures.
    pub signatures: DirectorySubspace,
}

impl Directories {
    pub(crate) async fn setup(
        txn: &RetryableTransaction,
        node_pubkey: P2POperatorPubKey,
    ) -> Result<Self, DirectoryError> {
        let dir = DirectoryLayer::default();
        let DirectoryOutput::DirectorySubspace(root) = dir
            .create_or_open(txn, &[node_pubkey.to_string()], None, Some(LAYER_ID))
            .await?
        else {
            panic!("should receive a subspace")
        };

        let DirectoryOutput::DirectorySubspace(signatures) = root
            .create_or_open(txn, &["signatures".to_string()], None, Some(LAYER_ID))
            .await?
        else {
            panic!("should receive a subspace")
        };

        Ok(Self { root, signatures })
    }

    /// Clears all data stored in the directories. Only available in test mode.
    #[cfg(test)]
    pub async fn clear(&self, txn: &RetryableTransaction) -> Result<bool, DirectoryError> {
        let dir = DirectoryLayer::default();
        dir.remove_if_exists(txn, self.root.get_path()).await
    }
}
