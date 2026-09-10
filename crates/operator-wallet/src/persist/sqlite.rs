//! SQLite-backed [`WalletStore`](super::WalletStore) on BDK's own persister.
//!
//! BDK owns the schema, its migrations, the changeset encoding, and the stored network and
//! descriptor that [`load_or_create`](super::load_or_create) checks. This adapter adds only:
//!
//! - WAL journaling with full synchronous commits, so a persist that returned `Ok` survives a
//!   crash;
//! - `quick_check` at open, so a damaged file fails before anything reads or writes it;
//! - a sync-to-async bridge that commits inline, since a batch commits in milliseconds.

use std::{
    fmt, fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use bdk_wallet::{
    rusqlite::{self, Connection},
    AsyncWalletPersister, ChangeSet, WalletPersister,
};
use thiserror::Error;

/// Lock wait before a busy connection errors. A safety net: only one process holds a store.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Which operator wallet a store belongs to. Selects the file name, so the two wallets can never
/// open each other's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletKind {
    /// General-funds wallet.
    General,
    /// Reserved wallet holding the claim-funding pool.
    Reserved,
}

impl WalletKind {
    /// Both kinds, in a fixed order.
    pub const ALL: [Self; 2] = [Self::General, Self::Reserved];

    /// Store file name inside the data directory.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::General => "general-wallet.sqlite",
            Self::Reserved => "reserved-wallet.sqlite",
        }
    }

    /// Store path inside `data_dir`.
    pub fn path_in(self, data_dir: &Path) -> PathBuf {
        data_dir.join(self.file_name())
    }
}

impl fmt::Display for WalletKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::General => "general",
            Self::Reserved => "reserved",
        })
    }
}

/// Errors from a [`SqliteStore`]. Every variant names the file so the operator can act on it.
#[derive(Debug, Error)]
pub enum SqliteStoreError {
    /// The parent directory could not be created.
    #[error("could not create wallet store directory {dir}: {source}")]
    CreateDir {
        /// Directory that could not be created.
        dir: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// SQLite failed: unreadable file, schema problem, or I/O error.
    #[error("wallet store {path}: {source}")]
    Sqlite {
        /// Store file.
        path: PathBuf,
        /// Underlying SQLite error.
        #[source]
        source: rusqlite::Error,
    },
    /// `quick_check` found structural damage.
    #[error("wallet store {path} failed its integrity check: {report}")]
    Corrupt {
        /// Store file.
        path: PathBuf,
        /// First line of the integrity report.
        report: String,
    },
    /// WAL journaling could not be enabled, so commits would not be durable.
    #[error("wallet store {path} could not enable WAL journaling (journal_mode is {mode})")]
    JournalMode {
        /// Store file.
        path: PathBuf,
        /// Journal mode SQLite reported instead.
        mode: String,
    },
}

/// SQLite-backed wallet store; see the [module docs](self) for what it adds over BDK's persister.
pub struct SqliteStore {
    path: PathBuf,
    conn: Mutex<Connection>,
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteStore {
    /// Opens the store at `path`, creating the file and its parent directory if needed.
    ///
    /// A new or empty file passes `quick_check` and loads as absent, which is the right outcome
    /// for a crash between file creation and the first commit. Nothing is written to a file that
    /// fails to open.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SqliteStoreError> {
        let path = path.into();
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(|source| SqliteStoreError::CreateDir {
                dir: dir.to_path_buf(),
                source,
            })?;
        }
        let sqlite = |source| SqliteStoreError::Sqlite {
            path: path.clone(),
            source,
        };

        let conn = Connection::open(&path).map_err(sqlite)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(sqlite)?;

        // Before any mutating pragma: switching journal mode rewrites the header, which would
        // modify a file this open is about to reject.
        let report: String = conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .map_err(sqlite)?;
        if report != "ok" {
            return Err(SqliteStoreError::Corrupt { path, report });
        }

        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(sqlite)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(SqliteStoreError::JournalMode { path, mode });
        }
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(sqlite)?;

        Ok(Self {
            path,
            conn: Mutex::new(conn),
        })
    }

    /// Opens the store for `kind` inside `data_dir`. See [`Self::open`].
    pub fn open_in_dir(data_dir: &Path, kind: WalletKind) -> Result<Self, SqliteStoreError> {
        Self::open(kind.path_in(data_dir))
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sqlite_error(&self, source: rusqlite::Error) -> SqliteStoreError {
        SqliteStoreError::Sqlite {
            path: self.path.clone(),
            source,
        }
    }
}

type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SqliteStoreError>> + Send + 'a>>;

impl AsyncWalletPersister for SqliteStore {
    type Error = SqliteStoreError;

    fn initialize<'a>(persister: &'a mut Self) -> StoreFuture<'a, ChangeSet>
    where
        Self: 'a,
    {
        Box::pin(async move {
            let mut conn = persister.conn();
            WalletPersister::initialize(&mut *conn).map_err(|e| persister.sqlite_error(e))
        })
    }

    fn persist<'a>(persister: &'a mut Self, changeset: &'a ChangeSet) -> StoreFuture<'a, ()>
    where
        Self: 'a,
    {
        Box::pin(async move {
            let mut conn = persister.conn();
            WalletPersister::persist(&mut *conn, changeset).map_err(|e| persister.sqlite_error(e))
        })
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::{
        bitcoin::{
            secp256k1::{Keypair, Secp256k1, SecretKey},
            Network, XOnlyPublicKey,
        },
        descriptor,
        descriptor::ExtendedDescriptor,
        LoadError, LoadMismatch,
    };

    use super::*;
    use crate::persist::{load_or_create, InitError, PersistedWallet};

    fn xonly(seed: u8) -> XOnlyPublicKey {
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0
    }

    fn tr_descriptor(seed: u8) -> ExtendedDescriptor {
        descriptor!(tr(xonly(seed))).expect("valid descriptor").0
    }

    /// Opens the store for `kind` and loads or creates the wallet for `seed` in it.
    async fn open_wallet(
        dir: &Path,
        kind: WalletKind,
        seed: u8,
    ) -> Result<(SqliteStore, PersistedWallet<SqliteStore>), InitError<SqliteStoreError>> {
        let mut store = SqliteStore::open_in_dir(dir, kind).map_err(InitError::Store)?;
        let wallet =
            load_or_create(&mut store, tr_descriptor(seed), Network::Regtest, None).await?;
        Ok((store, wallet))
    }

    #[tokio::test]
    async fn create_then_reopen_loads_and_uses_wal() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = open_wallet(dir.path(), WalletKind::General, 1)
            .await
            .unwrap();
        assert!(dir.path().join("general-wallet.sqlite").exists());
        let mode: String = store
            .conn()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let sync: i64 = store
            .conn()
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "FULL");
        drop(store);

        // A second open on a populated store can only succeed by loading: the create path would
        // fail with `DataAlreadyExists`.
        let (store, _) = open_wallet(dir.path(), WalletKind::General, 1)
            .await
            .unwrap();
        let wallets: i64 = store
            .conn()
            .query_row("SELECT count(*) FROM bdk_wallet", [], |r| r.get(0))
            .unwrap();
        assert_eq!(wallets, 1, "one wallet row, written once");
    }

    #[test]
    fn garbage_file_is_rejected_and_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = WalletKind::Reserved.path_in(dir.path());
        let garbage = b"definitely not a sqlite database; padded well past the header\n".repeat(40);
        fs::write(&path, &garbage).unwrap();

        let err = SqliteStore::open(&path).expect_err("garbage must not open");
        assert!(
            matches!(
                err,
                SqliteStoreError::Sqlite { .. } | SqliteStoreError::Corrupt { .. }
            ),
            "got {err}"
        );
        assert!(err.to_string().contains("reserved-wallet.sqlite"), "{err}");
        assert_eq!(
            fs::read(&path).unwrap(),
            garbage,
            "rejected file is left intact"
        );
    }

    /// Offsets 18 and 19 of the SQLite header are the write and read format versions: 1 for a
    /// rollback journal, 2 for WAL. `PRAGMA journal_mode=WAL` rewrites both.
    fn header_format_versions(path: &Path) -> [u8; 2] {
        let header = fs::read(path).unwrap();
        [header[18], header[19]]
    }

    #[test]
    fn structurally_damaged_file_is_rejected_before_the_journal_mode_is_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = WalletKind::General.path_in(dir.path());

        // A rollback-journal database (as a restored backup or a file from another tool may be)
        // with an intact header and a corrupted b-tree page: `quick_check` fails, but the
        // journal-mode switch would have succeeded and rewritten the header first.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=DELETE; \
             CREATE TABLE t(v TEXT); \
             WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 400) \
             INSERT INTO t(v) SELECT hex(zeroblob(64)) FROM c;",
        )
        .unwrap();
        drop(conn);
        assert_eq!(header_format_versions(&path), [1, 1], "not WAL yet");
        let mut bytes = fs::read(&path).unwrap();
        assert!(
            bytes.len() > 8192,
            "table must span more than the first page"
        );
        bytes[4096] = 0xFF; // page 2's b-tree page type
        fs::write(&path, &bytes).unwrap();

        let err = SqliteStore::open(&path).expect_err("damaged file must not open");
        assert!(
            matches!(
                err,
                SqliteStoreError::Corrupt { .. } | SqliteStoreError::Sqlite { .. }
            ),
            "got {err}"
        );
        assert_eq!(
            header_format_versions(&path),
            [1, 1],
            "a rejected file must not have its journal mode rewritten"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            bytes,
            "rejected file left untouched"
        );
    }

    #[tokio::test]
    async fn kinds_use_distinct_files_and_never_share_state() {
        let dir = tempfile::tempdir().unwrap();
        open_wallet(dir.path(), WalletKind::General, 1)
            .await
            .unwrap();
        open_wallet(dir.path(), WalletKind::Reserved, 2)
            .await
            .unwrap();
        assert_ne!(
            WalletKind::General.path_in(dir.path()),
            WalletKind::Reserved.path_in(dir.path())
        );

        // Opening the general store with the reserved descriptor is a mismatch, not a load.
        let err = open_wallet(dir.path(), WalletKind::General, 2)
            .await
            .expect_err("descriptor mismatch");
        assert!(matches!(
            err,
            InitError::InvalidState(e) if matches!(*e, LoadError::Mismatch(LoadMismatch::Descriptor { .. }))
        ));
        open_wallet(dir.path(), WalletKind::Reserved, 2)
            .await
            .expect("own descriptor still loads");
    }
}
