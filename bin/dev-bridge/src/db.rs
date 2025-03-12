use std::{
    env, fs,
    path::{Path, PathBuf},
};

use sqlx::{
    self,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use strata_bridge_db::persistent::sqlite::SqliteDb;
use tracing::info;

pub async fn create_db(datadir: impl AsRef<Path>, db_name: &str) -> SqliteDb {
    let db_path = create_db_file(datadir, db_name);

    let connect_options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);

    let pool_options = SqlitePoolOptions::new();

    let pool = pool_options
        .connect_with(connect_options)
        .await
        .expect("should be able to connect to db");

    let current_dir = env::current_dir().expect("should be able to get current working directory");
    let migrations_path = current_dir.join("migrations");

    let migrator = Migrator::new(migrations_path)
        .await
        .expect("should be able to initialize migrator");

    info!(action = "running migrations", %db_name);
    migrator
        .run(&pool)
        .await
        .expect("should be able to run migrations");

    SqliteDb::new(pool)
}

fn create_db_file(datadir: impl AsRef<Path>, db_name: &str) -> PathBuf {
    if !datadir.as_ref().exists() {
        fs::create_dir_all(datadir.as_ref())
            .map_err(|e| {
                panic!(
                    "could not create datadir at {:?} due to {}",
                    datadir.as_ref().canonicalize(),
                    e
                );
            })
            .unwrap();
    }

    let db_path = datadir.as_ref().join(db_name);

    if !db_path.exists() {
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false) // don't overwrite the file
            .open(db_path.as_path())
            .map_err(|e| {
                panic!(
                    "could not create public db at {:?} due to {}",
                    db_path.to_string_lossy(),
                    e
                );
            })
            .unwrap();
    }

    db_path
}
