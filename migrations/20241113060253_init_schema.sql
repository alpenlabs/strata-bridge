PRAGMA foreign_keys = ON;

-- Table for contracts
CREATE TABLE IF NOT EXISTS contracts (
    deposit_txid TEXT NOT NULL PRIMARY KEY, -- Store as hex string
    deposit_idx INTEGER NOT NULL UNIQUE,    -- Index of the deposit in the stake chain
    deposit_tx BLOB NOT NULL,               -- Serialized with bincode
    operator_table BLOB NOT NULL,           -- Serialized with bincode
    state TEXT NOT NULL                     -- JSON
);

-- Table for wots_public_keys with a compound index on (operator_idx, deposit_txid)
CREATE TABLE IF NOT EXISTS wots_public_keys (
    operator_idx INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL,  -- Store as hex string
    public_keys BLOB NOT NULL,   -- Serialized with rkyv
    PRIMARY KEY (operator_idx, deposit_txid)  -- Compound primary key
);

-- Table for wots_signatures with a compound index on (operator_idx, deposit_txid)
CREATE TABLE IF NOT EXISTS wots_signatures (
    operator_idx INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL,  -- Store as hex string
    signatures BLOB NOT NULL,    -- Serialized with rkyv
    PRIMARY KEY (operator_idx, deposit_txid)  -- Compound primary key
);

-- Table for signatures with a compound index on (operator_idx, txid, input_index)
CREATE TABLE IF NOT EXISTS signatures (
    operator_idx INTEGER NOT NULL,
    txid TEXT NOT NULL,          -- Store as hex string
    input_index INTEGER NOT NULL,
    signature TEXT NOT NULL,     -- Store as hex string
    PRIMARY KEY (operator_idx, txid, input_index)  -- Compound primary key
);

-- Table for nonces with a compound index on (operator_idx, txid, input_index)
CREATE TABLE IF NOT EXISTS nonces (
    operator_idx INTEGER NOT NULL,
    txid TEXT NOT NULL,          -- Store as hex string
    input_index INTEGER NOT NULL,
    nonce TEXT NOT NULL    ,     -- Store as hex string
    PRIMARY KEY (operator_idx, txid, input_index)  -- Compound primary key
);

-- Table for deposits with a primary key on deposit_txid mapping to an index that increments monotonically.
CREATE TABLE IF NOT EXISTS deposits (
    deposit_txid TEXT PRIMARY KEY,  -- Store as hex string
    deposit_id INTEGER UNIQUE NOT NULL
);

-- Table for stake transaction IDs.
CREATE TABLE IF NOT EXISTS operator_stake_txids (
    stake_id INTEGER NOT NULL,           -- Index that increments monotonically
    operator_idx INTEGER NOT NULL,
    stake_txid TEXT NOT NULL,            -- Store as hex string

    PRIMARY KEY (stake_id, operator_idx)  -- Compound primary key
);

-- Table to store operator pre-stake data
CREATE TABLE IF NOT EXISTS operator_pre_stake_data (
    operator_idx INTEGER PRIMARY KEY,            -- Unique operator id
    pre_stake_txid TEXT NOT NULL,                -- Store as hex string
    pre_stake_vout INTEGER NOT NULL
);

-- Table to store the stake chain txids for each operator id and deposit index in deposits table
CREATE TABLE IF NOT EXISTS operator_stake_data (
    operator_idx INTEGER NOT NULL,
    deposit_idx INTEGER NOT NULL,               -- Foreign key to deposits table
    funding_txid TEXT NOT NULL,                -- Store as hex string
    funding_vout INTEGER NOT NULL,
    hash TEXT NOT NULL,                        -- Store as hex string
    operator_descriptor TEXT NOT NULL,         -- Store as hex string
    withdrawal_fulfillment_pk BLOB NOT NULL,   -- Serialized with rkyv

    PRIMARY KEY (operator_idx, deposit_idx)     -- Compound primary key
);

-- Table to store the index of the last published stake transaction.
CREATE TABLE IF NOT EXISTS last_published_stake_index (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton row with a fixed id
    stake_index INTEGER NOT NULL                  -- Last fetched duty index
);

-- Table for claim_txid_to_operator_index_and_deposit_txid
CREATE TABLE IF NOT EXISTS claim_txid_to_operator_index_and_deposit_txid (
    claim_txid TEXT PRIMARY KEY,           -- Store as hex string
    operator_idx INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string
);

-- Table for post_assert_txid_to_operator_index_and_deposit_txid
CREATE TABLE IF NOT EXISTS post_assert_txid_to_operator_index_and_deposit_txid (
    post_assert_txid TEXT PRIMARY KEY,     -- Store as hex string
    operator_idx INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string
);

-- Table for assert_data_txid_to_operator_and_deposit with a primary key on assert_data_txid
CREATE TABLE IF NOT EXISTS assert_data_txid_to_operator_and_deposit (
    assert_data_txid TEXT PRIMARY KEY,     -- Store as hex string
    operator_idx INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string
);

-- Table for pre_assert_txid_to_operator_and_deposit with a primary key on pre_assert_data_txid
CREATE TABLE IF NOT EXISTS pre_assert_txid_to_operator_and_deposit (
    pre_assert_data_txid TEXT PRIMARY KEY, -- Store as hex string
    operator_idx INTEGER NOT NULL,
    deposit_txid TEXT NOT NULL             -- Store as hex string

);
-- Table to store public nonces for each operator
CREATE TABLE IF NOT EXISTS pub_nonces (
    operator_idx INTEGER NOT NULL,
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    pubnonce TEXT NOT NULL,
    PRIMARY KEY (operator_idx, txid, input_index)
);

-- Table to store aggregated nonces for each operator
CREATE TABLE IF NOT EXISTS aggregated_nonces (
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    agg_nonce TEXT NOT NULL,
    PRIMARY KEY (txid, input_index)
);

-- Table to store partial signatures for each operator
CREATE TABLE IF NOT EXISTS partial_signatures (
    operator_idx INTEGER NOT NULL,
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    partial_signature TEXT NOT NULL,
    PRIMARY KEY (operator_idx, txid, input_index)
);

-- Table to store witnesses for each operator
CREATE TABLE IF NOT EXISTS witnesses (
    operator_idx INTEGER NOT NULL,
    txid TEXT NOT NULL,
    input_index INTEGER NOT NULL,
    witness TEXT NOT NULL,
    PRIMARY KEY (operator_idx, txid, input_index)
);

-- Table to store duty status information with JSON serialization for the status
CREATE TABLE IF NOT EXISTS duty_tracker (
    duty_id TEXT PRIMARY KEY,             -- Unique identifier for each duty as an encoded txid
    status TEXT NOT NULL                  -- Status of the duty as JSON
);

-- Table to store relevant transactions observed on bitcoin
CREATE TABLE IF NOT EXISTS bitcoin_tx_index (
    txid TEXT PRIMARY KEY,                -- Unique identifier for each tx as an encoded txid
    tx TEXT NOT NULL                      -- The transaction stored as hex-encoded bytes
);

-- Table to store the last scanned Bitcoin block height
CREATE TABLE IF NOT EXISTS bitcoin_block_index_tracker (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Singleton table to store the latest block height
    block_height INTEGER NOT NULL          -- Last scanned block height
);

-- Table to store the last fetched duty index for tracking duty progress
CREATE TABLE IF NOT EXISTS duty_index_tracker (
    id INTEGER PRIMARY KEY CHECK (id = 1),      -- Singleton row with a fixed id
    last_fetched_duty_index INTEGER NOT NULL    -- Last fetched duty index
);

-- Table to store the checkpoint information when a withdrawal duty is received
CREATE TABLE IF NOT EXISTS strata_checkpoint (
    txid TEXT PRIMARY KEY,                      -- The deposit txid of the withdrawal duty for this checkpoint
    checkpoint_idx INTEGER NOT NULL             -- The latest checkpoint index associated with the duty
);
