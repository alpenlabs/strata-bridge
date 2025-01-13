//! Params related to the bridge tx graph connectors;
use std::time::Duration;

pub const NUM_PKS_A256_PER_CONNECTOR: usize = 7;
pub const NUM_PKS_A256: usize = 42;
pub const NUM_CONNECTOR_A256: usize = NUM_PKS_A256 / NUM_PKS_A256_PER_CONNECTOR;
pub const NUM_PKS_A256_RESIDUAL: usize = NUM_PKS_A256 % NUM_PKS_A256_PER_CONNECTOR;

pub const NUM_PKS_A160_PER_CONNECTOR: usize = 11;
pub const NUM_PKS_A160: usize = 574;
pub const NUM_CONNECTOR_A160: usize = NUM_PKS_A160 / NUM_PKS_A160_PER_CONNECTOR;
pub const NUM_PKS_A160_RESIDUAL: usize = NUM_PKS_A160 % NUM_PKS_A160_PER_CONNECTOR;

pub const TOTAL_CONNECTORS: usize = NUM_CONNECTOR_A256 + NUM_CONNECTOR_A160 + 1; // +1 for the
                                                                                 // residual A160(2 scripts) connectors

pub const NUM_ASSERT_DATA_TX1: usize = 1;
pub const NUM_ASSERT_DATA_TX1_A256_PK7: usize = 6;

pub const NUM_ASSERT_DATA_TX2: usize = 5;
pub const NUM_ASSERT_DATA_TX2_A160_PK11: usize = 9;

pub const NUM_ASSERT_DATA_TX3: usize = 1;
pub const NUM_ASSERT_DATA_TX3_A160_PK11: usize = 7;
pub const NUM_ASSERT_DATA_TX3_A160_PK2: usize = 1;

pub const NUM_ASSERT_DATA_TX: usize =
    NUM_ASSERT_DATA_TX1 + NUM_ASSERT_DATA_TX2 + NUM_ASSERT_DATA_TX3;

pub const TOTAL_VALUES: usize = NUM_ASSERT_DATA_TX1 * NUM_ASSERT_DATA_TX1_A256_PK7
    + NUM_ASSERT_DATA_TX2 * NUM_ASSERT_DATA_TX2_A160_PK11
    + NUM_ASSERT_DATA_TX3 * (NUM_ASSERT_DATA_TX3_A160_PK11 + NUM_ASSERT_DATA_TX3_A160_PK2);

// compile time to check to ensure that the numbers are sound.
const _: [(); 0] = [(); (TOTAL_VALUES - TOTAL_CONNECTORS)];

// FIXME: Move these to configurable params

pub const BLOCK_TIME: Duration = Duration::from_secs(30);

pub const SUPERBLOCK_MEASUREMENT_PERIOD: u32 = 100; // blocks

pub const TS_COMMITMENT_MARGIN: u32 = 288; // 2 days' worth of blocks in mainnet

pub const PAYOUT_OPTIMISTIC_TIMELOCK: u32 = 500;

const _: u32 =
    PAYOUT_OPTIMISTIC_TIMELOCK - (SUPERBLOCK_MEASUREMENT_PERIOD + TS_COMMITMENT_MARGIN + 100); // 100
                                                                                               // is slack

pub const PAYOUT_TIMELOCK: u32 = 288; // 2 day's worth of blocks in mainnet
