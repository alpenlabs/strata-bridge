pub(crate) const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub(crate) const DEFAULT_RPC_PORT: u32 = 4781;

pub(crate) const DUTY_QUEUE_SIZE: usize = 100; // needed since the withdrawal duty never clears up
                                               // in strata.
                                               // TODO: adjust once fixed in strata or
                                               // when the new duty tracker is merged, whichever happens first
pub(crate) const DEPOSIT_QUEUE_MULTIPLIER: usize = 2;
pub(crate) const COVENANT_QUEUE_MULTIPLIER: usize = 10;

pub(crate) const VERIFIER_DUTY_QUEUE_SIZE: usize = 20; // only one verifier so needs a lot of buffer

pub(crate) const DEFAULT_NUM_THREADS: usize = 3;
pub(crate) const DEFAULT_STACK_SIZE_MB: usize = 512;

pub(crate) const PUBLIC_DB_NAME: &str = "public.db";
pub(crate) const DUTY_TRACKER_DB_NAME: &str = "duty_tracker.db";
pub(crate) const BITCOIN_BLOCK_TRACKER_DB_NAME: &str = "btc_block_tracker.db";
pub(crate) const OPERATOR_DB_PREFIX: &str = "operator_";
