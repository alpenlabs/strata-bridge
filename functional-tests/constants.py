DD_ROOT = "_dd"
TEST_DIR: str = "tests"
BRIDGE_NODE_DIR = "bridge_node"
SECRET_SERVICE_DIR = "secret_service"
BLOCK_GENERATION_INTERVAL_SECS = 2
BRIDGE_NETWORK_SIZE = 3
DEFAULT_LOG_LEVEL = "DEBUG"
ASM_MAGIC_BYTES = "ALPN"
MOSAIC_DIR = "mosaic"

# Deposit Transaction output indices
DT_DEPOSIT_VOUT = 1  # Deposit funds locked in N/N taproot

# Game-graph tx output indices, mirrored from the Rust tx-graph crate.
# Naming follows `<SOURCE_TX>_<OUTPUT>_VOUT`.
CLAIM_CONTEST_VOUT = 0
CONTEST_PROOF_VOUT = 0
CONTEST_PAYOUT_VOUT = 1
CONTEST_WATCHTOWER_0_VOUT = 3
COUNTERPROOF_ACK_NACK_VOUT = 0

# Bridge protocol params
# Bridge supports this as u16, this is the max value
MAX_BRIDGE_TIMEOUT = (1 << 16) - 1
