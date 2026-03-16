DD_ROOT = "_dd"
TEST_DIR: str = "tests"
BRIDGE_NODE_DIR = "bridge_node"
SECRET_SERVICE_DIR = "secret_service"
BLOCK_GENERATION_INTERVAL_SECS = 2
BRIDGE_NETWORK_SIZE = 3
DEFAULT_LOG_LEVEL = "DEBUG"
ASM_MAGIC_BYTES = "ALPN"

# Deposit Transaction output indices
DT_DEPOSIT_VOUT = 1  # Deposit funds locked in N/N taproot

# Bridge protocol params
# Bridge supports this as u16, this is the max value
MAX_BRIDGE_TIMEOUT = (1 << 16) - 1
