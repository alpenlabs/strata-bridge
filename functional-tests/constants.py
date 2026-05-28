DD_ROOT = "_dd"
TEST_DIR: str = "tests"
BRIDGE_NODE_DIR = "bridge_node"
SECRET_SERVICE_DIR = "secret_service"
BLOCK_GENERATION_INTERVAL_SECS = 2
MEMPOOL_POLL_INTERVAL_SECS = 1
BRIDGE_NETWORK_SIZE = 3
DEFAULT_LOG_LEVEL = "DEBUG"
ASM_MAGIC_BYTES = "ALPN"
MOSAIC_DIR = "mosaic"

# ASM-param artifacts written under each env's `ASM_PARAMS_DIR`, consumed by the
# asm-runner, the bridge-proof host, and SP1 guest ELF.
ASM_PARAMS_DIR = "generated"
ASM_PARAMS_FILE = "asm-params.json"
ASM_VK_FILE = "asm-vk.json"
MOHO_VK_FILE = "moho-vk.json"

# Deposit Transaction output indices
DT_DEPOSIT_VOUT = 1  # Deposit funds locked in N/N taproot

# Game-graph tx output indices, mirrored from the Rust tx-graph crate.
# Naming follows `<SOURCE_TX>_<OUTPUT>_VOUT`.
CLAIM_CONTEST_VOUT = 0
CLAIM_PAYOUT_VOUT = 1
CONTEST_PROOF_VOUT = 0
CONTEST_PAYOUT_VOUT = 1
CONTEST_WATCHTOWER_0_VOUT = 3
COUNTERPROOF_ACK_NACK_VOUT = 0

# Bridge protocol params
# Bridge supports this as u16, this is the max value
MAX_BRIDGE_TIMEOUT = (1 << 16) - 1

# Test signing keys for the asm-runner's native backend (asm-stf + moho hosts).
NATIVE_TEST_ASM_SIGNING_KEY = "01" * 32
NATIVE_TEST_MOHO_SIGNING_KEY = "02" * 32
NATIVE_TEST_BRIDGE_PROOF_SIGNING_KEY = "03" * 32
NATIVE_TEST_COUNTERPROOF_SIGNING_KEY = "04" * 32

# Late import: `utils/__init__.py` eagerly re-exports `utils.bridge` etc., which
# pull other constants from this module at load time. Importing `utils.crypto`
# at the top of this file would resolve those submodules before their constants
# exist and raise a circular ImportError. Placing the import after all
# `from constants import …` consumers' inputs are defined breaks the cycle.
from utils.crypto import xonly_pubkey  # noqa: E402

NATIVE_TEST_ASM_VERIFYING_KEY = xonly_pubkey(NATIVE_TEST_ASM_SIGNING_KEY)
NATIVE_TEST_MOHO_VERIFYING_KEY = xonly_pubkey(NATIVE_TEST_MOHO_SIGNING_KEY)
NATIVE_TEST_BRIDGE_PROOF_VERIFYING_KEY = xonly_pubkey(NATIVE_TEST_BRIDGE_PROOF_SIGNING_KEY)
NATIVE_TEST_COUNTERPROOF_VERIFYING_KEY = xonly_pubkey(NATIVE_TEST_COUNTERPROOF_SIGNING_KEY)
