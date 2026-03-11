set -e

CONFIG_FILE="${CONFIG_FILE:-/app/config.toml}"
PARAMS_FILE="${PARAMS_FILE:-/tmp/asm-params.json}"
BRIDGE_PARAMS_FILE="${BRIDGE_PARAMS_FILE:-/bridge/params.toml}"

python3 /usr/local/bin/gen_asm_params.py \
  --config "$CONFIG_FILE" \
  --bridge-params "$BRIDGE_PARAMS_FILE" \
  --output "$PARAMS_FILE"

exec /usr/local/bin/strata-asm-runner --config "$CONFIG_FILE" --params "$PARAMS_FILE"
