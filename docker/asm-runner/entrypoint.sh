set -e

CONFIG_FILE="${CONFIG_FILE:-/app/config.toml}"
PARAMS_FILE="${PARAMS_FILE:-/app/asm-params.json}"

exec /usr/local/bin/strata-asm-runner --config "$CONFIG_FILE" --params "$PARAMS_FILE"
