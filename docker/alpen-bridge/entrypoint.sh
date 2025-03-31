MODE="${MODE:-op}"
PARAMS_FILE="${PARAMS_FILE:-/app/params.toml}"
CONFIG_FILE="${CONFIG_FILE:-/app/config.toml}"

sleep 5 # wait for bitcoind to be ready

/usr/local/bin/alpen-bridge $MODE --params $PARAMS_FILE --config $CONFIG_FILE
