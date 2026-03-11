#!/bin/bash -e

BITCOIND_CONF_FILE=/home/bitcoin/bitcoin.conf
BTC_USER=user
BTC_PASS=password


# Generate bitcoin.conf
cat <<EOF > ${BITCOIND_CONF_FILE}
regtest=1

[regtest]
rpcuser=${BTC_USER}
rpcpassword=${BTC_PASS}
rpcbind=0.0.0.0:18443
rpcallowip=0.0.0.0/0
fallbackfee=0.00001
server=1
txindex=1
printtoconsole=1
acceptnonstdtxn=1
minrelaytxfee=0.0
blockmintxfee=0.0
dustRelayFee=0.0
debug=zmq
debuglogfile=/home/bitcoin/daemon.log
zmqpubhashblock=tcp://0.0.0.0:28332
zmqpubhashtx=tcp://0.0.0.0:28333
zmqpubrawblock=tcp://0.0.0.0:28334
zmqpubrawtx=tcp://0.0.0.0:28335
zmqpubsequence=tcp://0.0.0.0:28336
EOF

bitcoind -daemon -conf=${BITCOIND_CONF_FILE}

sleep 1

GENERAL_WALLET_1=${GENERAL_WALLET_1}

GENERAL_WALLET_2=${GENERAL_WALLET_2}

GENERAL_WALLET_3=${GENERAL_WALLET_3}

bcli="bitcoin-cli -rpcuser=${BTC_USER} -rpcpassword=${BTC_PASS} -regtest -rpcconnect=127.0.0.1 -rpcport=18443"

# Fund the general wallets with enough funds.
$bcli generatetoaddress 10 ${GENERAL_WALLET_1}
sleep 0.1

$bcli generatetoaddress 10 ${GENERAL_WALLET_2}
sleep 0.1

$bcli generatetoaddress 10 ${GENERAL_WALLET_3}
sleep 0.1

# mine enough blocks to the default wallet address to mature coinbase funds
$bcli createwallet default
MY_ADDRESS=$($bcli -rpcwallet=default getnewaddress)
$bcli generatetoaddress 104 $MY_ADDRESS

# Run forever
if [ "$AUTOMINE" -ne 0 ]; then
    while true; do
        echo "generating a block to ${MY_ADDRESS}..."
        $bcli generatetoaddress 1 $MY_ADDRESS
        sleep $AUTOMINE;
    done
else
    tail -f /dev/null
fi
