#!/bin/bash

BITCOIND_CONF_FILE=/home/bitcoin/bitcoin.conf

# Generate bitcoin.conf
cat <<EOF > ${BITCOIND_CONF_FILE}
regtest=1

[regtest]
rpcuser=user
rpcpassword=password
rpcbind=172.28.1.8:18443
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
zmqpubhashblock=tcp://172.28.1.8:28332
zmqpubhashtx=tcp://172.28.1.8:28333
zmqpubrawblock=tcp://172.28.1.8:28334
zmqpubrawtx=tcp://172.28.1.8:28335
zmqpubsequence=tcp://172.28.1.8:28336
EOF

bitcoind -daemon -conf=${BITCOIND_CONF_FILE}

sleep 1

GENERAL_WALLET_1=${GENERAL_WALLET_1}
STAKE_CHAIN_WALLET_1=${STAKE_CHAIN_WALLET_1}

GENERAL_WALLET_2=${GENERAL_WALLET_2}
STAKE_CHAIN_WALLET_2=${STAKE_CHAIN_WALLET_2}

GENERAL_WALLET_3=${GENERAL_WALLET_3}
STAKE_CHAIN_WALLET_3=${STAKE_CHAIN_WALLET_3}

# Generate a block to the address of the operator's general wallet
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 ${GENERAL_WALLET_1}
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 ${GENERAL_WALLET_2}
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 ${GENERAL_WALLET_3}
sleep 0.1

# mine enough blocks to the default wallet address to mature coinbase funds
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 createwallet default
MY_ADDRESS=$(bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 -rpcwallet=default getnewaddress)
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 104 $MY_ADDRESS

# send some funds to the stake chain wallet too
FUNDING_AMOUNT="0.00027720"
echo "sending ${FUNDING_AMOUNT} BTC to the stake chain wallet"
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 sendtoaddress ${STAKE_CHAIN_WALLET_1} ${FUNDING_AMOUNT}
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 $MY_ADDRESS
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 sendtoaddress ${STAKE_CHAIN_WALLET_2} ${FUNDING_AMOUNT}
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 $MY_ADDRESS
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 sendtoaddress ${STAKE_CHAIN_WALLET_3} ${FUNDING_AMOUNT}
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 $MY_ADDRESS
sleep 0.1

# Run forever
tail -f /dev/null
