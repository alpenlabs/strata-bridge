#!/bin/bash

bitcoind -daemon -server -txindex -printtoconsole -regtest -rpcallowip=0.0.0.0/0 -rpcbind=172.28.1.8:18443 -rpcuser=user -rpcpassword=password -zmqpubhashblock=tcp://172.28.1.8:28332 -zmqpubhashtx=tcp://172.28.1.8:28333 -zmqpubrawblock=tcp://172.28.1.8:28334 -zmqpubrawtx=tcp://172.28.1.8:28335 -zmqpubsequence=tcp://172.28.1.8:28336 -fallbackfee=0.00001 -debug=zmq -debuglogfile=/home/bitcoin/daemon.log

sleep 1

# TESTING
# Generate a block to the address of the operator's general wallet
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 bcrt1p8whq75c5u2ccy00y7amzrlkc453acatz2fhcwjhks425qf5zx8pqqmvn20
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 bcrt1pjrd2pungnh6ae7acw9dt92t5hj8gkn2gh8nuwu2r3kakklkswqrquyus8n
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 bcrt1p8ctkj8tl2zxxhlt8ux8qyha0yxlg43yjvqwd6v2fl6acrnt3xrcq62cv6k
sleep 0.1

# mine enough blocks to the default wallet address to mature coinbase funds
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 createwallet default
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 loadwallet default
MY_ADDRESS=$(bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 -rpcwallet=default getnewaddress)
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 101 $MY_ADDRESS

# Run forever
tail -f /dev/null
