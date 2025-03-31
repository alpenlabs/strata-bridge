#!/bin/bash

bitcoind -daemon -server -txindex -printtoconsole -regtest -rpcallowip=0.0.0.0/0 -rpcbind=172.28.1.6:18443 -rpcuser=user -rpcpassword=password

sleep 2

# TESTING
# Generate 101 blocks to the address of the operator wallet
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.6 -rpcport=18443 generatetoaddress 101 bcrt1p8whq75c5u2ccy00y7amzrlkc453acatz2fhcwjhks425qf5zx8pqqmvn20

# Run forever
tail -f /dev/null