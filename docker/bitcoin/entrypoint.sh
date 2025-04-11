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
MY_ADDRESS=$(bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 -rpcwallet=default getnewaddress)
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 104 $MY_ADDRESS

# send some funds to the stake chain wallet too
FUNDING_AMOUNT="0.00027720"
echo "sending ${FUNDING_AMOUNT} BTC to the stake chain wallet"
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 sendtoaddress bcrt1pn049qtjwy9ppz7ljjl9r3tmp60et9y0t3cdkdame4g0kldjj5dqs7t87hf ${FUNDING_AMOUNT}
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 $MY_ADDRESS
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 sendtoaddress bcrt1pga206rnnd9vchqvs5s0gax4v99pdzlml470f3tfw8nfaemmmu0wsjru24g ${FUNDING_AMOUNT}
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 $MY_ADDRESS
sleep 0.1

bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 sendtoaddress bcrt1pmpv05lwwpdncjjtglmrccj4q75krhrskhvkur4af7t3dma0s6hhsl7j55p ${FUNDING_AMOUNT}
bitcoin-cli -rpcuser=user -rpcpassword=password -regtest -rpcconnect=172.28.1.8 -rpcport=18443 generatetoaddress 1 $MY_ADDRESS
sleep 0.1

# Run forever
tail -f /dev/null
