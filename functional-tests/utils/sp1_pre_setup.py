def pre_fund_operators(rpc, miner_addr, operator_key_infos, btc_config):
    """Fund every operator with `btc_config.funding_amount`."""
    # Make sure we have one mature coinbase per operator to spend from.
    num_operators = len(operator_key_infos)
    shortfall = max(0, 100 + num_operators - btc_config.initial_blocks)
    if shortfall > 0:
        rpc.proxy.generatetoaddress(shortfall, miner_addr)

    # Queue all the funding sends; they'll wait in the mempool.
    for key in operator_key_infos:
        rpc.proxy.sendtoaddress(key.GENERAL_WALLET, btc_config.funding_amount)

    # One batched mine confirms every pending send at once.
    rpc.proxy.generatetoaddress(btc_config.finalization_blocks, miner_addr)
