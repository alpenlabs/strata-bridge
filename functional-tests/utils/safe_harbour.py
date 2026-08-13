"""Helpers for safe-harbour (hard bridge upgrade) sweep tests."""

import logging

from bitcoinlib.services.bitcoind import BitcoindClient

from constants import DT_DEPOSIT_VOUT
from factory.common.asm_params import DEFAULT_SAFE_HARBOUR_ADDRESS
from utils.deposit import wait_until_deposit_utxo_spent
from utils.dev_cli import DevCli
from utils.utils import find_utxo_spender_txid, read_operator_key, wait_until

# Pinned to the Rust fee helpers (crates/tx-graph/src/fee.rs): the sweep's pinned vsize and the
# P2TR minimal non-dust value its anchor carries.
SWEEP_VSIZE = 154
SWEEP_ANCHOR_VALUE_SATS = 330


def sweep_payout_value_sats(deposit_amount: int, sweep_fee_rate: int) -> int:
    """Expected sweep payout: the deposit minus the pinned-vsize fee and the anchor value."""
    return deposit_amount - sweep_fee_rate * SWEEP_VSIZE - SWEEP_ANCHOR_VALUE_SATS


def safe_harbour_script_hex() -> str:
    """P2TR scriptPubKey hex of the frozen safe-harbour address (OP_1 <x-only key>)."""
    # The BOSD descriptor hex is a type tag (04 = P2TR) followed by the 32-byte x-only key.
    return "5120" + DEFAULT_SAFE_HARBOUR_ADDRESS[2:]


def activate_safe_harbour(ctx, bridge_rpcs, timeout=180) -> str:
    """Publish a Defcon1 admin tx and wait until every operator latches the frozen address."""
    bitcoind_props = ctx.get_service("bitcoin").props
    operator_key_infos = [read_operator_key(i) for i in range(len(bridge_rpcs))]
    dev_cli = DevCli(bitcoind_props, operator_key_infos)

    txid = dev_cli.send_defcon1()
    logging.info(f"Broadcasted Defcon1 admin tx: {txid}")

    def all_latched():
        addresses = [rpc.stratabridge_safeHarbourAddress() for rpc in bridge_rpcs]
        logging.info(f"Safe-harbour addresses: {addresses}")
        return all(address == DEFAULT_SAFE_HARBOUR_ADDRESS for address in addresses)

    wait_until(
        all_latched,
        timeout=timeout,
        step=2,
        error_msg="operators did not latch the safe-harbour activation",
    )
    return txid


def wait_until_deposit_swept(bitcoin_rpc: BitcoindClient, deposit_txid: str, timeout=300) -> dict:
    """Wait until the deposit UTXO is spent and return the spending tx (verbose JSON)."""
    wait_until_deposit_utxo_spent(bitcoin_rpc, deposit_txid, timeout=timeout)
    spender_txid = find_utxo_spender_txid(bitcoin_rpc, deposit_txid, DT_DEPOSIT_VOUT)
    return bitcoin_rpc.proxy.getrawtransaction(spender_txid, True)


def assert_sweep_tx(
    sweep_tx: dict, deposit_txid: str, deposit_amount: int, sweep_fee_rate: int
) -> None:
    """Assert the sweep shape: one deposit input, the safe-harbour payout, and the anchor."""
    sweep_txid = sweep_tx["txid"]

    inputs = [(vin["txid"], vin["vout"]) for vin in sweep_tx.get("vin", [])]
    assert inputs == [(deposit_txid, DT_DEPOSIT_VOUT)], (
        f"sweep {sweep_txid} must spend exactly the deposit outpoint "
        f"{deposit_txid}:{DT_DEPOSIT_VOUT}; inputs: {inputs}"
    )

    outputs = sweep_tx.get("vout", [])
    assert len(outputs) == 2, (
        f"sweep {sweep_txid} must have a payout and an anchor output, got {len(outputs)}"
    )
    payout, anchor = outputs

    assert payout["scriptPubKey"]["hex"] == safe_harbour_script_hex(), (
        f"sweep {sweep_txid} payout does not pay the frozen safe-harbour address: "
        f"{payout['scriptPubKey']}"
    )
    expected_payout = sweep_payout_value_sats(deposit_amount, sweep_fee_rate)
    payout_sats = int(round(payout["value"] * 100_000_000))
    assert payout_sats == expected_payout, (
        f"sweep {sweep_txid} payout is {payout_sats} sats, expected {expected_payout}"
    )

    anchor_sats = int(round(anchor["value"] * 100_000_000))
    assert anchor_sats == SWEEP_ANCHOR_VALUE_SATS, (
        f"sweep {sweep_txid} anchor is {anchor_sats} sats, expected {SWEEP_ANCHOR_VALUE_SATS}"
    )
    assert anchor["scriptPubKey"]["type"] == "witness_v1_taproot", (
        f"sweep {sweep_txid} anchor must be the operator-keyed P2TR anchor: "
        f"{anchor['scriptPubKey']}"
    )
