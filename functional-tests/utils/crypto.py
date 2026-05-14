"""Lightweight crypto helpers used by tests and config generators."""

from bitcoinlib.keys import Key


def xonly_pubkey(secret_hex: str) -> str:
    """Return the BIP-340 x-only public key (64-hex) for `secret_hex`."""
    pk = Key(secret_hex, is_private=True).public_hex
    assert pk is not None, f"bitcoinlib returned no pubkey for {secret_hex}"
    return pk[2:]
