import logging

from rpc.types import RpcCovenantId, RpcCurrentCovenant
from utils.utils import wait_until


def get_current_covenant(bridge_rpc) -> RpcCurrentCovenant:
    """Return the bridge node's current covenant and its deposit admission."""
    return RpcCurrentCovenant.from_json(bridge_rpc.stratabridge_currentCovenant())


def wait_until_current_covenant(
    bridge_rpcs: list,
    members: list[int],
    activation_height: int | None = None,
    admission_status: str = "ready",
    timeout: int = 600,
) -> RpcCovenantId:
    """Wait until every node reports the same current covenant with `members`.

    The covenant must also have `admission_status` and, when given, `activation_height`.
    Returns the covenant all nodes agree on.
    """
    result: dict[str, RpcCovenantId | None] = {"covenant": None}

    def check():
        reported = [get_current_covenant(rpc) for rpc in bridge_rpcs]
        logging.info(f"Current covenants: {reported}")
        matching = all(
            current.members == members
            and current.admission_status == admission_status
            and (
                activation_height is None or current.covenant.activation_height == activation_height
            )
            for current in reported
        )
        if not matching:
            return False

        covenants = {current.covenant for current in reported}
        assert len(covenants) == 1, f"nodes disagree on the current covenant: {reported}"
        result["covenant"] = covenants.pop()
        return True

    wait_until(
        check,
        timeout=timeout,
        step=1,
        error_msg=(
            f"Timeout after {timeout}s waiting for every node to report covenant members "
            f"{members} with admission `{admission_status}`"
            + ("" if activation_height is None else f" activated at {activation_height}")
        ),
    )
    covenant = result["covenant"]
    assert covenant is not None
    return covenant
