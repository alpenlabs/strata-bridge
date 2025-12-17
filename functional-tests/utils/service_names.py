"""
Service naming constants and utilities for functional tests.
"""

BRIDGE_NODE_DIR = "bridge_node"
SECRET_SERVICE_DIR = "secret_service"


def get_operator_service_name(operator_idx: int, service_type: str) -> str:
    """
    Generate consistent operator service name.

    Args:
        operator_idx: The operator index (e.g., 0, 1, 2)
        service_type: The service type (BRIDGE_NODE_DIR or SECRET_SERVICE_DIR)

    Returns:
        Formatted service name like "operator-0/bridge_node"
    """
    return f"operator-{operator_idx}/{service_type}"


def get_operator_dir_name(operator_idx: int) -> str:
    """
    Generate consistent operator directory name.

    Args:
        operator_idx: The operator index (e.g., 0, 1, 2)

    Returns:
        Formatted directory name like "operator-1"
    """
    return f"operator-{operator_idx}"


def get_mtls_cred_path(operator_idx: int, service_type: str) -> str:
    """
    Generate consistent mTLS credential path.

    Args:
        operator_idx: The operator index
        service_type: The service type (BRIDGE_NODE_DIR or SECRET_SERVICE_DIR)

    Returns:
        Relative path like "../mtls_cred/operator_0/bridge_node/tls"
    """
    return f"../mtls_cred/operator_{operator_idx}/{service_type}/tls"
