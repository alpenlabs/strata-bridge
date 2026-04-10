#!/usr/bin/env python3
"""build_matrix.py — Generate JSON build matrices for docker-publish-ecr.yml

Each matrix entry describes one image: which Dockerfile to build, which ECR
repository to push to, and which Trivy scanner configuration to use.

Usage:
    python3 scripts/ci/build_matrix.py --kind <dependency|app>

Reads build flags from environment variables set by resolve_build_plan.sh:
    BUILD_BASE, BUILD_RT, BUILD_STRATA_BRIDGE, BUILD_ASM_RUNNER, BUILD_SECRET_SERVICE

Prints a JSON array to stdout. An empty list ([]) means "nothing to build" —
the downstream matrix job will be skipped by GitHub Actions automatically.
"""

import argparse
import json
import os
import sys


def _flag(name: str) -> bool:
    """Read a BUILD_* env var as a boolean ('true'/'false')."""
    return os.environ.get(name, "false") == "true"


def dependency_matrix() -> list[dict]:
    """
    Base and rt are the Rust compilation layers shared by all app images.
    They use buildx with type=gha cache so the expensive Rust compile step
    is reused across workflow runs. Scanning is limited to vulnerabilities
    since these are intermediate build artifacts, not final shipped images.
    """
    items = []

    if _flag("BUILD_BASE"):
        items.append({
            "component": "base",
            "display_name": "bridge-base",
            "repository": "bridge-base",
            "dockerfile": "docker/base.Dockerfile",
            "cache_scope": "bridge-base-linux-amd64",
            "trivy_scanners": "vuln",
            "trivy_timeout": "15m",
        })

    if _flag("BUILD_RT"):
        items.append({
            "component": "rt",
            "display_name": "bridge-rt",
            "repository": "bridge-rt",
            "dockerfile": "docker/rt.Dockerfile",
            "cache_scope": "bridge-rt-linux-amd64",
            "trivy_scanners": "vuln",
            "trivy_timeout": "15m",
        })

    return items


def app_matrix() -> list[dict]:
    """
    Final app images are built on top of the dependency layer and pushed to
    both private ECR and public ECR. They use a broader Trivy scan (vuln +
    secret + misconfig) since these are the images that actually run in prod.
    """
    items = []

    if _flag("BUILD_STRATA_BRIDGE"):
        items.append({
            "component": "strata-bridge",
            "display_name": "strata-bridge",
            "repository": "strata-bridge",
            "public_repository": "strata-bridge",
            "dockerfile": "docker/strata-bridge/Dockerfile",
            "local_tag": "strata-bridge:latest",
            "trivy_scanners": "vuln,secret,misconfig",
            "trivy_timeout": "15m",
        })

    if _flag("BUILD_ASM_RUNNER"):
        items.append({
            "component": "strata-asm-runner",
            "display_name": "strata-asm-runner",
            "repository": "strata-asm-runner",
            "public_repository": "strata-asm-runner",
            "dockerfile": "docker/asm-runner/Dockerfile",
            "local_tag": "strata-asm-runner:latest",
            "trivy_scanners": "vuln,secret,misconfig",
            "trivy_timeout": "15m",
        })

    if _flag("BUILD_SECRET_SERVICE"):
        items.append({
            "component": "secret-service",
            "display_name": "secret-service",
            "repository": "secret-service",
            "public_repository": "secret-service",
            "dockerfile": "docker/secret-service/Dockerfile",
            "local_tag": "secret-service:latest",
            "trivy_scanners": "vuln,secret,misconfig",
            "trivy_timeout": "15m",
        })

    return items


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a JSON build matrix.")
    parser.add_argument(
        "--kind",
        required=True,
        choices=["dependency", "app"],
        help="Which matrix to generate: 'dependency' (base/rt) or 'app' (final images).",
    )
    args = parser.parse_args()

    matrix = dependency_matrix() if args.kind == "dependency" else app_matrix()
    print(json.dumps(matrix))


if __name__ == "__main__":
    main()
