#!/usr/bin/env python3
"""render_trivy_rollup.py — Aggregate per-image Trivy results into one summary table.

Called by the publish_report job in docker-publish-ecr.yml after all build jobs
complete. Each build job uploads a Trivy artifact named trivy-{component}-{tag};
this script downloads those artifacts, reads their JSON reports, and writes a
single rollup table to the GHA step summary so reviewers can see the overall
vulnerability posture of the publish run at a glance.

Artifact directory layout (after actions/download-artifact merges them):
    trivy-artifacts/
        trivy-strata-bridge-<tag>/
            strata-bridge.json
            strata-bridge.sarif
            strata-bridge.md
        trivy-rt-<tag>/
            rt.json
            ...

Expected env vars:
    IMAGE_TAG       — the short SHA tag used for all images in this run
    SUMMARY_PATH    — path to the GITHUB_STEP_SUMMARY file (injected by GHA as
                      the env var named in the workflow step's env block)

Output:
    trivy-rollup.md        — written to the working directory
    GITHUB_STEP_SUMMARY    — the rollup markdown is appended to the live job summary
"""

import json
import os
from collections import Counter
from pathlib import Path


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def strip_artifact_prefix(name: str, image_tag: str) -> str:
    """Extract the bare component name from an artifact directory name.

    Artifact dirs are named  trivy-{component}-{image_tag}  by the workflow.
    This strips the known prefix and suffix to recover the component name
    for use as a table row label.

    Example: "trivy-strata-bridge-abc12345" -> "strata-bridge"
    """
    if name.startswith("trivy-") and name.endswith(f"-{image_tag}"):
        return name[len("trivy-") : -(len(image_tag) + 1)]
    return name


def count_findings(json_path: Path) -> Counter:
    """Parse a Trivy JSON report and return a severity Counter.

    Aggregates vulnerabilities, misconfigurations, and secrets into a single
    counter keyed by severity string. Uses `or []` to guard against Trivy
    emitting null instead of an empty list for targets with no findings.
    """
    counts: Counter = Counter()
    data = json.loads(json_path.read_text())
    for target in data.get("Results", []):
        for vuln in target.get("Vulnerabilities", []) or []:
            counts[vuln.get("Severity", "UNKNOWN")] += 1
        for misconfig in target.get("Misconfigurations", []) or []:
            counts[misconfig.get("Severity", "UNKNOWN")] += 1
        for secret in target.get("Secrets", []) or []:
            counts[secret.get("Severity", "UNKNOWN")] += 1
    return counts


def main() -> None:
    image_tag = os.environ["IMAGE_TAG"]
    summary_path = os.environ["SUMMARY_PATH"]
    root = Path("trivy-artifacts")

    rows = []
    artifact_dirs = sorted(root.iterdir()) if root.exists() else []

    for artifact_dir in [p for p in artifact_dirs if p.is_dir()]:
        component = strip_artifact_prefix(artifact_dir.name, image_tag)
        json_files = list(artifact_dir.glob("*.json"))

        if json_files:
            counts = count_findings(json_files[0])
            status = "report available"
        else:
            counts = Counter()
            status = "no json report"

        rows.append({"component": component, "status": status, "counts": counts})

    # -----------------------------------------------------------------------
    # Build the rollup Markdown table
    # -----------------------------------------------------------------------
    lines: list[str] = ["## Trivy Rollup", ""]

    if not rows:
        lines += ["No Trivy artifacts were downloaded for this run.", ""]
    else:
        lines += [
            "| Image | Status | Critical | High | Medium | Low | Unknown |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for row in rows:
            c = row["counts"]
            lines.append(
                f"| {row['component']} | {row['status']}"
                f" | {c.get('CRITICAL', 0)}"
                f" | {c.get('HIGH', 0)}"
                f" | {c.get('MEDIUM', 0)}"
                f" | {c.get('LOW', 0)}"
                f" | {c.get('UNKNOWN', 0)} |"
            )
        lines += [
            "",
            "Artifacts contain the raw `.json`, `.sarif`, and per-image Markdown summaries.",
            "",
        ]

    markdown = "\n".join(lines) + "\n"

    Path("trivy-rollup.md").write_text(markdown, encoding="utf-8")

    # Append to the live step summary so it appears at the bottom of the job page.
    with open(summary_path, "a", encoding="utf-8") as f:
        f.write(markdown)


if __name__ == "__main__":
    main()
