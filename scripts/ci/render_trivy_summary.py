#!/usr/bin/env python3
"""render_trivy_summary.py — Write a per-image Trivy scan summary as Markdown.

Called by .github/actions/trivy-scan/action.yml after both scan steps complete.
Reads the JSON report produced by trivy-action, counts findings by severity,
and writes a Markdown summary that is:
  - printed to the GHA job log (via GITHUB_STEP_SUMMARY)
  - stored as a .md file inside trivy-results/ for the rollup job to reuse

Using Python instead of jq/shell because Trivy's JSON schema is inconsistent:
Results[].Vulnerabilities (and Misconfigurations/Secrets) can be a list, a dict,
or null depending on the scanner mode and image content. Python handles all three
cases cleanly without fragile shell conditionals.

Expected env vars (all injected by the action's step env: block):
    COMPONENT_DISPLAY_NAME  — human-readable image name for headings
    COMPONENT_NAME          — short identifier used for file names (e.g. "rt")
    IMAGE_REPOSITORY        — ECR repository path
    IMAGE_TAG               — image tag (short SHA)
    ECR_REGISTRY            — ECR registry URL
    ECR_REPOSITORY_PREFIX   — ECR path prefix
    TRIVY_STATUS            — "success" or "failed" from the scan step
    TRIVY_JSON_RC           — exit code of the JSON scan step
    TRIVY_SARIF_RC          — exit code of the SARIF scan step
    TRIVY_JSON_EXISTS       — "true" if trivy-results/{component}.json was produced
    TRIVY_SCANNERS          — comma-separated scanners (e.g. "vuln,secret,misconfig")
    TRIVY_TIMEOUT           — scan timeout string (e.g. "15m")

Output:
    trivy-results/{COMPONENT_NAME}.md
"""

import json
import os
from collections import Counter
from pathlib import Path


# Canonical severity ordering used for sorting findings and the summary table.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def iter_items(value: object) -> list[dict]:
    """Normalise a Trivy result field to a list of dicts.

    Trivy can emit lists, dicts, or null for the same field across different
    scanner modes. This normaliser ensures the caller always gets a flat list
    of dict items regardless of what Trivy actually produced.
    """
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [item for item in value.values() if isinstance(item, dict)]
    return []


def main() -> None:
    component = os.environ["COMPONENT_DISPLAY_NAME"]
    component_name = os.environ["COMPONENT_NAME"]
    image_ref = (
        f"{os.environ['ECR_REGISTRY']}"
        f"/{os.environ['ECR_REPOSITORY_PREFIX']}"
        f"/{os.environ['IMAGE_REPOSITORY']}"
        f":{os.environ['IMAGE_TAG']}"
    )

    counts: Counter = Counter()
    findings: list[dict] = []
    lines: list[str] = []

    # -----------------------------------------------------------------------
    # Header — always written regardless of whether scan output exists
    # -----------------------------------------------------------------------
    lines += [
        f"### Trivy Summary: {component}",
        "",
        f"`{image_ref}`",
        "",
        f"- Status: `{os.environ.get('TRIVY_STATUS', 'unknown')}`",
        f"- Scanners: `{os.environ['TRIVY_SCANNERS']}`",
        f"- Timeout: `{os.environ['TRIVY_TIMEOUT']}`",
        f"- Exit codes: json=`{os.environ.get('TRIVY_JSON_RC', '')}` sarif=`{os.environ.get('TRIVY_SARIF_RC', '')}`",
        "",
    ]

    # -----------------------------------------------------------------------
    # Body — only written when the JSON report was produced
    # -----------------------------------------------------------------------
    if os.environ.get("TRIVY_JSON_EXISTS") != "true":
        lines += ["Trivy did not produce a JSON report for this image.", ""]
    else:
        results = json.loads(Path(f"trivy-results/{component_name}.json").read_text())

        for target in results.get("Results", []):
            if not isinstance(target, dict):
                continue
            target_name = target.get("Target", "unknown")

            for vuln in iter_items(target.get("Vulnerabilities")):
                severity = vuln.get("Severity", "UNKNOWN")
                counts[severity] += 1
                findings.append({
                    "severity": severity,
                    "target": target_name,
                    "kind": "vuln",
                    "id": vuln.get("VulnerabilityID", "unknown"),
                })

            for misconfig in iter_items(target.get("Misconfigurations")):
                severity = misconfig.get("Severity", "UNKNOWN")
                counts[severity] += 1
                findings.append({
                    "severity": severity,
                    "target": target_name,
                    "kind": "misconfig",
                    "id": misconfig.get("ID", "unknown"),
                })

            for secret in iter_items(target.get("Secrets")):
                severity = secret.get("Severity", "UNKNOWN")
                counts[severity] += 1
                findings.append({
                    "severity": severity,
                    "target": target_name,
                    "kind": "secret",
                    "id": secret.get("RuleID", "secret"),
                })

        # Sort by severity (CRITICAL first), then by ID for stable ordering.
        findings.sort(key=lambda f: (
            SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
            f["id"],
            f["target"],
        ))

        # Severity count table
        lines += [
            "| CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |",
            "| --- | --- | --- | --- | --- |",
            "| " + " | ".join(str(counts.get(s, 0)) for s in SEVERITY_ORDER) + " |",
            "",
        ]

        if findings:
            # Show only the top 10 findings to keep the summary scannable.
            lines += [
                "Top findings:",
                "",
                "| Severity | Type | ID | Target |",
                "| --- | --- | --- | --- |",
            ]
            for f in findings[:10]:
                lines.append(f"| {f['severity']} | {f['kind']} | `{f['id']}` | `{f['target']}` |")
            lines.append("")
        else:
            lines += ["No Trivy findings detected.", ""]

    Path(f"trivy-results/{component_name}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
