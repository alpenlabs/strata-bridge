#!/usr/bin/env python3
"""render_publish_overview.py — Write the publish-run overview to the job summary."""

import json
import os


def format_private_image(repository: str, image_tag: str) -> str:
    return (
        f"{os.environ['ECR_REGISTRY']}"
        f"/{os.environ['ECR_REPOSITORY_PREFIX']}"
        f"/{repository}:{image_tag}"
    )


def format_public_image(repository: str, image_tag: str) -> str:
    return (
        f"{os.environ['PUBLIC_ECR_REGISTRY']}"
        f"/{os.environ['PUBLIC_ECR_NAMESPACE']}"
        f"/{repository}:{image_tag}"
    )


def main() -> None:
    image_tag = os.environ["IMAGE_TAG"]
    dependency_tag = os.environ["DEPENDENCY_TAG"]
    dependency_matrix = json.loads(os.environ["DEPENDENCY_MATRIX"])
    app_matrix = json.loads(os.environ["APP_MATRIX"])

    lines = [
        "## Docker Publish to ECR",
        "",
        f"- Workflow ref: `{os.environ['WORKFLOW_REF']}`",
        f"- Checkout ref: `{os.environ['CHECKOUT_REF']}`",
        f"- Resolved commit: `{os.environ['RESOLVED_SHA']}`",
        f"- Image tag: `{image_tag}`",
        f"- Dependency tag: `{dependency_tag}`",
        "- Scan mode: advisory",
        "",
        "### Selected Images",
    ]

    if not dependency_matrix and not app_matrix:
        lines += ["- None", ""]
    else:
        for item in dependency_matrix:
            lines.append(f"- `{format_private_image(item['repository'], image_tag)}`")
        for item in app_matrix:
            lines.append(f"- `{format_private_image(item['repository'], image_tag)}`")
            lines.append(f"  public: `{format_public_image(item['public_repository'], image_tag)}`")
        lines.append("")

    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
