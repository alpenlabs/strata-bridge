# Push to ECR

This repository publishes bridge images through `.github/workflows/docker-publish-ecr.yml`.
The intended post-merge trigger is manual-only via `workflow_dispatch` so image publication stays explicit.

## Prerequisites

- Repository variables:
  - `AWS_REGION`
  - `ECR_REGISTRY`
  - `ECR_REPOSITORY_PREFIX`
  - `AWS_ROLE_TO_ASSUME`
  - `PUBLIC_AWS_ROLE_TO_ASSUME`
- Access to run the `Docker Publish to ECR` workflow in GitHub Actions.

## Workflow Inputs

- `ref`
  - Optional git branch, tag, or commit SHA to build.
  - If omitted, GitHub uses the branch selected in the workflow-dispatch UI.
- `components`
  - Optional comma-separated list of images to build.
  - Allowed values: `base`, `rt`, `strata-bridge`, `strata-asm-runner`, `secret-service`, `all`.
  - The default is `all`.
- `dependency_tag`
  - Required only when building final app images without rebuilding `base` and `rt`.
  - This must be an existing tag already published for both dependency images.

## Build Flow

1. The workflow resolves the checkout ref, commit SHA, image tag, and build matrices.
2. Dependency images `bridge-base` and `bridge-rt` are built with `docker buildx` and pushed to private ECR.
3. App images pull those dependency images back into the runner, build locally, run Trivy, then push to private and public ECR.
4. The final report job downloads all Trivy artifacts and writes a rollup summary.

## Component Rules

- `base` and `rt` are treated as a pair whenever app images are rebuilt alongside dependency images.
- If you build only app images, you must supply `dependency_tag` so the workflow can pull the matching dependency images.
- Trivy scans are advisory. Scan failures emit warnings and still upload artifacts and SARIF when available.

## Common Runs

Build everything from the selected branch:

- `components=all`

Rebuild only the final app images against an existing dependency tag:

- `components=strata-bridge,strata-asm-runner,secret-service`
- `dependency_tag=<existing-tag>`

Rebuild dependency images together with one app image:

- `components=base,rt,strata-bridge`

## Outputs

- Private images are published to `${ECR_REGISTRY}/${ECR_REPOSITORY_PREFIX}/...`.
- App images are also published to `public.ecr.aws/${PUBLIC_ECR_NAMESPACE}/...`.
- Trivy JSON, SARIF, and Markdown summaries are uploaded as GitHub Actions artifacts.
