#!/usr/bin/env bash
# resolve_build_plan.sh — Compute the build plan for docker-publish-ecr.yml
#
# Reads workflow inputs from environment variables, resolves git refs,
# determines which images to build, enforces dependency pairing rules,
# and writes all outputs to GITHUB_OUTPUT so downstream jobs can consume
# them as a single JSON payload instead of repeating logic in YAML conditionals.
#
# Expected env vars (all injected by the workflow step):
#   GITHUB_EVENT_NAME     — "push" or "workflow_dispatch"
#   GITHUB_REF            — current ref (set by GHA on push events)
#   GITHUB_SHA            — current commit SHA
#   INPUT_REF             — optional override ref from workflow_dispatch input
#   INPUT_COMPONENTS      — comma-separated list of components to build, or "all"
#   INPUT_DEPENDENCY_TAG  — optional existing ECR tag for base/rt when not rebuilding them
#   GITHUB_OUTPUT         — path to the GHA outputs file (set by the runner)

set -euo pipefail

# ---------------------------------------------------------------------------
# 1. Resolve checkout ref and image tag
# ---------------------------------------------------------------------------

# If a manual ref override was supplied use it; fall back to GITHUB_REF then GITHUB_SHA.
# GITHUB_SHA is the guaranteed-stable fallback since GITHUB_REF can be empty on some events.
checkout_ref="${INPUT_REF:-${GITHUB_REF:-}}"
if [[ -z "${checkout_ref}" ]]; then
  checkout_ref="${GITHUB_SHA}"
fi

resolved_sha="$(git rev-parse HEAD)"
# 8-char short SHA — short enough to fit in Docker tag limits, unique enough for any single repo.
image_tag="$(git rev-parse --short=8 HEAD)"

# ---------------------------------------------------------------------------
# 2. Parse component selection
# ---------------------------------------------------------------------------

# Strip accidental whitespace from the comma-separated input.
components="${INPUT_COMPONENTS// /}"

if [[ -z "${components}" ]]; then
  # workflow_dispatch without an explicit components input defaults to app images only —
  # callers who want to rebuild base/rt must pass them explicitly.
  # Push-triggered runs use "all" so CI exercises the full dependency + app image path.
  if [[ "${GITHUB_EVENT_NAME}" == "workflow_dispatch" ]]; then
    components="strata-bridge,strata-asm-runner,secret-service"
  else
    components="all"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Map component names to build flags
# ---------------------------------------------------------------------------

build_base=false
build_rt=false
build_strata_bridge=false
build_asm_runner=false
build_secret_service=false

if [[ "${components}" == "all" ]]; then
  build_base=true
  build_rt=true
  build_strata_bridge=true
  build_asm_runner=true
  build_secret_service=true
else
  IFS=',' read -r -a requested <<< "${components}"
  for component in "${requested[@]}"; do
    case "${component}" in
      base)           build_base=true ;;
      rt)             build_rt=true ;;
      strata-bridge)  build_strata_bridge=true ;;
      strata-asm-runner) build_asm_runner=true ;;
      secret-service) build_secret_service=true ;;
      "")             ;; # tolerate trailing commas
      *)
        echo "::error::Unsupported component: ${component}"
        exit 1
        ;;
    esac
  done
fi

# ---------------------------------------------------------------------------
# 4. Enforce dependency pairing rule
# ---------------------------------------------------------------------------
# App Dockerfiles FROM bridge-base and bridge-rt, so both must exist together
# in ECR with the same tag. If any app image is requested alongside even one
# dependency image, force both base and rt to be rebuilt together so the pair
# is never mismatched in the registry.
if [[ ("${build_strata_bridge}" == "true" || "${build_asm_runner}" == "true" || "${build_secret_service}" == "true") \
   && ("${build_base}" == "true" || "${build_rt}" == "true") ]]; then
  build_base=true
  build_rt=true
fi

# ---------------------------------------------------------------------------
# 5. Resolve dependency_tag
# ---------------------------------------------------------------------------
# When rebuilding dependencies the new image tag becomes the dependency tag automatically.
# When skipping the dependency build the caller must supply an existing ECR tag via
# INPUT_DEPENDENCY_TAG so app images know which base/rt to pull.
dependency_tag="${INPUT_DEPENDENCY_TAG:-}"
if [[ "${build_base}" == "true" || "${build_rt}" == "true" ]]; then
  dependency_tag="${image_tag}"
elif [[ "${build_strata_bridge}" == "true" || "${build_asm_runner}" == "true" || "${build_secret_service}" == "true" ]]; then
  if [[ -z "${dependency_tag}" ]]; then
    echo "::error::dependency_tag is required when building final images without rebuilding base and rt"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# 6. Generate JSON build matrices via build_matrix.py
# ---------------------------------------------------------------------------
# Pass all build flags as env vars so build_matrix.py can read them without
# needing positional arguments, keeping the interface stable if new images are added.
export BUILD_BASE="${build_base}"
export BUILD_RT="${build_rt}"
export BUILD_STRATA_BRIDGE="${build_strata_bridge}"
export BUILD_ASM_RUNNER="${build_asm_runner}"
export BUILD_SECRET_SERVICE="${build_secret_service}"

dependency_matrix="$(python3 .github/scripts/build_matrix.py --kind dependency)"
app_matrix="$(python3 .github/scripts/build_matrix.py --kind app)"

# ---------------------------------------------------------------------------
# 7. Write outputs to GITHUB_OUTPUT
# ---------------------------------------------------------------------------
{
  echo "checkout_ref=${checkout_ref}"
  echo "resolved_sha=${resolved_sha}"
  echo "image_tag=${image_tag}"
  echo "dependency_tag=${dependency_tag}"
  echo "dependency_matrix=${dependency_matrix}"
  echo "app_matrix=${app_matrix}"
} >> "${GITHUB_OUTPUT}"
