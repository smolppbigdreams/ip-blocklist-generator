#!/usr/bin/env bash
#MISE description="Build container image using pack CLI and push to registry."
set -eo pipefail

# ==========================================
# Validate Environment
# ==========================================
: "${REGISTRY_HOST:?missing variable}"
: "${REGISTRY_OWNER:?missing variable}"
: "${IMAGE_NAME:?missing variable}"
: "${IMAGE_TAG:=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")}"

# ==========================================
# Configure Image Tags & Flags
# ==========================================
# Enforce lowercase for OCI compliance
REGISTRY_OWNER=$(echo "${REGISTRY_OWNER}" | tr '[:upper:]' '[:lower:]')
IMAGE_NAME=$(echo "${IMAGE_NAME}" | tr '[:upper:]' '[:lower:]')

BASE_REF="${REGISTRY_HOST}/${REGISTRY_OWNER}/${IMAGE_NAME}"
PRIMARY_IMAGE="${BASE_REF}:${IMAGE_TAG}"

# Determine tag
TAG_ARGS=("--tag" "${PRIMARY_IMAGE}")
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
if [[ "${ADD_LATEST_TAG:-false}" == "true" ]] || [[ "${CURRENT_BRANCH}" == "main" ]]; then
  TAG_ARGS+=("--tag" "${BASE_REF}:latest")
fi

# CI-specific flags
BUILD_FLAGS=()
if [[ "${CI:-false}" == "true" ]]; then
  BUILD_FLAGS+=("--network" "host" "--publish")
fi

# ==========================================
# Build Container
# ==========================================
gum spin --spinner monkey --title "[🐳] Building container with buildpacks..." -- \
  pack build "${PRIMARY_IMAGE}" \
  "${TAG_ARGS[@]}" \
  "${BUILD_FLAGS[@]}" \
  --builder paketobuildpacks/builder-jammy-base \
  --buildpack docker.io/paketocommunity/rust

gum log --level info "Processed image: ${PRIMARY_IMAGE} ${TAG_ARGS[*]}"
