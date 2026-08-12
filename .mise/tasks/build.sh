#!/usr/bin/env bash
#MISE description="Build container image using pack CLI and push to registry."
set -eo pipefail

: "${REGISTRY_HOST:?missing variable}"
: "${REGISTRY_OWNER:?missing variable}"
: "${IMAGE_NAME:?missing variable}"
: "${IMAGE_TAG:=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")}"

# Enforce lowercase for OCI compliance
REGISTRY_OWNER=$(echo "${REGISTRY_OWNER}" | tr '[:upper:]' '[:lower:]')
IMAGE_NAME=$(echo "${IMAGE_NAME}" | tr '[:upper:]' '[:lower:]')

BASE_REF="${REGISTRY_HOST}/${REGISTRY_OWNER}/${IMAGE_NAME}"
PRIMARY_IMAGE="${BASE_REF}:${IMAGE_TAG}"

# Always tag with commit SHA or dev
TAG_ARGS=( "--tag" "${BASE_REF}:${IMAGE_TAG}" )

# Determine if 'latest' tag is to be used
EXTRA_TAG_ARGS=()
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
if [[ "${ADD_LATEST_TAG:-false}" == "true" ]] || [[ "${CURRENT_BRANCH}" == "main" ]]; then
    EXTRA_TAG_ARGS+=( "--tag" "${BASE_REF}:latest" )
fi

# CI flags
PUBLISH_FLAG=""
if [[ "${CI:-false}" == "true" ]]; then
    PUBLISH_FLAG="--publish"
fi

gum spin --show-output --spinner minidot --title "[📦] Building container with buildpacks..." -- \
    pack build "${PRIMARY_IMAGE}" \
        "${EXTRA_TAG_ARGS[@]}" \
        --network host \
        --builder paketobuildpacks/builder-jammy-base \
        --buildpack docker.io/paketocommunity/rust \
        ${PUBLISH_FLAG}

gum log --level info "Image published: ${PRIMARY_IMAGE} ${EXTRA_TAG_ARGS[*]}"
