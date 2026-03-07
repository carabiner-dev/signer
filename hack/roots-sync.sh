#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0
#
# roots-sync.sh fetches the upstream sigstore signing config and updates
# the local roots file in place.
#
# GitHub does not publish an official signing config, so only the sigstore
# public good instance is updated.

set -euo pipefail

source "$(dirname "$0")/common.sh"

ROOTS_FILE="${1:-sigstore/sigstore-roots.json}"
UPSTREAM_SIGSTORE_URL="https://raw.githubusercontent.com/sigstore/root-signing/main/targets/signing_config.v0.2.json"

if ! command -v jq &>/dev/null; then
    exit_with_msg "jq is required but not installed"
fi

if [ ! -f "$ROOTS_FILE" ]; then
    exit_with_msg "ERROR: roots file not found: ${ROOTS_FILE}"
fi

echo "Fetching sigstore public good signing config from upstream..."
upstream_config=$(curl -sSfL "$UPSTREAM_SIGSTORE_URL") || exit_with_msg "ERROR: failed to fetch upstream signing config"

# Extract current local config for comparison
local_config=$(jq -S '.roots[] | select(.id == "sigstore") | ."signing-config"' "$ROOTS_FILE")
upstream_normalized=$(echo "$upstream_config" | jq -S .)

if [ "$local_config" = "$upstream_normalized" ]; then
    echo "Already up to date."
    exit 0
fi

echo "Updating sigstore signing config in ${ROOTS_FILE}..."

# Update the signing-config for the sigstore root entry in place
updated=$(jq --argjson upstream "$upstream_config" '
    .roots |= map(
        if .id == "sigstore" then
            .["signing-config"] = $upstream
        else
            .
        end
    )
' "$ROOTS_FILE")

echo "$updated" | jq . > "$ROOTS_FILE"

echo "Updated. Diff:"
diff <(echo "$local_config") <(echo "$upstream_normalized") || true
