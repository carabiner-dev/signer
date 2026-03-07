#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0
#
# verify-roots-sync.sh verifies that the embedded sigstore signing configs
# are in sync with their upstream sources.
#
# Currently only the sigstore public good instance publishes an official
# signing config (via the sigstore/root-signing repository). GitHub does
# not publish theirs, so it is skipped with a reminder.

set -euo pipefail

source "$(dirname "$0")/common.sh"

ROOTS_FILE="${1:-sigstore/sigstore-roots.json}"
UPSTREAM_SIGSTORE_URL="https://raw.githubusercontent.com/sigstore/root-signing/main/targets/signing_config.v0.2.json"

if ! command -v jq &>/dev/null; then
    exit_with_msg "jq is required but not installed"
fi

echo "Checking signing configs in ${ROOTS_FILE} against upstream..."
echo

# Extract the signing config for the sigstore root
local_config=$(jq -r '.roots[] | select(.id == "sigstore") | ."signing-config"' "$ROOTS_FILE")
if [ -z "$local_config" ] || [ "$local_config" = "null" ]; then
    exit_with_msg "ERROR: could not find sigstore root signing config in ${ROOTS_FILE}"
fi

# Fetch upstream
echo "Fetching sigstore public good signing config from upstream..."
upstream_config=$(curl -sSfL "$UPSTREAM_SIGSTORE_URL") || exit_with_msg "ERROR: failed to fetch upstream signing config"

# Normalize both (sort keys) and compare
local_normalized=$(echo "$local_config" | jq -S .)
upstream_normalized=$(echo "$upstream_config" | jq -S .)

if [ "$local_normalized" = "$upstream_normalized" ]; then
    echo "OK: sigstore public good signing config is in sync with upstream"
else
    echo "DIFF: sigstore public good signing config differs from upstream"
    echo
    echo "--- local (${ROOTS_FILE})"
    echo "+++ upstream (${UPSTREAM_SIGSTORE_URL})"
    diff <(echo "$local_normalized") <(echo "$upstream_normalized") || true
    echo
    echo "To update, copy the upstream signing config into the sigstore root entry"
    echo "in ${ROOTS_FILE} under the \"signing-config\" key."
    exit 1
fi

echo

# Check GitHub root
github_config=$(jq -r '.roots[] | select(.id == "github") | ."signing-config"' "$ROOTS_FILE")
if [ -n "$github_config" ] && [ "$github_config" != "null" ]; then
    echo "NOTE: GitHub does not publish an official signing config."
    echo "      The github root signing config cannot be automatically verified."
    echo "      Please verify manually that the following URLs are correct:"
    echo "$github_config" | jq -r '
        (.caUrls // [] | .[].url) as $ca |
        (.tsaUrls // [] | .[].url) as $tsa |
        (.rekorTlogUrls // [] | .[].url) as $rekor |
        empty
    ' 2>/dev/null || true
    echo "$github_config" | jq -r '[.caUrls[]?.url, .tsaUrls[]?.url, .rekorTlogUrls[]?.url] | .[]' 2>/dev/null | sed 's/^/      - /'
fi

echo
echo "Done."
