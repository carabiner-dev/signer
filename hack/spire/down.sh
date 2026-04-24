#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0
#
# Tear down the local SPIRE fixture. Leaves the upstream CA material in
# place so a subsequent `up.sh` reuses the same trust anchor (and therefore
# the same bundle.pem). Delete hack/spire/upstream-ca by hand if you want a
# fresh root.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "==> Stopping spire-agent and spire-server"
docker compose down --volumes --remove-orphans

echo "==> Cleaning runtime artifacts"
rm -f socket/api.sock bundle.pem
rmdir socket 2>/dev/null || true

echo "SPIRE fixture torn down. upstream-ca/ preserved for next run."
