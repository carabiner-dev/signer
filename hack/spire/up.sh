#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0
#
# Boot a local SPIRE server + agent and register this user's UID as a
# workload. Produces:
#   hack/spire/socket/api.sock  — agent Workload API socket
#   hack/spire/bundle.pem       — pinned trust root for the verifier
#
# Upstream CA material is generated on first run under hack/spire/upstream-ca
# and reused on subsequent runs, so teardown/up loops don't invalidate the
# exported bundle.pem unless you blow the CA away manually.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

AGENT_SPIFFE_ID="spiffe://test.local/agent/test"
WORKLOAD_SPIFFE_ID="spiffe://test.local/workload"

echo "==> Preparing upstream CA"
if [[ ! -f upstream-ca/ca.pem ]]; then
    mkdir -p upstream-ca
    openssl ecparam -name prime256v1 -genkey -noout -out upstream-ca/ca-key.pem
    openssl req -new -x509 -days 3650 \
        -key upstream-ca/ca-key.pem \
        -out upstream-ca/ca.pem \
        -subj "/CN=carabiner-signer-test-upstream-ca" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    # The spire-server container runs as a non-root `spire` user. When we
    # bind-mount this directory the in-container UID won't match the host
    # user that just generated these files, so openssl's default 0600 key
    # mode prevents SPIRE from loading it. Test-fixture CA; not a secret
    # worth protecting with tight perms.
    chmod 0644 upstream-ca/ca-key.pem upstream-ca/ca.pem
    echo "    generated fresh upstream CA in upstream-ca/"
else
    echo "    reusing existing upstream CA at upstream-ca/ca.pem"
fi

echo "==> Preparing socket directory"
mkdir -p socket
# The agent runs as the non-root `spire` user inside the container. When
# Docker bind-mounts this host dir, UIDs don't line up, so open the
# permissions wide for the test fixture. Also clear any stale socket from
# a previous run so the `until [ -S ... ]` wait below is against the
# current boot, not a leftover file.
chmod 0777 socket
rm -f socket/api.sock

echo "==> Starting spire-server"
docker compose up -d spire-server

echo "==> Waiting for server healthcheck"
for _ in $(seq 1 30); do
    if docker compose exec -T spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! docker compose exec -T spire-server /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; then
    echo "    server never became healthy; check 'make spire-logs'" >&2
    exit 1
fi

echo "==> Generating join token for the agent"
TOKEN_OUTPUT=$(docker compose exec -T spire-server /opt/spire/bin/spire-server token generate \
    -spiffeID "${AGENT_SPIFFE_ID}")
# Output looks like: "Token: <hex>"
TOKEN=$(echo "${TOKEN_OUTPUT}" | awk -F': ' '/^Token:/ {print $2}' | tr -d '[:space:]')
if [[ -z "${TOKEN}" ]]; then
    echo "    failed to parse join token from: ${TOKEN_OUTPUT}" >&2
    exit 1
fi

echo "==> Starting spire-agent"
SPIRE_JOIN_TOKEN="${TOKEN}" docker compose up -d spire-agent

echo "==> Waiting for agent Workload API socket"
for _ in $(seq 1 60); do
    if [[ -S socket/api.sock ]]; then
        break
    fi
    sleep 1
done
if [[ ! -S socket/api.sock ]]; then
    echo "    agent never exposed its Workload API socket; check 'make spire-logs'" >&2
    exit 1
fi

echo "==> Registering workload entry for UID $(id -u)"
docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
    -parentID "${AGENT_SPIFFE_ID}" \
    -spiffeID "${WORKLOAD_SPIFFE_ID}" \
    -selector "unix:uid:$(id -u)" >/dev/null

echo "==> Exporting trust bundle"
docker compose exec -T spire-server /opt/spire/bin/spire-server bundle show -format pem > bundle.pem

echo ""
echo "SPIRE is up."
echo "  socket:       ${SCRIPT_DIR}/socket/api.sock"
echo "  trust bundle: ${SCRIPT_DIR}/bundle.pem"
echo "  workload SVID: ${WORKLOAD_SPIFFE_ID}"
echo ""
echo "Run 'make spiffe-tests' to exercise the end-to-end flow."
