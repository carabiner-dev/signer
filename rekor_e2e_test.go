// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package signer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
)

// The keyless fixture verifies against the real public log: the search
// proposes the hand-built intoto v0.0.1 entry and the dsse entry, so
// this covers the proposal format the offline tests cannot (their test
// log answers regardless of the request).
func TestE2EKeylessRekor(t *testing.T) {
	data, err := os.ReadFile("testdata/keyless/generator.intoto.jsonl")
	require.NoError(t, err)
	res, err := NewVerifier().VerifyStatementBytes(data, options.WithRekorVerification(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, api.VerificationStatus_VERIFIED, res.GetSignature().GetStatus(), res.GetSignature().GetError())
	ids := res.GetSignature().GetIdentities()
	require.Len(t, ids, 1)
	assert.Contains(t, ids[0].GetSigstore().GetIdentity(), "builder_go_slsa3.yml")
}
