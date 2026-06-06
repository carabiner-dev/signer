// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package signer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/options"
)

// TestSignAndVerifyE2E performs a real end-to-end signing and verification
// against the sigstore public good instance. It requires GitHub Actions
// OIDC tokens to be available.
func TestSignAndVerifyE2E(t *testing.T) {
	t.Parallel()
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("(not running in an actions workflow)")
	}
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") == "" {
		t.Skip("(OIDC tokens not available)")
	}
	s := NewSigner()
	statementData, err := os.ReadFile("bundle/testdata/statement.json")
	require.NoError(t, err)
	bndl, err := s.SignStatementBundle(statementData)
	require.NoError(t, err)
	require.NotNil(t, bndl)

	v := NewVerifier()
	res, err := v.VerifyParsedBundle(bndl, options.WithSkipIdentityCheck(true))
	require.NoError(t, err)
	require.NotNil(t, res)
}
