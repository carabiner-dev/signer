// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package signer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/signer/api/v1"
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

// TestSignAndVerifySourceRepositoryE2E signs in a GitHub Actions workflow and
// checks that the source repository URI captured from the Fulcio cert (OID
// 1.3.6.1.4.1.57264.1.12) is the repo running the workflow, and that
// source_repository_uri_match pins it. Verifying against the Actions OIDC
// issuer populates the VerifiedIdentity the capture reads from.
func TestSignAndVerifySourceRepositoryE2E(t *testing.T) {
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
	res, err := v.VerifyParsedBundle(bndl, options.WithExpectedIdentityRegex(
		`^https://token\.actions\.githubusercontent\.com$`, `.*`,
	))
	require.NoError(t, err)
	require.NotNil(t, res)

	sv := api.SignatureVerificationFromResult(res)
	require.NotEmpty(t, sv.GetIdentities())
	ss := sv.GetIdentities()[0].GetSigstore()
	require.NotNil(t, ss)

	wantRepo := os.Getenv("GITHUB_SERVER_URL") + "/" + os.Getenv("GITHUB_REPOSITORY")
	require.Equal(t, wantRepo, ss.GetSourceRepositoryUri())

	require.True(t, sv.MatchesSigstoreIdentity(&api.IdentitySigstore{
		SourceRepositoryUriMatch: &api.StringMatcher{Kind: &api.StringMatcher_Exact{Exact: wantRepo}},
	}))
	require.False(t, sv.MatchesSigstoreIdentity(&api.IdentitySigstore{
		SourceRepositoryUriMatch: &api.StringMatcher{Kind: &api.StringMatcher_Exact{Exact: "https://github.com/evil/repo"}},
	}))
}
