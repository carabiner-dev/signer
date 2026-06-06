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

// TestSignAndVerifyE2E signs in a GitHub Actions workflow and verifies the
// bundle two ways: skipping the identity check, and pinning the exact issuer/SAN
// so the source repository URI (Fulcio OID 1.3.6.1.4.1.57264.1.12) is captured
// and matchable. Requires GitHub Actions OIDC tokens.
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

	// Verify skipping the identity check. The result still carries the cert
	// summary, which we use to pin the exact identity below.
	res, err := v.VerifyParsedBundle(bndl, options.WithSkipIdentityCheck(true))
	require.NoError(t, err)
	require.NotNil(t, res.Signature)
	require.NotNil(t, res.Signature.Certificate)

	// Pin the exact issuer/SAN (which SignatureVerificationFromResult needs to
	// surface an identity), then check the captured source repo and the matcher.
	issuer := res.Signature.Certificate.Issuer
	san := res.Signature.Certificate.SubjectAlternativeName
	require.NotEmpty(t, san)

	res, err = v.VerifyParsedBundle(bndl, options.WithExpectedIdentity(issuer, san))
	require.NoError(t, err)

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
