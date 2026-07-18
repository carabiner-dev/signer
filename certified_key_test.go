// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/bundle/bundlefakes"
)

// TestCertifiedKeyRejectsNonSigstoreCredentials verifies the sigstore backend
// requirement: a non-sigstore credential provider is rejected before any flow
// runs. The hermetic positive tests for the material itself live in the
// sigstore package (CredentialProvider.CertifiedKey).
func TestCertifiedKeyRejectsNonSigstoreCredentials(t *testing.T) {
	t.Parallel()
	s := NewSigner()
	s.Credentials = &bundlefakes.FakeCredentialProvider{}

	leaf, chain, key, err := s.CertifiedKey(t.Context())
	require.Error(t, err)
	require.ErrorContains(t, err, "requires the sigstore backend")
	require.Nil(t, leaf)
	require.Nil(t, chain)
	require.Nil(t, key)
}
