// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/options"
)

func TestVerify(t *testing.T) {
	// Not parallel: subtests share the global TUF cache (~/.sigstore/root)
	// and on Windows the atomic metadata rename fails with "Access is denied"
	// when two goroutines access the same per-URL cache concurrently.
	for _, tt := range []struct {
		name         string
		rootsPath    string
		attestattion string
		mustErr      bool
	}{
		{"single", "testdata/github.json", "testdata/github-release.sigstore.json", false},
		{"wrong-instance", "testdata/github.json", "testdata/public-good.sigstore.json", true},
		{"two-instances", "testdata/sigstore-roots.json", "testdata/public-good.sigstore.json", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Subtests must not run in parallel: they share the global
			// TUF cache (~/.sigstore/root) and on Windows the atomic
			// metadata rename fails with "Access is denied" when two
			// goroutines access the same per-URL cache concurrently.
			data, err := os.ReadFile(tt.rootsPath)
			require.NoError(t, err)

			verifier, err := NewWithError(WithSigstoreRootsData(data))
			require.NoError(t, err)

			b, err := verifier.OpenBundle(tt.attestattion)
			require.NoError(t, err)
			res, err := verifier.Verify(&options.Verification{
				SigstoreVerification: options.SigstoreVerification{
					SkipIdentityCheck: true,
				},
			}, b)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
		})
	}
}
