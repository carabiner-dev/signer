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
	t.Parallel()
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
			t.Parallel()
			data, err := os.ReadFile(tt.rootsPath)
			require.NoError(t, err)

			verifier := New(WithSigstoreRootsData(data))

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
