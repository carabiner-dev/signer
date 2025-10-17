// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/sigstore"
)

// TestEnsureDefaultSigstore checks that the default sigstore
// options match the first instance in the roots file.
func TestEnsureDefaultSigstore(t *testing.T) {
	conf, err := sigstore.ParseRoots(DefaultRoots)
	require.NoError(t, err)

	moded := DefaultSigstore
	// Timestamp is not exposed in json :/
	moded.Timestamp = false
	moded.HideOIDCOptions = false

	conf.Roots[0].RootData = nil
	require.Empty(t, cmp.Diff(conf.Roots[0].Instance, moded.Instance))
}

// TestDefaultRoots checks that the default roots are valid and that the first
// root is sign-capable
func TestDefaultRoots(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		getRoots func(t *testing.T) *sigstore.SigstoreRoots
	}{
		{"top-level-file", func(t *testing.T) *sigstore.SigstoreRoots {
			t.Helper()
			roots, err := sigstore.ParseRootsFile("sigstore-roots.json")
			require.NoError(t, err)
			return roots
		}},
		{"options-embed", func(t *testing.T) *sigstore.SigstoreRoots {
			t.Helper()
			roots, err := sigstore.ParseRoots(DefaultRoots)
			require.NoError(t, err)
			return roots
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			roots := tt.getRoots(t)

			// Require at least one root
			require.GreaterOrEqual(t, len(roots.Roots), 1)
			require.NoError(t, roots.Roots[0].ValidateSigner())

			// Verify all returned sets are valid
			for _, r := range roots.Roots {
				require.NoError(t, r.ValidateVerifier())
			}
		})
	}
}
