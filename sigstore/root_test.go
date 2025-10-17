// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/options"
)

// TestEnsureDefaultSigstore checks that the default sigstore
// options match the first instance in the roots file.
func TestEnsureDefaultSigstore(t *testing.T) {
	conf, err := ParseRoots(options.DefaultRoots)
	require.NoError(t, err)

	moded := options.DefaultSigstore
	// Timestamp is not exposed in json :/
	moded.Timestamp = false
	moded.HideOIDCOptions = false

	conf.Roots[0].RootData = nil
	require.Empty(t, cmp.Diff(conf.Roots[0].Sigstore, moded))
}

// TestDefaultRoots checks that the default roots are valid and that the first
// root is sign-capable
func TestDefaultRoots(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		getRoots func(t *testing.T) *SigstoreRoots
	}{
		{"top-level-file", func(t *testing.T) *SigstoreRoots {
			t.Helper()
			roots, err := ParseRootsFile("../sigstore-roots.json")
			require.NoError(t, err)
			return roots
		}},
		{"options-embed", func(t *testing.T) *SigstoreRoots {
			t.Helper()
			roots, err := ParseRoots(options.DefaultRoots)
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
				require.NoError(t, r.Validate())
			}
		})
	}
}

func TestParseRoots(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		file        string
		expectedLen int
		mustErr     bool
	}{
		{"real", "testdata/roots1.json", 2, false},
		{"err", "testdata/invalid.json", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tt.file)
			require.NoError(t, err)
			roots, err := ParseRoots(data)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, roots.Roots, tt.expectedLen)
		})
	}
}
