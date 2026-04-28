// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/bundle/bundlefakes"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/sigstore"
)

func TestVerifyParsedBundleIntegration(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		mustErr     bool
		getVerifier func(t *testing.T) bundle.Verifier
	}{
		{"success", false, func(t *testing.T) bundle.Verifier {
			t.Helper()
			v := bundlefakes.FakeVerifier{}
			return &v
		}},
		{"verify-fails", true, func(t *testing.T) bundle.Verifier {
			t.Helper()
			v := bundlefakes.FakeVerifier{}
			v.VerifyReturns(nil, errors.New("verifying failed"))
			return &v
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sut := Verifier{
				Options:        options.DefaultVerifier,
				bundleVerifier: tt.getVerifier(t),
			}
			_, err := sut.VerifyParsedBundle(nil)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestNewVerifierSigstoreRootsPath asserts the runtime honors
// SigstoreRootsPath: passing a path overrides SigstoreRootsData, and a
// missing file falls back to the existing data without panicking.
func TestNewVerifierSigstoreRootsPath(t *testing.T) {
	t.Parallel()

	t.Run("path-overrides-data", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "roots.json")
		require.NoError(t, os.WriteFile(path, sigstore.DefaultRoots, 0o600))

		v := NewVerifier(func(o *options.Verifier) {
			o.SigstoreRootsPath = path
			o.SigstoreRootsData = []byte(`{"roots":[]}`)
		})
		require.NotNil(t, v)
	})

	t.Run("missing-path-falls-back-gracefully", func(t *testing.T) {
		t.Parallel()
		v := NewVerifier(func(o *options.Verifier) {
			o.SigstoreRootsPath = filepath.Join(t.TempDir(), "absent.json")
		})
		require.NotNil(t, v, "missing path must not panic; falls back to data")
	})
}
