// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/bundle/bundlefakes"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/sigstore"
)

// TestBuildBundleOptionsTSAFallback covers the SPIFFE-style path:
// Timestamp is requested but SigningConfig is nil. BuildBundleOptions
// must synthesize a TSA-only SigningConfig from the embedded sigstore
// roots and populate bundleOptions.TimestampAuthorities, without
// dragging in Fulcio / OIDC / Rekor.
func TestBuildBundleOptionsTSAFallback(t *testing.T) {
	t.Parallel()

	cp := &bundlefakes.FakeCredentialProvider{}
	cp.CertificateProviderReturns(nil, nil)

	bs := &bundle.DefaultSigner{}

	t.Run("tsa-fallback-when-signing-config-nil", func(t *testing.T) {
		t.Parallel()
		opts := &options.Signer{
			SigstoreRootsData: sigstore.DefaultRoots,
			Sigstore: options.Sigstore{
				Instance: sigstore.Instance{
					Timestamp: true,
				},
			},
		}
		bo, err := bs.BuildBundleOptions(opts, cp)
		require.NoError(t, err)
		require.NotNil(t, bo)
		require.NotEmpty(t, bo.TimestampAuthorities,
			"BuildBundleOptions must populate TimestampAuthorities from the TSA-only fallback")
	})

	t.Run("no-timestamp-no-fallback", func(t *testing.T) {
		t.Parallel()
		opts := &options.Signer{
			SigstoreRootsData: sigstore.DefaultRoots,
			Sigstore:          options.Sigstore{Instance: sigstore.Instance{Timestamp: false}},
		}
		bo, err := bs.BuildBundleOptions(opts, cp)
		require.NoError(t, err)
		require.NotNil(t, bo)
		require.Empty(t, bo.TimestampAuthorities,
			"BuildBundleOptions must not call the TSA fallback when Timestamp is off")
	})

	t.Run("explicit-signing-config-wins", func(t *testing.T) {
		t.Parallel()
		// When the caller supplies their own SigningConfig (sigstore
		// path), BuildBundleOptions must use it directly and not fall
		// back to embedded defaults.
		parsed, err := sigstore.ParseRoots(sigstore.DefaultRoots)
		require.NoError(t, err)
		require.NotEmpty(t, parsed.Roots)
		require.NotNil(t, parsed.Roots[0].SigningConfig)

		opts := &options.Signer{
			SigstoreRootsData: sigstore.DefaultRoots,
			Sigstore: options.Sigstore{
				Instance: sigstore.Instance{
					Timestamp:     true,
					SigningConfig: parsed.Roots[0].SigningConfig,
				},
			},
		}
		bo, err := bs.BuildBundleOptions(opts, cp)
		require.NoError(t, err)
		require.NotNil(t, bo)
		require.NotEmpty(t, bo.TimestampAuthorities)
	})
}
