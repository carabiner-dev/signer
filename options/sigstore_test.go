// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/sigstore"
)

// TestEnsureDefaultSigstore checks that the default sigstore
// options match the first instance in the roots file.
func TestEnsureDefaultSigstore(t *testing.T) {
	conf, err := sigstore.ParseRoots(sigstore.DefaultRoots)
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(conf.Roots), 1)

	root := conf.Roots[0]

	// Verify signing config was parsed from the official format
	require.NotNil(t, root.SigningConfig, "signing config should be parsed")

	// Verify the signing config has the expected Fulcio URL
	fulcioURLs := root.SigningConfig.FulcioCertificateAuthorityURLs()
	require.NotEmpty(t, fulcioURLs)
	require.Equal(t, "https://fulcio.sigstore.dev", fulcioURLs[0].URL)

	// Verify OIDC provider URL
	oidcURLs := root.SigningConfig.OIDCProviderURLs()
	require.NotEmpty(t, oidcURLs)
	require.Equal(t, "https://oauth2.sigstore.dev/auth", oidcURLs[0].URL)

	// Verify Rekor URL
	rekorURLs := root.SigningConfig.RekorLogURLs()
	require.NotEmpty(t, rekorURLs)
	require.Equal(t, "https://rekor.sigstore.dev", rekorURLs[0].URL)

	// Verify client-side OIDC config
	require.Equal(t, "sigstore", root.OIDCConfig.ClientID)
	require.Equal(t, "http://localhost:0/auth/callback", root.OIDCConfig.RedirectURL)
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
			roots, err := sigstore.ParseRootsFile("../sigstore-roots.json")
			require.NoError(t, err)
			return roots
		}},
		{"options-embed", func(t *testing.T) *sigstore.SigstoreRoots {
			t.Helper()
			roots, err := sigstore.ParseRoots(sigstore.DefaultRoots)
			require.NoError(t, err)
			return roots
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			roots := tt.getRoots(t)

			// Require at least one root
			require.GreaterOrEqual(t, len(roots.Roots), 1)

			// Verify all roots have a signing config
			for _, r := range roots.Roots {
				require.NotNil(t, r.SigningConfig, "root %q should have a signing config", r.ID)
			}

			// First root must be sign-capable
			require.NoError(t, roots.Roots[0].ValidateSigner())

			// Verify all returned sets are valid
			for _, r := range roots.Roots {
				require.NoError(t, r.ValidateVerifier())
			}
		})
	}
}
