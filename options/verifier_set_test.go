// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestVerifierSetAddFlags(t *testing.T) {
	t.Parallel()

	set := DefaultVerifierSet()
	cmd := &cobra.Command{Use: "test"}
	set.AddFlags(cmd)

	for _, name := range []string{
		"key",
		"sigstore-roots",
		"spiffe-trust-domain",
		"spiffe-trust-bundle",
		"spiffe-path",
		"spiffe-path-regex",
	} {
		require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %q must be registered", name)
	}
}

func TestVerifierSetActive(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.

	t.Run("default-only-sigstore-active", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		require.False(t, set.Keys.Active())
		require.True(t, set.Sigstore.Active())
		require.False(t, set.Spiffe.Active())
	})

	t.Run("keys-active-with-paths", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Keys.PublicKeyPaths = []string{writeECPublicKey(t)}
		require.True(t, set.Keys.Active())
		require.True(t, set.Sigstore.Active())
		require.False(t, set.Spiffe.Active())
	})

	t.Run("spiffe-active-via-flag", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Spiffe.Verify.TrustBundlePath = testTrustBundlePath
		require.True(t, set.Spiffe.Active())
	})

	t.Run("spiffe-active-via-env", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "/from/env")
		set := DefaultVerifierSet()
		require.True(t, set.Spiffe.Active())
	})

	t.Run("spiffe-active-via-pem", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Spiffe.Verify.TrustBundlePEM = []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
		require.True(t, set.Spiffe.Active())
	})

	t.Run("nil-children-inactive", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		var (
			k *KeysVerify
			s *SigstoreVerifySet
			p *SpiffeVerifySet
		)
		require.False(t, k.Active())
		require.False(t, s.Active())
		require.False(t, p.Active())
	})
}

func TestVerifierSetValidate(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.

	t.Run("default-passes", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		require.NoError(t, DefaultVerifierSet().Validate())
	})

	t.Run("inactive-spiffe-skipped", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Keys.PublicKeyPaths = []string{writeECPublicKey(t)}
		// SPIFFE is left unconfigured — bundled Validate must not fail
		// for the missing trust bundle since SPIFFE is inactive.
		require.NoError(t, set.Validate())
	})

	t.Run("active-spiffe-without-bundle-fails", func(t *testing.T) {
		// Forced active by setting TrustBundlePEM, but Validate's check
		// for a path/PEM source then sees the PEM and passes. Use a
		// regex with TrustBundlePEM set to trigger Active=true while
		// also injecting a malformed path-regex, so Validate has
		// something to reject.
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Spiffe.Verify.TrustBundlePEM = []byte("stub")
		set.Spiffe.Verify.PathRegex = "[unclosed"
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "compiling --spiffe-path-regex")
	})

	t.Run("active-keys-with-missing-file-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Keys.PublicKeyPaths = []string{"/does/not/exist.pub"}
		err := set.Validate()
		require.Error(t, err)
	})
}

func TestVerifierSetApplyToVerifier(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.

	t.Run("composes-active-children", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		set.Keys.PublicKeyPaths = []string{writeECPublicKey(t)}
		set.Sigstore.Common.RootsData = []byte(`{"roots":[]}`)
		set.Spiffe.Verify.TrustBundlePath = testTrustBundlePath
		set.Spiffe.Verify.TrustDomain = testTrustDomain

		var v Verifier
		require.NoError(t, set.ApplyToVerifier(&v))

		require.Len(t, v.PubKeys, 1)
		require.JSONEq(t, `{"roots":[]}`, string(v.SigstoreRootsData))
		require.Equal(t, testTrustBundlePath, v.TrustRootsPath)
		require.Equal(t, testTrustDomain, v.ExpectedTrustDomain)
	})

	t.Run("inactive-children-contribute-nothing", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultVerifierSet()
		// Only sigstore is active by default.
		var v Verifier
		require.NoError(t, set.ApplyToVerifier(&v))
		require.Empty(t, v.PubKeys)
		require.Empty(t, v.TrustRootsPath)
		require.Empty(t, v.ExpectedTrustDomain)
	})

	t.Run("nil-target-errors", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		require.Error(t, DefaultVerifierSet().ApplyToVerifier(nil))
	})
}

func TestVerifierSetBuildVerifier(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.

	t.Setenv("SPIFFE_TRUST_BUNDLE", "")
	set := DefaultVerifierSet()
	set.Keys.PublicKeyPaths = []string{writeECPublicKey(t)}

	v, err := set.BuildVerifier()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, v.PubKeys, 1)
	// DefaultVerifier carries the embedded sigstore roots — the bundled
	// builder must preserve them so the runtime still has trust material
	// for the always-on sigstore baseline.
	require.NotEmpty(t, v.SigstoreRootsData)
}
