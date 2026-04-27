// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// writeECPublicKey writes a PKIX-encoded ECDSA P-256 public key to a
// fresh file and returns the path.
func writeECPublicKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pub")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestKeysVerifyAddFlags(t *testing.T) {
	t.Parallel()

	k := DefaultKeysVerify()
	cmd := &cobra.Command{Use: "test"}
	k.AddFlags(cmd)

	require.NotNil(t, cmd.PersistentFlags().Lookup("key"))
	require.NotNil(t, cmd.PersistentFlags().ShorthandLookup("k"))
}

func TestKeysVerifyValidate(t *testing.T) {
	t.Parallel()

	t.Run("empty-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultKeysVerify().Validate())
	})

	t.Run("missing-file-fails", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysVerify()
		k.PublicKeyPaths = []string{filepath.Join(t.TempDir(), "absent.pub")}
		err := k.Validate()
		require.Error(t, err)
	})

	t.Run("existing-file-passes", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysVerify()
		k.PublicKeyPaths = []string{writeECPublicKey(t)}
		require.NoError(t, k.Validate())
	})
}

func TestKeysVerifyApplyToVerifier(t *testing.T) {
	t.Parallel()

	t.Run("populates-pubkeys", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysVerify()
		k.PublicKeyPaths = []string{writeECPublicKey(t), writeECPublicKey(t)}

		var v Verifier
		require.NoError(t, k.ApplyToVerifier(&v))
		require.Len(t, v.Verification.PubKeys, 2)
	})

	t.Run("empty-paths-yields-empty-pubkeys", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysVerify()
		var v Verifier
		require.NoError(t, k.ApplyToVerifier(&v))
		require.Empty(t, v.Verification.PubKeys)
	})

	t.Run("nil-target-errors", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysVerify()
		require.Error(t, k.ApplyToVerifier(nil))
	})

	t.Run("nil-options-errors", func(t *testing.T) {
		t.Parallel()
		k := &KeysVerify{}
		err := k.ApplyToVerifier(&Verifier{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "construct via DefaultKeysVerify")
	})

	t.Run("malformed-key-file-errors", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		bad := filepath.Join(dir, "bad.pub")
		require.NoError(t, os.WriteFile(bad, []byte("not a key"), 0o600))
		k := DefaultKeysVerify()
		k.PublicKeyPaths = []string{bad}
		err := k.ApplyToVerifier(&Verifier{})
		require.Error(t, err)
	})
}

func TestKeysVerifyBuildVerifier(t *testing.T) {
	t.Parallel()

	k := DefaultKeysVerify()
	k.PublicKeyPaths = []string{writeECPublicKey(t)}

	v, err := k.BuildVerifier()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Len(t, v.Verification.PubKeys, 1)
}

func TestSigstoreVerifySetApplyToVerifier(t *testing.T) {
	t.Parallel()

	t.Run("passes-roots-path-through", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreVerifySet("sigstore")
		set.Common.RootsPath = "/tmp/custom-roots.json"

		var v Verifier
		require.NoError(t, set.ApplyToVerifier(&v))
		require.Equal(t, "/tmp/custom-roots.json", v.SigstoreRootsPath)
	})

	t.Run("inline-roots-data-overrides-default", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreVerifySet("sigstore")
		set.Common.RootsData = []byte(`{"roots":[]}`)

		var v Verifier
		require.NoError(t, set.ApplyToVerifier(&v))
		require.Equal(t, []byte(`{"roots":[]}`), v.SigstoreRootsData)
	})

	t.Run("nil-target-errors", func(t *testing.T) {
		t.Parallel()
		set := DefaultSigstoreVerifySet("sigstore")
		require.Error(t, set.ApplyToVerifier(nil))
	})

	t.Run("nil-set-errors", func(t *testing.T) {
		t.Parallel()
		var set *SigstoreVerifySet
		require.Error(t, set.ApplyToVerifier(&Verifier{}))
	})
}

func TestSigstoreVerifySetBuildVerifier(t *testing.T) {
	t.Parallel()

	set := DefaultSigstoreVerifySet("sigstore")
	v, err := set.BuildVerifier()
	require.NoError(t, err)
	require.NotNil(t, v)
}

func TestSpiffeVerifySetApplyToVerifier(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.

	t.Run("populates-shared-verification", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultSpiffeVerifySet("spiffe")
		set.Verify.TrustDomain = "prod.example.org"
		set.Verify.TrustBundlePath = "/tmp/bundle.pem"
		set.Verify.Path = "/workload"

		var v Verifier
		require.NoError(t, set.ApplyToVerifier(&v))
		require.Equal(t, "prod.example.org", v.Verification.ExpectedTrustDomain)
		require.Equal(t, "/tmp/bundle.pem", v.Verification.TrustRootsPath)
		require.Equal(t, "/workload", v.Verification.ExpectedPath)
	})

	t.Run("nil-target-errors", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		set := DefaultSpiffeVerifySet("spiffe")
		require.Error(t, set.ApplyToVerifier(nil))
	})

	t.Run("nil-set-errors", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		var set *SpiffeVerifySet
		require.Error(t, set.ApplyToVerifier(&Verifier{}))
	})
}

func TestSpiffeVerifySetBuildVerifier(t *testing.T) {
	t.Setenv("SPIFFE_TRUST_BUNDLE", "/tmp/bundle.pem")
	set := DefaultSpiffeVerifySet("spiffe")
	v, err := set.BuildVerifier()
	require.NoError(t, err)
	require.NotNil(t, v)
	require.Equal(t, "/tmp/bundle.pem", v.Verification.TrustRootsPath)
}
