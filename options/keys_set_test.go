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

	"github.com/carabiner-dev/signer/key"
)

// writeECPrivateKey writes a PKCS#8-encoded ECDSA P-256 private key
// to a fresh file and returns the path.
func writeECPrivateKey(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestKeysSignAddFlags(t *testing.T) {
	t.Parallel()

	t.Run("registers-bare-flags", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		cmd := &cobra.Command{Use: "test"}
		k.AddFlags(cmd)

		require.NotNil(t, cmd.PersistentFlags().Lookup("signing-key"))
		require.NotNil(t, cmd.PersistentFlags().Lookup("signing-key-passphrase-env"))

		// -K is the sign-side short, mirroring upstream's -k for --key.
		require.NotNil(t, cmd.PersistentFlags().ShorthandLookup("K"))
	})

	t.Run("default-passphrase-envvar", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		require.Equal(t, "SIGNING_KEY_PASSPHRASE", k.PassphraseEnvVar)
	})

	t.Run("flag-prefix-applies", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		k.Config().FlagPrefix = "alt"
		cmd := &cobra.Command{Use: "test"}
		k.AddFlags(cmd)
		require.NotNil(t, cmd.PersistentFlags().Lookup("alt-signing-key"))
		require.NotNil(t, cmd.PersistentFlags().Lookup("alt-signing-key-passphrase-env"))
	})
}

func TestKeysSignValidate(t *testing.T) {
	t.Parallel()

	t.Run("no-paths-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultKeysSign().Validate())
	})

	t.Run("existing-path-passes", func(t *testing.T) {
		t.Parallel()
		path := writeECPrivateKey(t)
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{path}
		require.NoError(t, k.Validate())
	})

	t.Run("missing-path-fails", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{filepath.Join(t.TempDir(), "nope.pem")}
		err := k.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "checking signing key")
	})
}

func TestKeysSignParseSigningKeys(t *testing.T) {
	t.Parallel()

	t.Run("parses-pem-private-key", func(t *testing.T) {
		t.Parallel()
		path := writeECPrivateKey(t)
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{path}
		providers, err := k.ParseSigningKeys()
		require.NoError(t, err)
		require.Len(t, providers, 1)
		priv, err := providers[0].PrivateKey()
		require.NoError(t, err)
		require.Equal(t, key.ECDSA, priv.Type)
	})

	t.Run("parses-multiple-keys", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{writeECPrivateKey(t), writeECPrivateKey(t)}
		providers, err := k.ParseSigningKeys()
		require.NoError(t, err)
		require.Len(t, providers, 2)
	})

	t.Run("missing-file-errors-with-path", func(t *testing.T) {
		t.Parallel()
		bad := filepath.Join(t.TempDir(), "missing.pem")
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{bad}
		_, err := k.ParseSigningKeys()
		require.Error(t, err)
		require.Contains(t, err.Error(), bad)
	})

	t.Run("malformed-key-errors-with-path", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.pem")
		require.NoError(t, os.WriteFile(path, []byte("not a key"), 0o600))
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{path}
		_, err := k.ParseSigningKeys()
		require.Error(t, err)
		require.Contains(t, err.Error(), path)
	})

	t.Run("add-keys-prepended", func(t *testing.T) {
		t.Parallel()
		path := writeECPrivateKey(t)
		k := DefaultKeysSign()
		k.PrivateKeyPaths = []string{path}
		extra := stubPrivateKeyProvider{}
		k.AddKeys(extra)
		providers, err := k.ParseSigningKeys()
		require.NoError(t, err)
		require.Len(t, providers, 2)
		require.Equal(t, extra, providers[0], "AddKeys-supplied provider should come first")
	})

	t.Run("empty-paths-and-no-extras", func(t *testing.T) {
		t.Parallel()
		k := DefaultKeysSign()
		providers, err := k.ParseSigningKeys()
		require.NoError(t, err)
		require.Empty(t, providers)
	})
}

// TestKeysSignPassphraseEnvPassesThrough lives at the top level
// because t.Setenv is not allowed inside any parallel-aware test
// chain. It uses an unencrypted PEM key so the passphrase value
// doesn't have to match real key material — the goal is just to
// confirm that PassphraseEnvVar resolution doesn't break parsing.
func TestKeysSignPassphraseEnvPassesThrough(t *testing.T) {
	path := writeECPrivateKey(t)
	t.Setenv("SIGNING_KEY_PASSPHRASE_TEST", "dont-need-it")
	k := DefaultKeysSign()
	k.PrivateKeyPaths = []string{path}
	k.PassphraseEnvVar = "SIGNING_KEY_PASSPHRASE_TEST"
	providers, err := k.ParseSigningKeys()
	require.NoError(t, err)
	require.Len(t, providers, 1)
}

// stubPrivateKeyProvider is a no-op PrivateKeyProvider for tests that
// only care about the slice ordering / pass-through behaviour of
// AddKeys, not the underlying key material.
type stubPrivateKeyProvider struct{}

func (stubPrivateKeyProvider) PrivateKey() (*key.Private, error) { return nil, nil }
