// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSignerSetAddFlags(t *testing.T) {
	t.Parallel()

	set := DefaultSignerSet()
	cmd := &cobra.Command{Use: "test"}
	set.AddFlags(cmd)

	for _, name := range []string{
		"signing-backend",
		"signing-key",
		"signing-key-passphrase-env",
		"sigstore-roots",
		"spiffe-trust-domain",
		"spiffe-socket",
	} {
		require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %q must be registered", name)
	}
}

func TestSignerSetValidateUnknownBackend(t *testing.T) {
	t.Parallel()

	set := DefaultSignerSet()
	set.Backend = "carrier-pigeon"
	err := set.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown --signing-backend")
}

func TestSignerSetValidateKeyBackend(t *testing.T) {
	t.Parallel()

	t.Run("missing-keys-fails", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		// Validate passes (paths empty → no os.Stat). BuildSigner is the
		// place that errors out for "no keys configured".
		require.NoError(t, set.Validate())
		_, err := set.BuildSigner()
		require.Error(t, err)
		require.Contains(t, err.Error(), "no signing keys")
	})

	t.Run("with-key-builds", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		set.Keys.PrivateKeyPaths = []string{writeECPrivateKey(t)}
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.Equal(t, BackendKey, opts.Backend)
		require.Len(t, opts.Keys, 1)
	})

	t.Run("nil-keys-child-fails", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendKey)
		set.Keys = nil
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Keys is nil")
	})
}

func TestSignerSetValidateSpiffeBackend(t *testing.T) {
	// No t.Parallel — t.Setenv conflicts with parallel chains.
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")

	t.Run("missing-socket-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SPIFFE_ENDPOINT_SOCKET")
	})

	t.Run("env-satisfies", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/sock")
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.Equal(t, BackendSpiffe, opts.Backend)

		creds, err := set.BuildCredentialProvider()
		require.NoError(t, err)
		require.NotNil(t, creds)
	})

	t.Run("nil-spiffe-child-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/sock")
		set := DefaultSignerSet()
		set.Backend = string(BackendSpiffe)
		set.Spiffe = nil
		err := set.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Spiffe is nil")
	})
}

func TestSignerSetSigstoreBackendDefault(t *testing.T) {
	t.Parallel()

	t.Run("explicit-sigstore", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = string(BackendSigstore)
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.NotNil(t, opts)

		// Sigstore doesn't need an external credential provider.
		creds, err := set.BuildCredentialProvider()
		require.NoError(t, err)
		require.Nil(t, creds)
	})

	t.Run("empty-backend-defaults-to-sigstore", func(t *testing.T) {
		t.Parallel()
		set := DefaultSignerSet()
		set.Backend = ""
		require.NoError(t, set.Validate())

		opts, err := set.BuildSigner()
		require.NoError(t, err)
		require.NotNil(t, opts)
	})
}

// TestSignerSetBuildCredentialProviderSkipsNonSpiffe asserts the
// (nil, nil) contract for non-SPIFFE backends — callers can call this
// uniformly without checking the Backend first.
func TestSignerSetBuildCredentialProviderSkipsNonSpiffe(t *testing.T) {
	t.Parallel()

	for _, backend := range []Backend{BackendKey, BackendSigstore} {
		set := DefaultSignerSet()
		set.Backend = string(backend)
		creds, err := set.BuildCredentialProvider()
		require.NoError(t, err, "backend %q", backend)
		require.Nil(t, creds, "backend %q must yield (nil, nil)", backend)
	}
}
