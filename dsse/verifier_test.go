// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
)

func TestHashPayload(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		file     string
		hasher   crypto.Hash
		mustErr  bool
		expected string
	}{
		{"sigstore", "sigstore.dsse.json", crypto.SHA256, false, "febfe5fe33ed74786141f15d9d24744530bf1d2db1fc509176be34bc29d6bc84"},
		{"sigstore", "sigstore.dsse.json", crypto.SHA384, false, "3d42e98a8ceea5e0679c8ad71bd8b32877e2dbc03484bc57dbdf57f1fa9ca414a90360e06024b604099c62b95067c54f"},
		{"sigstore", "sigstore.dsse.json", crypto.SHA512, false, "49e908bbeee80df3d9bfc7f575c29fed105f85578c917047fe75c9ae95db70af82b51c0cb5e85ea7f143bf0e07af5e47e855120e4adfefd43ac36d5c110c3960"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &DefaultVerifier{}
			env, err := v.OpenEnvelope(filepath.Join("testdata", tt.file))
			require.NoError(t, err)

			exp, err := hex.DecodeString(tt.expected)
			require.NoError(t, err)

			res, err := hashPayload(env, tt.hasher)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, exp, res, "Expected %x, got %x", exp, res)
		})
	}
}

func TestOpenEnvelope(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		file    string
		mustErr bool
		sigLen  int
		sig0    string
	}{
		{"sigstore", "sigstore.dsse.json", false, 1, "MEUCIQCOgpXO0V4xNCGslEpGnj9nGkEYTOqefQ/VIAVAYXUUJQIgMFiwpsELF+076kyK+8wiSD9Mcl1o78cbBdMRZd+thHk="},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &DefaultVerifier{}
			env, err := v.OpenEnvelope(filepath.Join("testdata", tt.file))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, env)

			require.Equal(t, "application/vnd.in-toto+json", env.GetPayloadType())
			require.Len(t, env.GetSignatures(), tt.sigLen)
			if tt.sig0 != "" {
				sig, err := base64.StdEncoding.DecodeString(tt.sig0)
				require.NoError(t, err)
				require.Equal(t, sig, env.GetSignatures()[0].GetSig())
			}
		})
	}
}

func TestRunVerification(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		dssePath string
		keyPath  string
		scheme   string
		mustErr  bool
		expect   bool
	}{
		{"sigstore", "sigstore.dsse.json", "sigstore.dsse.key", "", false, true}, // ecdsa-sha2-nistp384
		{"rebuild", "rebuild.dsse.json", "rebuild.key", "", false, true},
		{"fail-swap-keys", "rebuild.dsse.json", "sigstore.dsse.key", "", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &DefaultVerifier{}
			env, err := v.OpenEnvelope(filepath.Join("testdata", tt.dssePath))
			require.NoError(t, err)

			keydata, err := os.ReadFile(filepath.Join("testdata", tt.keyPath))
			require.NoError(t, err)

			pubKey, err := key.NewParser().ParsePublicKey(key.Scheme(tt.scheme), keydata)
			require.NoError(t, err)

			res, err := v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, []*key.Public{pubKey})
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tt.expect, res.Verified)
		})
	}
}
