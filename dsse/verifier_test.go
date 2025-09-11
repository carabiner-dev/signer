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
		{"sigstore", "sigstore.dsse.json", crypto.SHA256, false, "3aa489a09d7c7fac5f2cac100c28baab237b06644fa14233307b5b20214d4a12"},
		{"sigstore", "sigstore.dsse.json", crypto.SHA384, false, "040de0426b22dbeb20344b06c25fc0055b7d907b726b1c7093188a9cd443e3fbf39d0aad26e6825e217f59d91d2bbe95"},
		{"sigstore", "sigstore.dsse.json", crypto.SHA512, false, "33aecc7a107850e53afd3bee4a058799f0f40ea9cbc0891012b06f0ba0d0cfbad030a026e008961178e4bab5fe680dc4bef5f095473d68fe7a4952356cb38ff9"},
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
		name            string
		dssePath        string
		keyPaths        []string
		scheme          string
		mustErr         bool
		expect          bool
		expectedMatches int
	}{
		{"sigstore", "sigstore.dsse.json", []string{"sigstore.dsse.key"}, "", false, true, 1}, // ecdsa-sha2-nistp384
		{"rebuild", "rebuild.dsse.json", []string{"rebuild.key"}, "", false, true, 1},
		// This works because we don't deduplicate keys for now. Let's break this test case :D
		{"multiple", "rebuild.dsse.json", []string{"rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key"}, "", false, true, 5},
		{"one-matches-one-not", "rebuild.dsse.json", []string{"rebuild.key", "sigstore.dsse.key"}, "", false, true, 1},
		{"fail-swap-keys", "rebuild.dsse.json", []string{"sigstore.dsse.key"}, "", false, false, 0},
		{"mass-to-check-parallel", "rebuild.dsse.json", []string{
			"rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key",
			"sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key",
			"rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key",
			"sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key",
			"rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key",
			"sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key",
			"rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key", "rebuild.key",
			"sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key", "sigstore.dsse.key",
		}, "", false, true, 20},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v := &DefaultVerifier{}
			env, err := v.OpenEnvelope(filepath.Join("testdata", tt.dssePath))
			require.NoError(t, err)

			pubKeys := []key.PublicKeyProvider{}
			for _, path := range tt.keyPaths {
				// Parse the keys
				keydata, err := os.ReadFile(filepath.Join("testdata", path))
				require.NoError(t, err)

				opts := []key.FnOpt{}
				if tt.scheme != "" {
					opts = append(opts, key.WithScheme(key.Scheme(tt.scheme)))
				}

				pubKey, err := key.NewParser().ParsePublicKey(keydata, opts...)
				require.NoError(t, err)
				pubKeys = append(pubKeys, pubKey)
			}

			res, err := v.RunVerification(&options.Verifier{}, key.NewVerifier(), env, pubKeys)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tt.expect, res.Verified)
			require.Len(t, res.Keys, tt.expectedMatches)
		})
	}
}
