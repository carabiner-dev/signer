// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/key"
)

func TestVerifyIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		mustFail bool
		sut      *Identity
	}{
		{"sigstore", false, &Identity{
			Id: "sut",
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "test@example.com",
			},
		}},
		{"key", false, &Identity{
			Id: "sut",
			Key: &IdentityKey{
				Id:   "key-id",
				Type: "rsa",
				Data: "kjshdidy82387y387",
			},
		}},
		{"ref", false, &Identity{
			Ref: &IdentityRef{
				Id: "abcde",
			},
		}},
		{"no-ids", true, &Identity{}},
		{"two-ids", true, &Identity{
			Ref: &IdentityRef{
				Id: "abcde",
			},
			Key: &IdentityKey{
				Id:   "key-id",
				Type: "rsa",
				Data: "kjshdidy82387y387",
			},
		}},
		{"key-no-data-or-id", true, &Identity{
			Id: "sut",
			Key: &IdentityKey{
				Id: "", Type: "rsa", Data: "",
			},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.sut.Validate()
			if tt.mustFail {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestIdentityKeyFromPublic(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, IdentityKeyFromPublic(nil))
	})

	t.Run("carries-signing-fingerprint", func(t *testing.T) {
		t.Parallel()
		// A *key.Public standing in for a post-verification entry whose
		// signature was made by a subkey: ID() reports the primary,
		// SigningKeyFingerprint reports the subkey.
		pub := &key.Public{
			Scheme:                key.Ed25519,
			SigningKeyFingerprint: "04B44C056663906446B77A6D89F11DC191AA7042",
		}
		// Force ID() to return the primary fingerprint via the same
		// mechanism Public uses for GPG-derived keys.
		pub.Data = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPRILHF2NfPlV9xTQkLTM5aWCQfY9bF4cHRPm8a9Uc2o=\n-----END PUBLIC KEY-----\n"

		ik := IdentityKeyFromPublic(pub)
		require.NotNil(t, ik)
		require.Equal(t, "04B44C056663906446B77A6D89F11DC191AA7042", ik.GetSigningFingerprint())
		require.Equal(t, string(key.Ed25519), ik.GetType())
	})
}
