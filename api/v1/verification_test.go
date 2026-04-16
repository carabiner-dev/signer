// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchesKeyIdentity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		matches bool
		sut     *SignatureVerification
		id      *IdentityKey
	}{
		{
			"id-match", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}}},
			}, &IdentityKey{Id: "1234abc"},
		},
		{
			"id-and-type-match", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}}},
			}, &IdentityKey{Id: "1234abc", Type: "rsa"},
		},
		{
			"id-match-type-ignored-when-empty", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			}, &IdentityKey{Id: "1234abc", Type: "rsa"},
		},
		{
			"id-match-data-ignored", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Data: "keydata"}}},
			}, &IdentityKey{Id: "1234abc", Data: "different-data"},
		},
		{
			"no-id-no-match", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			}, &IdentityKey{Data: "keydata"},
		},
		{
			"wrong-id", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc"}}},
			}, &IdentityKey{Id: "wrong"},
		},
		{
			"type-mismatch", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}}},
			}, &IdentityKey{Id: "1234abc", Type: "ecdsa"},
		},
		{
			"two-signers-first-matches", true,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}},
					{Key: &IdentityKey{Id: "5678def", Type: "ecdsa"}},
				},
			}, &IdentityKey{Id: "1234abc", Type: "rsa"},
		},
		{
			"two-signers-second-matches", true,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}},
					{Key: &IdentityKey{Id: "5678def", Type: "ecdsa"}},
				},
			}, &IdentityKey{Id: "5678def", Type: "ecdsa"},
		},
		{
			"two-signers-none-match", false,
			&SignatureVerification{
				Identities: []*Identity{
					{Key: &IdentityKey{Id: "1234abc", Type: "rsa"}},
					{Key: &IdentityKey{Id: "5678def", Type: "ecdsa"}},
				},
			}, &IdentityKey{Id: "aaaaaaa"},
		},
		{
			"nil-signer-key", false,
			&SignatureVerification{
				Identities: []*Identity{{Sigstore: &IdentitySigstore{Issuer: "x"}}},
			}, &IdentityKey{Id: "1234abc"},
		},
		{
			"empty-identities", false,
			&SignatureVerification{
				Identities: []*Identity{},
			}, &IdentityKey{Id: "1234abc"},
		},
		{
			// Identity has only Data (PEM key), Id/Type should be
			// auto-populated via Normalize before matching.
			"data-only-auto-normalize", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id:   "5be34774cae03891",
					Type: "ecdsa-sha2-nistp256",
				}}},
			}, &IdentityKey{
				Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			},
		},
		{
			// Same as above but signer has a different key — should not match.
			"data-only-auto-normalize-no-match", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id:   "aaaaaaaaaaaaaaaa",
					Type: "ecdsa-sha2-nistp256",
				}}},
			}, &IdentityKey{
				Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			},
		},
		{
			// Policy pins the signing subkey and verified identity matches it.
			"signing-fingerprint-pin-match", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP"},
		},
		{
			// Case-insensitive so upper/lower-hex fingerprints don't matter.
			"signing-fingerprint-pin-case-insensitive", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "subkeyfp",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP"},
		},
		{
			// Policy pins a different subkey than the one that signed.
			"signing-fingerprint-pin-mismatch", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_A",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_B"},
		},
		{
			// Policy omits the signing fingerprint — pin is not enforced even
			// if the verified identity has one.
			"signing-fingerprint-unpinned-permissive", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_A",
				}}},
			}, &IdentityKey{Id: "PRIMARYFP"},
		},
		{
			// Policy uses only the subkey fingerprint as Id — matches against
			// the signer's SigningFingerprint field.
			"id-matches-signer-subkey", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEYFP",
				}}},
			}, &IdentityKey{Id: "SUBKEYFP"},
		},
		{
			// Policy Id is a subkey fingerprint that doesn't match either the
			// primary or the signer's actual subkey.
			"id-matches-neither-primary-nor-subkey", false,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP", SigningFingerprint: "SUBKEY_A",
				}}},
			}, &IdentityKey{Id: "SUBKEY_B"},
		},
		{
			// Fingerprint comparisons are case-insensitive, including the
			// primary Id match (hex fingerprints show up in either case).
			"id-case-insensitive", true,
			&SignatureVerification{
				Identities: []*Identity{{Key: &IdentityKey{
					Id: "PRIMARYFP",
				}}},
			}, &IdentityKey{Id: "primaryfp"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, tt.sut.MatchesKeyIdentity(tt.id))
		})
	}
}

func TestMatchesKeyIdentityDoesNotMutate(t *testing.T) {
	t.Parallel()
	keyData := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n"

	identity := &IdentityKey{Data: keyData}
	sv := &SignatureVerification{
		Identities: []*Identity{{Key: &IdentityKey{Id: "5be34774cae03891"}}},
	}

	require.True(t, sv.MatchesKeyIdentity(identity))

	// The original identity must not be mutated.
	require.Empty(t, identity.GetId())
	require.Empty(t, identity.GetType())
	require.Equal(t, keyData, identity.GetData())
}
