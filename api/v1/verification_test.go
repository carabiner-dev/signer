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
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.matches, tt.sut.MatchesKeyIdentity(tt.id))
		})
	}
}
