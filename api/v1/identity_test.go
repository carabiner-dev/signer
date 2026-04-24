// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/key"
)

// mintSpiffeLeafForTest mints a self-signed cert whose URI SAN is the given
// spiffe:// ID. Good enough for IdentitySpiffeFromCert unit tests.
func mintSpiffeLeafForTest(t *testing.T, spiffeURI string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	uri, err := url.Parse(spiffeURI)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svid"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if uri != nil && uri.Scheme != "" {
		tpl.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

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

func TestIdentitySpiffeFromString(t *testing.T) {
	t.Parallel()

	t.Run("success-with-path", func(t *testing.T) {
		t.Parallel()
		id, err := IdentitySpiffeFromString("spiffe://prod.example.org/workload/api")
		require.NoError(t, err)
		require.Equal(t, "prod.example.org", id.GetTrustDomain())
		require.Equal(t, "/workload/api", id.GetPath())
		require.Empty(t, id.GetTrustRoots())
		require.Empty(t, id.GetPathRegex())
	})

	t.Run("success-no-path", func(t *testing.T) {
		t.Parallel()
		id, err := IdentitySpiffeFromString("spiffe://example.org")
		require.NoError(t, err)
		require.Equal(t, "example.org", id.GetTrustDomain())
		require.Empty(t, id.GetPath())
	})

	t.Run("invalid-scheme", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromString("https://example.org/workload")
		require.Error(t, err)
	})

	t.Run("empty-string", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromString("")
		require.Error(t, err)
	})

	t.Run("missing-trust-domain", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromString("spiffe:///workload")
		require.Error(t, err)
	})
}

func TestIdentitySpiffeFromCert(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		leaf := mintSpiffeLeafForTest(t, "spiffe://prod.example.org/workload/api")
		id, err := IdentitySpiffeFromCert(leaf)
		require.NoError(t, err)
		require.Equal(t, "prod.example.org", id.GetTrustDomain())
		require.Equal(t, "/workload/api", id.GetPath())
		require.Empty(t, id.GetTrustRoots(), "TrustRoots must not be populated on the verified-side identity")
		require.Empty(t, id.GetPathRegex())
	})

	t.Run("nil-cert", func(t *testing.T) {
		t.Parallel()
		_, err := IdentitySpiffeFromCert(nil)
		require.Error(t, err)
	})

	t.Run("cert-with-no-uri-san", func(t *testing.T) {
		t.Parallel()
		leaf := mintSpiffeLeafForTest(t, "")
		_, err := IdentitySpiffeFromCert(leaf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "spiffe://")
	})

	t.Run("cert-with-non-spiffe-uri-san", func(t *testing.T) {
		t.Parallel()
		leaf := mintSpiffeLeafForTest(t, "https://example.com/workload")
		_, err := IdentitySpiffeFromCert(leaf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "spiffe://")
	})

	t.Run("cert-with-malformed-spiffe-uri", func(t *testing.T) {
		t.Parallel()
		// Valid URI scheme but not a valid SPIFFE ID (empty trust domain).
		leaf := mintSpiffeLeafForTest(t, "spiffe:///workload")
		_, err := IdentitySpiffeFromCert(leaf)
		require.Error(t, err)
	})
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
