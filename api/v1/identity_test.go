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
		{"spiffe-valid-svid", false, &Identity{
			Spiffe: &IdentitySpiffe{Svid: "spiffe://example.org/workload"},
		}},
		{"spiffe-valid-matcher-only", false, &Identity{
			Spiffe: &IdentitySpiffe{
				TrustDomainMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "example.org"},
				},
			},
		}},
		{"spiffe-no-constraint", true, &Identity{
			Spiffe: &IdentitySpiffe{},
		}},
		{"spiffe-invalid-svid", true, &Identity{
			Spiffe: &IdentitySpiffe{Svid: "not-a-spiffe-uri"},
		}},
		{"spiffe-bad-regex-in-path-match", true, &Identity{
			Spiffe: &IdentitySpiffe{
				PathMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"spiffe-bad-glob-in-svid-match", true, &Identity{
			Spiffe: &IdentitySpiffe{
				SvidMatch: &StringMatcher{
					Kind: &StringMatcher_Glob{Glob: "[malformed"},
				},
			},
		}},
		{"sigstore-legacy-regex-bad", true, func() *Identity {
			mode := SigstoreModeRegexp
			return &Identity{
				Sigstore: &IdentitySigstore{
					Mode:     &mode,
					Issuer:   "https://accounts.google.com",
					Identity: "[unclosed",
				},
			}
		}()},
		{"sigstore-legacy-half-specified", true, &Identity{
			Sigstore: &IdentitySigstore{Issuer: "https://accounts.google.com"},
		}},
		{"sigstore-matcher-only-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				IssuerMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://accounts.google.com"},
				},
			},
		}},
		{"sigstore-identity-match-bad-regex", true, &Identity{
			Sigstore: &IdentitySigstore{
				IdentityMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"key-id-match-valid", false, &Identity{
			Key: &IdentityKey{
				IdMatch: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "abc123"},
				},
			},
		}},
		{"key-type-match-bad-regex", true, &Identity{
			Key: &IdentityKey{
				Id: "abc123",
				TypeMatch: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				},
			},
		}},
		{"outer-matcher-missing-field", true, &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "u@example.com",
			},
			Matchers: []*Matcher{{
				Kind: &Matcher_String_{String_: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "foo"},
				}},
			}},
		}},
		{"outer-matcher-bad-regex", true, &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "u@example.com",
			},
			Matchers: []*Matcher{{
				Field: "sigstore.issuer",
				Kind: &Matcher_String_{String_: &StringMatcher{
					Kind: &StringMatcher_Regex{Regex: "[unclosed"},
				}},
			}},
		}},
		{"outer-matcher-valid", false, &Identity{
			Sigstore: &IdentitySigstore{
				Issuer:   "https://accounts.google.com",
				Identity: "u@example.com",
			},
			Matchers: []*Matcher{{
				Field: "sigstore.issuer",
				Kind: &Matcher_String_{String_: &StringMatcher{
					Kind: &StringMatcher_Exact{Exact: "https://accounts.google.com"},
				}},
			}},
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

func TestIdentityPrincipalRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		principal string
	}{
		{"sigstore", "sigstore::https://accounts.google.com::user@example.com"},
		{"sigstore-regex-pattern", "sigstore::https://.*::.*@example\\.com"},
		{"key", "key::rsa::1234abcdef"},
		{"ref", "ref:shared-identity"},
		{"spiffe", "spiffe://prod.example.org/workload/api"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, err := NewIdentityFromPrincipal(tt.principal)
			require.NoError(t, err)
			require.Equal(t, tt.principal, id.Principal())
		})
	}
}

// TestIdentityPrincipalLegacyRegexpFormAccepted documents that the parser
// still accepts the historical "sigstore(regexp)::..." principal form for
// back-compat, but Principal() now emits the bare form — matcher semantics
// (Mode=regexp) are not part of the principal identifier.
func TestIdentityPrincipalLegacyRegexpFormAccepted(t *testing.T) {
	t.Parallel()
	id, err := NewIdentityFromPrincipal("sigstore(regexp)::https://.*::.*@example\\.com")
	require.NoError(t, err)
	require.NotNil(t, id.GetSigstore())
	require.Equal(t, SigstoreModeRegexp, id.GetSigstore().GetMode())
	require.Equal(t, "https://.*", id.GetSigstore().GetIssuer())
	require.Equal(t, ".*@example\\.com", id.GetSigstore().GetIdentity())
	require.Equal(t,
		"sigstore::https://.*::.*@example\\.com",
		id.Principal(),
		"Principal() drops the (regexp) marker — matcher semantics aren't part of the identifier")
}

func TestIdentitySlugAliasesPrincipal(t *testing.T) {
	t.Parallel()
	// Existing callers using the deprecated names must see identical
	// behavior to the new names.
	viaPrincipal, err := NewIdentityFromPrincipal("sigstore::https://accounts.google.com::user@example.com")
	require.NoError(t, err)
	viaSlug, err := NewIdentityFromSlug("sigstore::https://accounts.google.com::user@example.com")
	require.NoError(t, err)
	require.Equal(t, viaPrincipal.Principal(), viaSlug.Principal())
	require.Equal(t, viaPrincipal.Slug(), viaPrincipal.Principal())
}

func TestIdentitySpiffeFromString(t *testing.T) {
	t.Parallel()

	t.Run("success-with-path", func(t *testing.T) {
		t.Parallel()
		id, err := IdentitySpiffeFromString("spiffe://prod.example.org/workload/api")
		require.NoError(t, err)
		require.Equal(t, "spiffe://prod.example.org/workload/api", id.GetSvid())
		require.Empty(t, id.GetTrustRoots())
	})

	t.Run("success-no-path", func(t *testing.T) {
		t.Parallel()
		id, err := IdentitySpiffeFromString("spiffe://example.org")
		require.NoError(t, err)
		require.Equal(t, "spiffe://example.org", id.GetSvid())
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
		require.Equal(t, "spiffe://prod.example.org/workload/api", id.GetSvid())
		require.Empty(t, id.GetTrustRoots(), "TrustRoots must not be populated on the verified-side identity")
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
