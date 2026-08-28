// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	targetEmail       = "signer-target@example.iam.gserviceaccount.com"
	metadataAccessTok = "metadata-access-token"
	keyAccessTok      = "key-access-token"
)

// iamCredentialsServer fakes the IAM Credentials API generateIdToken method.
// It checks the target in the path, the bearer token and the request body and
// answers with an identity token for the target.
func iamCredentialsServer(t *testing.T, wantBearer string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, fmt.Sprintf(generateIDTokenPath, targetEmail), r.URL.Path)
		assert.Equal(t, "Bearer "+wantBearer, r.Header.Get("Authorization"))

		body := struct {
			Audience     string `json:"audience"`
			IncludeEmail bool   `json:"includeEmail"`
		}{}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "sigstore", body.Audience)
		assert.True(t, body.IncludeEmail)

		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error": {"message": "permission denied"}}`)) //nolint:errcheck // test handler
			return
		}
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"token": fakeJWT(t, targetEmail)}))
	}))
}

// metadataWithAccessToken fakes a metadata server that serves both identity
// and access tokens.
func metadataWithAccessToken(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, metadataFlavorValue, r.Header.Get(metadataFlavorHeader))
		w.Header().Set(metadataFlavorHeader, metadataFlavorValue)
		switch r.URL.Path {
		case accessTokenPath:
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"access_token": metadataAccessTok, "expires_in": 3600, "token_type": "Bearer",
			}))
		case identityPath:
			_, _ = w.Write([]byte(fakeJWT(t, "metadata-sa@example.iam.gserviceaccount.com"))) //nolint:errcheck // test handler
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// accessTokenEndpoint fakes the OAuth token endpoint for a scoped JWT-bearer
// exchange: it verifies the assertion asks for the cloud platform scope and
// answers with an access token.
func accessTokenEndpoint(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, jwtBearerGrant, r.Form.Get("grant_type"))

		parts := splitJWT(t, r.Form.Get("assertion"))
		digest := sha256.Sum256([]byte(parts.signingInput))
		assert.NoError(t, rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, digest[:], parts.signature))
		assert.Equal(t, testEmail, parts.claims["iss"])
		assert.Equal(t, cloudPlatformScope, parts.claims["scope"])
		assert.Nil(t, parts.claims["target_audience"], "access token assertions must not carry target_audience")

		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"access_token": keyAccessTok}))
	}))
}

// TestImpersonate covers minting identity tokens for another service account.
// No t.Parallel: the subtests use t.Setenv.
func TestImpersonate(t *testing.T) { //nolint:paralleltest
	ctx := context.Background()

	t.Run("metadata identity impersonates the target", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "")
		iam := iamCredentialsServer(t, metadataAccessTok, http.StatusOK)
		defer iam.Close()
		meta := metadataWithAccessToken(t)
		defer meta.Close()

		p, err := New(WithImpersonation(targetEmail))
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}
		p.iamURL = iam.URL

		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, targetEmail, got.Subject)
		assert.Len(t, strings.Split(got.RawString, "."), 3)
	})

	t.Run("service account key impersonates the target", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "")
		iam := iamCredentialsServer(t, keyAccessTok, http.StatusOK)
		defer iam.Close()
		exchange := accessTokenEndpoint(t)
		defer exchange.Close()

		p, err := New(
			WithServiceAccountJSON(serviceAccountJSON(t, exchange.URL)),
			WithImpersonation(targetEmail),
			WithAmbientCredentials(false),
		)
		require.NoError(t, err)
		p.Metadata = deadMetadata(t)
		p.iamURL = iam.URL

		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, targetEmail, got.Subject)
	})

	t.Run("env var names the target for the zero value provider", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, targetEmail)
		iam := iamCredentialsServer(t, metadataAccessTok, http.StatusOK)
		defer iam.Close()
		meta := metadataWithAccessToken(t)
		defer meta.Close()

		p := &Provider{Metadata: Metadata{Host: meta.URL}, iamURL: iam.URL}
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, targetEmail, got.Subject)
	})

	t.Run("explicit target wins over env var", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "someone-else@example.iam.gserviceaccount.com")
		iam := iamCredentialsServer(t, metadataAccessTok, http.StatusOK)
		defer iam.Close()
		meta := metadataWithAccessToken(t)
		defer meta.Close()

		p, err := New(WithImpersonation(targetEmail))
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}
		p.iamURL = iam.URL

		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		assert.Equal(t, targetEmail, got.Subject)
	})

	t.Run("denied impersonation is an error, never a fallback", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "")
		iam := iamCredentialsServer(t, metadataAccessTok, http.StatusForbidden)
		defer iam.Close()
		meta := metadataWithAccessToken(t)
		defer meta.Close()

		p, err := New(WithImpersonation(targetEmail))
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}
		p.iamURL = iam.URL

		got, err := p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "403")
		require.ErrorContains(t, err, targetEmail)
		assert.Nil(t, got)
	})

	t.Run("no caller credential is an error", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "")
		iam := iamCredentialsServer(t, "", http.StatusOK)
		defer iam.Close()

		p, err := New(WithImpersonation(targetEmail))
		require.NoError(t, err)
		p.Metadata = deadMetadata(t)
		p.iamURL = iam.URL

		got, err := p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "no Google Cloud credential available")
		assert.Nil(t, got)
	})

	t.Run("ambient disabled without a key is an error", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "")
		meta := metadataWithAccessToken(t)
		defer meta.Close()

		p, err := New(WithImpersonation(targetEmail), WithAmbientCredentials(false))
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}

		got, err := p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "ambient credentials disabled")
		assert.Nil(t, got)
	})

	t.Run("failed key exchange is an error even with metadata available", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		t.Setenv(impersonateEnv, "")
		exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer exchange.Close()
		meta := metadataWithAccessToken(t)
		defer meta.Close()

		p, err := New(
			WithServiceAccountJSON(serviceAccountJSON(t, exchange.URL)),
			WithImpersonation(targetEmail),
		)
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}

		got, err := p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "403")
		assert.Nil(t, got)
	})

	t.Run("invalid audience is rejected before any request", func(t *testing.T) {
		t.Setenv(impersonateEnv, "")
		p, err := New(WithImpersonation(targetEmail))
		require.NoError(t, err)
		_, err = p.Provide(ctx, "bad audience")
		require.Error(t, err)
	})
}

func TestWithImpersonation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		target    string
		shouldErr bool
	}{
		{name: "valid email", target: targetEmail},
		{name: "trimmed", target: "  " + targetEmail + "  "},
		{name: "empty", target: "", shouldErr: true},
		{name: "not an email", target: "not-an-email", shouldErr: true},
		{name: "path characters", target: "a@b/c", shouldErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := New(WithImpersonation(tc.target))
			if tc.shouldErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, strings.TrimSpace(tc.target), p.impersonationTarget())
		})
	}
}

func TestMetadataAccessToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		meta := metadataWithAccessToken(t)
		defer meta.Close()
		got, err := (&Metadata{Host: meta.URL}).AccessToken(ctx)
		require.NoError(t, err)
		assert.Equal(t, metadataAccessTok, got)
	})

	t.Run("not on gcp reports no token", func(t *testing.T) {
		t.Parallel()
		m := deadMetadata(t)
		got, err := m.AccessToken(ctx)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("missing flavor header reports no token", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token": "x"}`)) //nolint:errcheck // test handler
		}))
		defer srv.Close()
		got, err := (&Metadata{Host: srv.URL}).AccessToken(ctx)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("server error is an error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(metadataFlavorHeader, metadataFlavorValue)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, err := (&Metadata{Host: srv.URL}).AccessToken(ctx)
		require.Error(t, err)
	})
}
