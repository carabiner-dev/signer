// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEmail = "signer@example.iam.gserviceaccount.com"

// testKey is generated once; 2048-bit keygen is slow enough to share.
var testKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

// serviceAccountJSON builds a service-account key file whose token_uri points
// at tokenURI (an httptest server in these tests).
func serviceAccountJSON(t *testing.T, tokenURI string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(testKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	data, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"client_email":   testEmail,
		"private_key_id": "key-1",
		"private_key":    string(keyPEM),
		"token_uri":      tokenURI,
	})
	require.NoError(t, err)
	return data
}

// tokenEndpoint fakes Google's OAuth token endpoint: it verifies the
// JWT-bearer request (including the assertion's RS256 signature and claims)
// and answers with an id_token for the requested target_audience.
func tokenEndpoint(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, jwtBearerGrant, r.Form.Get("grant_type"))

		parts := splitJWT(t, r.Form.Get("assertion"))
		digest := sha256.Sum256([]byte(parts.signingInput))
		assert.NoError(t, rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, digest[:], parts.signature))
		assert.Equal(t, testEmail, parts.claims["iss"])
		assert.Equal(t, testEmail, parts.claims["sub"])
		assert.Equal(t, "sigstore", parts.claims["target_audience"])

		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		idToken := fakeJWT(t, testEmail)
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"id_token": idToken}))
	}))
}

type jwtParts struct {
	signingInput string
	signature    []byte
	claims       map[string]any
}

func splitJWT(t *testing.T, token string) jwtParts {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "assertion is not a three-part JWT")
	rawSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(rawPayload, &claims))
	return jwtParts{
		signingInput: parts[0] + "." + parts[1],
		signature:    rawSig,
		claims:       claims,
	}
}

// metadataServer fakes the metadata server answering with a token.
func metadataServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(metadataFlavorHeader, metadataFlavorValue)
		_, _ = w.Write([]byte(fakeJWT(t, "metadata-sa@example.iam.gserviceaccount.com"))) //nolint:errcheck // test handler
	}))
}

// deadMetadata returns a Metadata pointed at a closed server, standing in for
// "not on Google Cloud".
func deadMetadata(t *testing.T) Metadata {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	return Metadata{Host: srv.URL}
}

// TestProviderProvide covers the credential resolution of the full Provider.
// No t.Parallel: the subtests use t.Setenv to isolate the ADC variable.
func TestProviderProvide(t *testing.T) { //nolint:paralleltest
	ctx := context.Background()

	t.Run("explicit service account", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		srv := tokenEndpoint(t, http.StatusOK)
		defer srv.Close()

		p, err := New(WithServiceAccountJSON(serviceAccountJSON(t, srv.URL)))
		require.NoError(t, err)
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, testEmail, got.Subject)
	})

	t.Run("service account failure falls back to metadata by default", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		exchange := tokenEndpoint(t, http.StatusForbidden)
		defer exchange.Close()
		meta := metadataServer(t)
		defer meta.Close()

		p, err := New(WithServiceAccountJSON(serviceAccountJSON(t, exchange.URL)))
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "metadata-sa@example.iam.gserviceaccount.com", got.Subject)
	})

	t.Run("service account failure without fallback errors", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		exchange := tokenEndpoint(t, http.StatusForbidden)
		defer exchange.Close()
		meta := metadataServer(t)
		defer meta.Close()

		p, err := New(
			WithServiceAccountJSON(serviceAccountJSON(t, exchange.URL)),
			WithAmbientCredentials(false),
		)
		require.NoError(t, err)
		p.Metadata = Metadata{Host: meta.URL}
		_, err = p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "403")
	})

	t.Run("service account failure with no metadata surfaces the exchange error", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		exchange := tokenEndpoint(t, http.StatusForbidden)
		defer exchange.Close()

		p, err := New(WithServiceAccountJSON(serviceAccountJSON(t, exchange.URL)))
		require.NoError(t, err)
		p.Metadata = deadMetadata(t)
		_, err = p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "403")
	})

	t.Run("env var service account is used", func(t *testing.T) {
		srv := tokenEndpoint(t, http.StatusOK)
		defer srv.Close()
		path := filepath.Join(t.TempDir(), "key.json")
		require.NoError(t, os.WriteFile(path, serviceAccountJSON(t, srv.URL), 0o600))
		t.Setenv(credentialsEnv, path)

		p := &Provider{Metadata: deadMetadata(t)}
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, testEmail, got.Subject)
	})

	t.Run("explicit key wins over env var", func(t *testing.T) {
		srv := tokenEndpoint(t, http.StatusOK)
		defer srv.Close()
		t.Setenv(credentialsEnv, filepath.Join(t.TempDir(), "missing.json"))

		p, err := New(WithServiceAccountJSON(serviceAccountJSON(t, srv.URL)))
		require.NoError(t, err)
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
	})

	t.Run("unsupported env credential type falls through silently", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wif.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"type":"external_account"}`), 0o600))
		t.Setenv(credentialsEnv, path)
		meta := metadataServer(t)
		defer meta.Close()

		p := &Provider{Metadata: Metadata{Host: meta.URL}}
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "metadata-sa@example.iam.gserviceaccount.com", got.Subject)
	})

	t.Run("broken env credential with no metadata errors", func(t *testing.T) {
		t.Setenv(credentialsEnv, filepath.Join(t.TempDir(), "missing.json"))
		p := &Provider{Metadata: deadMetadata(t)}
		_, err := p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, credentialsEnv)
	})

	t.Run("zero value off gcp reports no token", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		p := &Provider{Metadata: deadMetadata(t)}
		got, err := p.Provide(ctx, "sigstore")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("ambient disabled with no key is an error", func(t *testing.T) {
		t.Setenv(credentialsEnv, "")
		p, err := New(WithAmbientCredentials(false))
		require.NoError(t, err)
		_, err = p.Provide(ctx, "sigstore")
		require.ErrorContains(t, err, "no service account key")
	})
}

func TestNewOptions(t *testing.T) {
	t.Parallel()

	t.Run("invalid json is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := New(WithServiceAccountJSON([]byte("not json")))
		require.Error(t, err)
	})

	t.Run("non service account credential is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := New(WithServiceAccountJSON([]byte(`{"type":"authorized_user"}`)))
		require.ErrorContains(t, err, "not a service account")
	})

	t.Run("missing key file is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := New(WithServiceAccountFile(filepath.Join(t.TempDir(), "nope.json")))
		require.Error(t, err)
	})

	t.Run("key file loads", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "key.json")
		require.NoError(t, os.WriteFile(path, serviceAccountJSON(t, "https://example.com/token"), 0o600))
		p, err := New(WithServiceAccountFile(path))
		require.NoError(t, err)
		require.NotNil(t, p)
	})
}
