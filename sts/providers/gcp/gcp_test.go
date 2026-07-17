// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeJWT builds an unsigned three-part JWT whose payload carries the given
// subject, enough for subjectFromJWT to parse.
func fakeJWT(t *testing.T, subject string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + subject + `","aud":"sigstore"}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return header + "." + payload + "." + sig
}

func TestProvide(t *testing.T) {
	t.Parallel()
	const subject = "miniprow@example.iam.gserviceaccount.com"
	token := fakeJWT(t, subject)

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/computeMetadata/v1/instance/service-accounts/default/identity", r.URL.Path)
			assert.Equal(t, "sigstore", r.URL.Query().Get("audience"))
			assert.Equal(t, "full", r.URL.Query().Get("format"))
			assert.Equal(t, metadataFlavorValue, r.Header.Get(metadataFlavorHeader))
			w.Header().Set(metadataFlavorHeader, metadataFlavorValue)
			_, _ = w.Write([]byte(token + "\n")) //nolint:errcheck // test handler
		}))
		defer srv.Close()

		m := &Metadata{Host: srv.URL, Client: srv.Client()}
		got, err := m.Provide(context.Background(), "sigstore")
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, token, got.RawString)
		assert.Equal(t, subject, got.Subject)
	})

	t.Run("not on gcp - transport error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(metadataFlavorHeader, metadataFlavorValue)
			_, _ = w.Write([]byte(token)) //nolint:errcheck // test handler
		}))
		url := srv.URL
		srv.Close() // now unreachable: stands in for "not on Google Cloud"

		m := &Metadata{Host: url, Client: srv.Client()}
		got, err := m.Provide(context.Background(), "sigstore")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("missing metadata-flavor header is not the real server", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// No Metadata-Flavor response header.
			_, _ = w.Write([]byte(token)) //nolint:errcheck // test handler
		}))
		defer srv.Close()

		m := &Metadata{Host: srv.URL, Client: srv.Client()}
		got, err := m.Provide(context.Background(), "sigstore")
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("on gcp but non-200 is an error", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(metadataFlavorHeader, metadataFlavorValue)
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		m := &Metadata{Host: srv.URL, Client: srv.Client()}
		got, err := m.Provide(context.Background(), "sigstore")
		require.Error(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty audience is rejected", func(t *testing.T) {
		t.Parallel()
		m := &Metadata{}
		_, err := m.Provide(context.Background(), "  ")
		require.Error(t, err)
	})

	t.Run("invalid audience is rejected", func(t *testing.T) {
		t.Parallel()
		m := &Metadata{}
		_, err := m.Provide(context.Background(), "bad audience?x=1")
		require.Error(t, err)
	})
}
