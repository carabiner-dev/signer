// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gcp implements an ambient STS provider that reads an OIDC identity
// token for the current service account from the Google Cloud metadata
// server. It works on any Google Cloud compute surface that exposes the
// metadata server (Cloud Run, GCE, GKE, Cloud Functions).
//
// When not running on Google Cloud the provider reports no token (nil, nil)
// so the ambient credential flow falls through to the other providers. It is
// deliberately dependency-light (standard library + oauthflow only), matching
// the github and gitlab providers, so it belongs in signer itself rather than
// signer-extras.
package gcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// defaultMetadataHost is the Google Cloud metadata server hostname.
	defaultMetadataHost = "metadata.google.internal"

	// metadataHostEnv mirrors the variable honoured by Google's own client
	// libraries; when set it overrides the metadata host. It is also how tests
	// point the provider at an httptest server.
	metadataHostEnv = "GCE_METADATA_HOST"

	// metadataFlavorHeader / metadataFlavorValue identify a genuine Google
	// metadata server. The request must send it and the server echoes it back;
	// we require it on the response to confirm we are really talking to the
	// metadata server and not some proxy that happened to resolve
	// metadata.google.internal.
	metadataFlavorHeader = "Metadata-Flavor"
	metadataFlavorValue  = "Google"

	// identityPath mints an OIDC identity token for the default service
	// account.
	identityPath = "/computeMetadata/v1/instance/service-accounts/default/identity"

	// defaultTimeout bounds the metadata request. Off Google Cloud the dial
	// usually fails fast, but this cap keeps a slow or hanging lookup from
	// stalling the ambient probe that runs on every signing.
	defaultTimeout = 2 * time.Second
)

// Metadata is an STS provider backed by the Google Cloud metadata server. The
// zero value is ready to use as an ambient provider; the exported fields exist
// so tests can redirect it and are not needed in production.
type Metadata struct {
	// Host overrides the metadata server host. Defaults to $GCE_METADATA_HOST,
	// then metadata.google.internal. May include a scheme (used by tests).
	Host string
	// Client overrides the HTTP client. Defaults to a client with Timeout.
	Client *http.Client
	// Timeout is used when Client is nil. Defaults to defaultTimeout.
	Timeout time.Duration
}

// Provide returns an OIDC identity token for the current service account with
// the given audience, or (nil, nil) when not running on Google Cloud.
func (m *Metadata) Provide(ctx context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	audience = strings.TrimSpace(audience)
	if audience == "" {
		return nil, fmt.Errorf("audience string must not be empty")
	}
	if strings.ContainsAny(audience, " \t\n\r&?#") {
		return nil, fmt.Errorf("audience string contains invalid characters")
	}

	endpoint := fmt.Sprintf(
		"%s%s?audience=%s&format=full", m.baseURL(), identityPath, url.QueryEscape(audience),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(metadataFlavorHeader, metadataFlavorValue)

	resp, err := m.client().Do(req)
	if err != nil {
		// A transport error means the metadata server is unreachable, i.e. we
		// are not on Google Cloud. Report no token so the ambient flow tries
		// the next provider rather than failing the whole signing.
		return nil, nil
	}
	defer resp.Body.Close() //nolint:errcheck

	// Confirm this really is the Google metadata server and not something else
	// that answered the metadata hostname.
	if resp.Header.Get(metadataFlavorHeader) != metadataFlavorValue {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"metadata server returned status %d requesting identity token", resp.StatusCode,
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading identity token from metadata server: %w", err)
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		return nil, fmt.Errorf("metadata server returned an empty identity token")
	}

	subject, err := subjectFromJWT(raw)
	if err != nil {
		return nil, fmt.Errorf("extracting subject from identity token: %w", err)
	}

	return &oauthflow.OIDCIDToken{RawString: raw, Subject: subject}, nil
}

// baseURL returns the scheme+host of the metadata server. The metadata server
// speaks plain HTTP; a Host that already carries a scheme (as tests supply) is
// used verbatim.
func (m *Metadata) baseURL() string {
	h := m.host()
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		return strings.TrimSuffix(h, "/")
	}
	return "http://" + h
}

func (m *Metadata) host() string {
	if m.Host != "" {
		return m.Host
	}
	if env := os.Getenv(metadataHostEnv); env != "" {
		return env
	}
	return defaultMetadataHost
}

func (m *Metadata) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	timeout := m.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &http.Client{Timeout: timeout}
}

// subjectFromJWT extracts the subject claim from an unverified JWT (Fulcio
// verifies the token when issuing the certificate). Mirrors the gitlab
// provider's handling.
func subjectFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding JWT payload: %w", err)
	}
	return oauthflow.SubjectFromUnverifiedToken(payload)
}
