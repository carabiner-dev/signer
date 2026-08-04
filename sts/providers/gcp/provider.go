// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// Provider is the Google Cloud STS provider. It resolves a credential in
// application-default order: a service-account key configured with
// WithServiceAccountJSON / WithServiceAccountFile, then a key file named by
// $GOOGLE_APPLICATION_CREDENTIALS, then the ambient metadata server.
//
// When a service-account key fails, the provider falls back to the metadata
// server unless WithAmbientCredentials(false) disabled it. The zero value is
// the ambient default: no explicit key, env var honored, metadata enabled.
type Provider struct {
	// Metadata is the metadata-server provider used as the ambient credential
	// source. Its exported fields exist so tests can redirect it.
	Metadata Metadata

	sa      *serviceAccount
	ambient *bool
}

// Option configures a Provider built with New.
type Option func(*Provider) error

// New builds a Provider from the given options.
func New(opts ...Option) (*Provider, error) {
	p := &Provider{}
	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// WithServiceAccountJSON configures the provider to mint identity tokens with
// the given service-account JSON key instead of the ambient credentials.
func WithServiceAccountJSON(data []byte) Option {
	return func(p *Provider) error {
		sa, err := parseServiceAccount(data)
		if err != nil {
			return err
		}
		p.sa = sa
		return nil
	}
}

// WithServiceAccountFile is WithServiceAccountJSON reading the key from path.
func WithServiceAccountFile(path string) Option {
	return func(p *Provider) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading service account key: %w", err)
		}
		return WithServiceAccountJSON(data)(p)
	}
}

// WithAmbientCredentials controls whether the provider may use the metadata
// server, both as the last credential source and as the fallback when a
// configured service-account key fails. It defaults to enabled.
func WithAmbientCredentials(enabled bool) Option {
	return func(p *Provider) error {
		p.ambient = &enabled
		return nil
	}
}

func (p *Provider) ambientEnabled() bool {
	return p.ambient == nil || *p.ambient
}

// Provide returns an OIDC identity token with the given audience from the
// first credential source that yields one, or (nil, nil) when none is
// available and none was explicitly configured.
func (p *Provider) Provide(ctx context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	sa, saErr := p.credential()
	if sa != nil {
		token, err := sa.provide(ctx, audience)
		if err == nil {
			return token, nil
		}
		saErr = err
	}

	if !p.ambientEnabled() {
		if saErr != nil {
			return nil, saErr
		}
		return nil, errors.New("ambient credentials disabled and no service account key configured")
	}

	token, err := p.Metadata.Provide(ctx, audience)
	if err == nil && token != nil {
		return token, nil
	}
	if saErr != nil {
		// The configured key failed and the fallback produced nothing: the
		// key failure is the actionable error, don't swallow it.
		return nil, fmt.Errorf("service account credential failed (no metadata server fallback): %w", saErr)
	}
	return token, err
}

// credential returns the service-account key to use: the explicitly
// configured one, else one named by $GOOGLE_APPLICATION_CREDENTIALS. A nil,
// nil return means no key is in play and the metadata server is the only
// candidate. Env-var credentials of other ADC types (authorized_user,
// external_account) are skipped silently: they are valid for Google's own
// libraries but cannot mint arbitrary-audience identity tokens.
func (p *Provider) credential() (*serviceAccount, error) {
	if p.sa != nil {
		return p.sa, nil
	}
	path := os.Getenv(credentialsEnv)
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // G703: reading the file the env var names is the ADC contract
	if err != nil {
		return nil, fmt.Errorf("reading %s key file: %w", credentialsEnv, err)
	}
	probe := struct {
		Type string `json:"type"`
	}{}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parsing %s key file: %w", credentialsEnv, err)
	}
	if probe.Type != serviceAccountType {
		return nil, nil
	}
	sa, err := parseServiceAccount(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", credentialsEnv, err)
	}
	return sa, nil
}
