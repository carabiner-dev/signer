// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// impersonateEnv names the service account to impersonate when none is
	// configured explicitly. It is the variable cosign's google-impersonate
	// provider honours, so environments set up for cosign work unchanged.
	impersonateEnv = "GOOGLE_SERVICE_ACCOUNT_NAME"

	// defaultIAMCredentialsURL is the base URL of the IAM Credentials API.
	defaultIAMCredentialsURL = "https://iamcredentials.googleapis.com" //nolint:gosec // G101: public endpoint URL, not a credential

	// generateIDTokenPath is the IAM Credentials method that mints an OIDC
	// identity token for a service account. The "-" project wildcard lets
	// the API resolve the account's project from its email.
	generateIDTokenPath = "/v1/projects/-/serviceAccounts/%s:generateIdToken"
)

// impersonationTarget returns the service account to impersonate: the one
// configured with WithImpersonation, else the one named by
// $GOOGLE_SERVICE_ACCOUNT_NAME, else none.
func (p *Provider) impersonationTarget() string {
	if p.target != "" {
		return p.target
	}
	return strings.TrimSpace(os.Getenv(impersonateEnv))
}

// impersonate mints an identity token for target with the given audience by
// authenticating to the IAM Credentials API with the provider's own
// credential. Unlike the direct flows it never falls back: an explicitly
// requested identity either signs or fails.
func (p *Provider) impersonate(ctx context.Context, target, audience string) (*oauthflow.OIDCIDToken, error) {
	audience, err := validateAudience(audience)
	if err != nil {
		return nil, err
	}

	accessToken, err := p.callerAccessToken(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("impersonating %s: %w", target, err)
	}

	token, err := p.generateIDToken(ctx, target, audience, accessToken)
	if err != nil {
		return nil, fmt.Errorf("impersonating %s: %w", target, err)
	}
	return token, nil
}

// callerAccessToken returns an access token for the credential that will
// call the IAM Credentials API: the configured or $GOOGLE_APPLICATION_CREDENTIALS
// service-account key, else the metadata server identity.
func (p *Provider) callerAccessToken(ctx context.Context, target string) (string, error) {
	sa, err := p.credential()
	if err != nil {
		return "", err
	}
	if sa != nil {
		token, err := sa.accessToken(ctx)
		if err != nil {
			return "", fmt.Errorf("obtaining access token for %s: %w", sa.ClientEmail, err)
		}
		return token, nil
	}

	if !p.ambientEnabled() {
		return "", errors.New("ambient credentials disabled and no service account key configured")
	}

	token, err := p.Metadata.AccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("obtaining access token from metadata server: %w", err)
	}
	if token == "" {
		return "", fmt.Errorf(
			"no Google Cloud credential available to impersonate %s (no service account key and no metadata server)",
			target,
		)
	}
	return token, nil
}

// generateIDToken calls the IAM Credentials API to mint an identity token for
// target with the given audience, authenticated with accessToken.
func (p *Provider) generateIDToken(
	ctx context.Context, target, audience, accessToken string,
) (*oauthflow.OIDCIDToken, error) {
	payload, err := json.Marshal(struct {
		Audience     string `json:"audience"`
		IncludeEmail bool   `json:"includeEmail"`
	}{
		Audience:     audience,
		IncludeEmail: true,
	})
	if err != nil {
		return nil, err
	}

	endpoint := p.iamCredentialsURL() + fmt.Sprintf(generateIDTokenPath, target)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: exchangeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling the IAM credentials API: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading IAM credentials API response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"IAM credentials API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)),
		)
	}

	token := struct {
		Token string `json:"token"`
	}{}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parsing IAM credentials API response: %w", err)
	}
	if token.Token == "" {
		return nil, errors.New("IAM credentials API response has no token")
	}

	subject, err := subjectFromJWT(token.Token)
	if err != nil {
		return nil, fmt.Errorf("extracting subject from identity token: %w", err)
	}
	return &oauthflow.OIDCIDToken{RawString: token.Token, Subject: subject}, nil
}

func (p *Provider) iamCredentialsURL() string {
	if p.iamURL != "" {
		return strings.TrimSuffix(p.iamURL, "/")
	}
	return defaultIAMCredentialsURL
}
