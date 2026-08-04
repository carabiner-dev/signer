// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// credentialsEnv is Google's standard application-default-credentials
	// variable. When no key is configured explicitly the provider reads the
	// key file it names, mirroring ADC precedence.
	credentialsEnv = "GOOGLE_APPLICATION_CREDENTIALS" //nolint:gosec // G101: env variable name, not a credential

	// serviceAccountType is the only ADC credential type this provider can
	// exchange. The other types (authorized_user, external_account) cannot
	// mint arbitrary-audience identity tokens from a self-signed assertion.
	serviceAccountType = "service_account"

	// defaultTokenURI is used when the key file omits token_uri.
	defaultTokenURI = "https://oauth2.googleapis.com/token" //nolint:gosec // G101: public endpoint URL, not a credential

	// jwtBearerGrant is the RFC 7523 grant type for the assertion exchange.
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: RFC 7523 grant type URN, not a credential

	// exchangeTimeout bounds the call to the OAuth token endpoint. Unlike the
	// metadata probe this is a real internet round trip, so it gets more room
	// than defaultTimeout.
	exchangeTimeout = 10 * time.Second

	// assertionLifetime is the validity window of the self-signed assertion.
	// It only needs to outlive the exchange request.
	assertionLifetime = 5 * time.Minute

	// assertionSkew is subtracted from the assertion's iat so a slightly
	// fast local clock does not make Google reject it as not yet valid.
	assertionSkew = 10 * time.Second
)

// serviceAccount is a parsed Google service-account key file.
type serviceAccount struct {
	Type         string `json:"type"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	TokenURI     string `json:"token_uri"`

	key *rsa.PrivateKey
}

// parseServiceAccount parses and validates a service-account JSON key,
// including its private key, so misconfiguration surfaces at option time
// rather than on the first signing.
func parseServiceAccount(data []byte) (*serviceAccount, error) {
	sa := &serviceAccount{}
	if err := json.Unmarshal(data, sa); err != nil {
		return nil, fmt.Errorf("parsing service account JSON: %w", err)
	}
	if sa.Type != serviceAccountType {
		return nil, fmt.Errorf("credential type %q is not a service account key", sa.Type)
	}
	if sa.ClientEmail == "" {
		return nil, errors.New("service account key has no client_email")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = defaultTokenURI
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("service account key has no PEM-encoded private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing service account private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("service account private key is %T, expected RSA", parsed)
	}
	sa.key = rsaKey
	return sa, nil
}

// provide mints an OIDC identity token for the audience by signing a
// JWT-bearer assertion with the service-account key and exchanging it at the
// key's token endpoint. This is the same flow Google's idtoken package runs,
// implemented on the standard library to keep the package dependency-light.
func (sa *serviceAccount) provide(ctx context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	audience, err := validateAudience(audience)
	if err != nil {
		return nil, err
	}

	assertion, err := sa.signAssertion(audience, time.Now())
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type": []string{jwtBearerGrant},
		"assertion":  []string{assertion},
	}
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, sa.TokenURI, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: exchangeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging service account assertion: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Cap the read: the endpoint returns a small JSON document and error
	// bodies only get quoted in the message below.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading token endpoint response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"token endpoint returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)),
		)
	}

	token := struct {
		IDToken string `json:"id_token"`
	}{}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parsing token endpoint response: %w", err)
	}
	if token.IDToken == "" {
		return nil, errors.New("token endpoint response has no id_token")
	}

	subject, err := subjectFromJWT(token.IDToken)
	if err != nil {
		return nil, fmt.Errorf("extracting subject from identity token: %w", err)
	}
	return &oauthflow.OIDCIDToken{RawString: token.IDToken, Subject: subject}, nil
}

// signAssertion builds and signs the RS256 JWT-bearer assertion whose
// target_audience claim asks Google for an identity token with that audience.
func (sa *serviceAccount) signAssertion(audience string, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": sa.PrivateKeyID,
	})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Issuer         string `json:"iss"`
		Subject        string `json:"sub"`
		Audience       string `json:"aud"`
		IssuedAt       int64  `json:"iat"`
		Expiry         int64  `json:"exp"`
		TargetAudience string `json:"target_audience"`
	}{
		Issuer:         sa.ClientEmail,
		Subject:        sa.ClientEmail,
		Audience:       sa.TokenURI,
		IssuedAt:       now.Add(-assertionSkew).Unix(),
		Expiry:         now.Add(assertionLifetime).Unix(),
		TargetAudience: audience,
	})
	if err != nil {
		return "", err
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) +
		"." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, sa.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}
