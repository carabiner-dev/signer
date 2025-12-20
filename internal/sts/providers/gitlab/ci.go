// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gitlab implements a client to read OIDC tokens from GitLab CI
// using the SIGSTORE_ID_TOKEN environment variable.
package gitlab

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

const (
	// VariableGitLabIDToken is the environment variable that GitLab CI
	// sets when id_tokens are configured in the pipeline.
	VariableGitLabIDToken = "SIGSTORE_ID_TOKEN" //nolint:gosec // These are not hardcoded credentials
)

type CI struct{}

// Provide reads the OIDC token from the SIGSTORE_ID_TOKEN environment variable.
// This token should be configured in GitLab CI with:
//
//	id_tokens:
//	  SIGSTORE_ID_TOKEN:
//	    aud: sigstore
//
// See: https://docs.gitlab.com/ci/yaml/signing_examples/#sign-or-verify-container-images-and-build-artifacts-by-using-cosign
func (ci *CI) Provide(ctx context.Context, audience string) (*oauthflow.OIDCIDToken, error) {
	// Get the token from the environment
	rawToken := os.Getenv(VariableGitLabIDToken)
	if rawToken == "" {
		return nil, nil
	}

	// Extract the subject from the JWT token by parsing it.
	// We parse without verifying the signature because Fulcio will
	// verify the token when issuing the certificate.
	subject, err := extractSubjectFromJWT(rawToken)
	if err != nil {
		return nil, fmt.Errorf("extracting subject from JWT token: %w", err)
	}

	token := &oauthflow.OIDCIDToken{
		RawString: rawToken,
		Subject:   subject,
	}

	return token, nil
}

// extractSubjectFromJWT extracts the subject claim from a JWT token.
// It decodes the payload portion of the JWT and parses it to extract the subject.
func extractSubjectFromJWT(token string) (string, error) {
	// JWT format is: header.payload.signature
	// We need to extract and decode the payload (middle part)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (base64url encoding)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decoding JWT payload: %w", err)
	}

	// Use the oauthflow helper to extract the subject from the decoded payload
	return oauthflow.SubjectFromUnverifiedToken(payload)
}
