// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitlab

import (
	"context"
	"os"
	"testing"
)

func TestCI_Provide(t *testing.T) {
	// A valid JWT token for testing (header.payload.signature)
	// This is a minimal JWT with {"sub": "project_path:mygroup/myproject:ref_type:branch:ref:main"}
	// Note: The signature is invalid, but that's OK because SubjectFromUnverifiedToken
	// doesn't verify signatures - Fulcio will do that later.
	validJWT := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwcm9qZWN0X3BhdGg6bXlncm91cC9teXByb2plY3Q6cmVmX3R5cGU6YnJhbmNoOnJlZjptYWluIiwiaXNzIjoiaHR0cHM6Ly9naXRsYWIuZXhhbXBsZS5jb20iLCJhdWQiOiJzaWdzdG9yZSJ9.fake-signature"

	tests := []struct {
		name        string
		envValue    string
		wantToken   bool
		wantSubject string
		wantErr     bool
	}{
		{
			name:        "valid JWT token",
			envValue:    validJWT,
			wantToken:   true,
			wantSubject: "project_path:mygroup/myproject:ref_type:branch:ref:main",
			wantErr:     false,
		},
		{
			name:      "token absent",
			envValue:  "",
			wantToken: false,
			wantErr:   false,
		},
		{
			name:      "invalid JWT token",
			envValue:  "not-a-jwt-token",
			wantToken: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			if tt.envValue != "" {
				t.Setenv(VariableGitLabIDToken, tt.envValue)
				defer os.Unsetenv(VariableGitLabIDToken) //nolint:errcheck
			} else {
				os.Unsetenv(VariableGitLabIDToken) //nolint:errcheck
			}

			// Run the provider
			ci := &CI{}
			token, err := ci.Provide(context.Background(), "sigstore")

			// Check error
			if (err != nil) != tt.wantErr {
				t.Errorf("Provide() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check token presence
			if (token != nil) != tt.wantToken {
				t.Errorf("Provide() token = %v, wantToken %v", token, tt.wantToken)
				return
			}

			// If we expect a token, verify its values
			if tt.wantToken {
				if token.RawString != tt.envValue {
					t.Errorf("Provide() token.RawString = %v, want %v", token.RawString, tt.envValue)
				}
				if token.Subject != tt.wantSubject {
					t.Errorf("Provide() token.Subject = %v, want %v", token.Subject, tt.wantSubject)
				}
			}
		})
	}
}
