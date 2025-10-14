// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/bundle/bundlefakes"
	"github.com/carabiner-dev/signer/options"
)

func TestVerifyParsedBundleIntegration(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name        string
		mustErr     bool
		getVerifier func(t *testing.T) bundle.Verifier
	}{
		{"success", false, func(t *testing.T) bundle.Verifier {
			t.Helper()
			v := bundlefakes.FakeVerifier{}
			return &v
		}},
		{"BuildSigstoreVerifier-fails", true, func(t *testing.T) bundle.Verifier {
			t.Helper()
			v := bundlefakes.FakeVerifier{}
			v.BuildSigstoreVerifierReturns(nil, errors.New("building verifier failed"))
			return &v
		}},
		{"BuildSigstoreVeRunVerificationrifier-fails", true, func(t *testing.T) bundle.Verifier {
			t.Helper()
			v := bundlefakes.FakeVerifier{}
			v.RunVerificationReturns(nil, errors.New("verifying failed"))
			return &v
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sut := Verifier{
				Options:         options.DefaultVerifier,
				bundleVerifiers: []bundle.Verifier{tt.getVerifier(t)},
			}
			_, err := sut.VerifyParsedBundle(nil)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
