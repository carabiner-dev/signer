// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"os"
	"testing"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/bundle/bundlefakes"
	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/dsse/dssefakes"
	"github.com/carabiner-dev/signer/options"
)

func TestSignStatement(t *testing.T) {
	t.Parallel()

	attData := `{
  "predicateType": "https://example.com/my-predicate/v1",
  "predicate": { "something": "custom" },
  "type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    { "name": "MY-POLICY" }
  ]
}
`
	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	for _, tt := range []struct {
		name      string
		mustErr   bool
		getSigner func(t *testing.T) bundle.Signer
	}{
		{"success", false, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			return &signer
		}},
		{"VerifyAttestationContent-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.VerifyAttestationContentReturns(errors.New("invalid attesatation"))
			return &signer
		}},
		{"GetKeyPair-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.GetKeyPairReturns(nil, errors.New("failed creating keypair"))
			return &signer
		}},
		{"GetAmbientTokens-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.GetAmbientTokensReturns(errors.New("fetchin ambient tokens failed"))
			return &signer
		}},
		{"GetOidcToken-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.GetOidcTokenReturns(errors.New("getting oidc token fails"))
			return &signer
		}},
		{"BuildSigstoreSignerOptions-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.BuildSigstoreSignerOptionsReturns(nil, errors.New("getting signer options fails"))
			return &signer
		}},
		{"SignBundle-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.SignBundleReturns(nil, errors.New("signing bundle failed"))
			return &signer
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sut := &Signer{
				Options:      opts,
				bundleSigner: tt.getSigner(t),
			}
			res, err := sut.SignStatement([]byte(attData))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
		})
	}
}

func TestSignMessage(t *testing.T) {
	t.Parallel()

	testData := "this is my signed data"

	// Parse the roots
	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	for _, tt := range []struct {
		name      string
		mustErr   bool
		getSigner func(t *testing.T) bundle.Signer
	}{
		{"success", false, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			return &signer
		}},
		{"GetKeyPair-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.GetKeyPairReturns(nil, errors.New("failed creating keypair"))
			return &signer
		}},
		{"GetAmbientTokens-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.GetAmbientTokensReturns(errors.New("fetchin ambient tokens failed"))
			return &signer
		}},
		{"GetOidcToken-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.GetOidcTokenReturns(errors.New("getting oidc token fails"))
			return &signer
		}},
		{"BuildSigstoreSignerOptions-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.BuildSigstoreSignerOptionsReturns(nil, errors.New("getting signer options fails"))
			return &signer
		}},
		{"SignBundle-fails", true, func(t *testing.T) bundle.Signer {
			t.Helper()
			signer := bundlefakes.FakeSigner{}
			signer.SignBundleReturns(nil, errors.New("signing bundle failed"))
			return &signer
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sut := &Signer{
				Options:      opts,
				bundleSigner: tt.getSigner(t),
			}
			res, err := sut.SignMessage([]byte(testData))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
		})
	}
}

func TestSignEnvelope(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		mustErr   bool
		getSigner func(*testing.T) dsse.Signer
	}{
		{"success", false, func(t *testing.T) dsse.Signer {
			t.Helper()
			return &dssefakes.FakeSigner{}
		}},
		{"signing-fails", true, func(t *testing.T) dsse.Signer {
			t.Helper()
			s := &dssefakes.FakeSigner{}
			s.SignReturns(errors.New("error signing"))
			return s
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dsseSigner := tt.getSigner(t)

			signer := &Signer{
				dsseSigner: dsseSigner,
			}

			err := signer.SignEnvelope(&sdsse.Envelope{})
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSignStatementToDSSE(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		mustErr   bool
		getSigner func(*testing.T) dsse.Signer
	}{
		{"success", false, func(t *testing.T) dsse.Signer {
			t.Helper()
			return &dssefakes.FakeSigner{}
		}},
		{"wrap-payload-fails", true, func(t *testing.T) dsse.Signer {
			t.Helper()
			s := &dssefakes.FakeSigner{}
			s.WrapPayloadReturns(nil, errors.New("error signing"))
			return s
		}},
		{"signing-fails", true, func(t *testing.T) dsse.Signer {
			t.Helper()
			s := &dssefakes.FakeSigner{}
			s.SignReturns(errors.New("error signing"))
			return s
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dsseSigner := tt.getSigner(t)

			signer := &Signer{
				dsseSigner: dsseSigner,
			}

			_, err := signer.SignStatementToDSSE([]byte("test"))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestSignAndVerifyMocked exercises the full sign → verify flow using mocked
// sigstore interactions. This runs on all PRs including forks where real
// OIDC tokens are unavailable.
func TestSignAndVerifyMocked(t *testing.T) {
	t.Parallel()

	statementData, err := os.ReadFile("bundle/testdata/statement.json")
	require.NoError(t, err)

	// Set up a signer with a mocked bundle signer
	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	fakeBundleSigner := &bundlefakes.FakeSigner{}
	s := &Signer{
		Options:      opts,
		bundleSigner: fakeBundleSigner,
	}

	bndl, err := s.SignStatement(statementData)
	require.NoError(t, err)
	require.NotNil(t, bndl)

	// Verify the mock signer was called with the expected flow
	require.Equal(t, 1, fakeBundleSigner.VerifyAttestationContentCallCount())
	require.Equal(t, 1, fakeBundleSigner.WrapDataCallCount())
	require.Equal(t, 1, fakeBundleSigner.GetKeyPairCallCount())
	require.Equal(t, 1, fakeBundleSigner.GetAmbientTokensCallCount())
	require.Equal(t, 1, fakeBundleSigner.GetOidcTokenCallCount())
	require.Equal(t, 1, fakeBundleSigner.BuildSigstoreSignerOptionsCallCount())
	require.Equal(t, 1, fakeBundleSigner.SignBundleCallCount())

	// Verify using a mocked verifier that returns a successful result
	fakeVerifier := &bundlefakes.FakeVerifier{}
	fakeVerifier.VerifyReturns(&verify.VerificationResult{}, nil)
	v := Verifier{
		Options:        options.DefaultVerifier,
		bundleVerifier: fakeVerifier,
	}

	res, err := v.VerifyParsedBundle(bndl, options.WithSkipIdentityCheck(true))
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, 1, fakeVerifier.VerifyCallCount())
}
