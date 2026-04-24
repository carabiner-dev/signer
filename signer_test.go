// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/bundle/bundlefakes"
	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/dsse/dssefakes"
	"github.com/carabiner-dev/signer/options"
)

// testHarness builds a Signer wired with fake collaborators that callers can
// tweak before running a sign call.
type testHarness struct {
	bundleSigner *bundlefakes.FakeSigner
	credentials  *bundlefakes.FakeCredentialProvider
}

func newTestHarness() *testHarness {
	return &testHarness{
		bundleSigner: &bundlefakes.FakeSigner{},
		credentials:  &bundlefakes.FakeCredentialProvider{},
	}
}

func (h *testHarness) signer(t *testing.T) *Signer {
	t.Helper()
	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())
	return &Signer{
		Options:      opts,
		Credentials:  h.credentials,
		bundleSigner: h.bundleSigner,
	}
}

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
	for _, tt := range []struct {
		name    string
		mustErr bool
		setup   func(*testHarness)
	}{
		{"success", false, func(h *testHarness) {}},
		{"VerifyAttestationContent-fails", true, func(h *testHarness) {
			h.bundleSigner.VerifyAttestationContentReturns(errors.New("invalid attesatation"))
		}},
		{"Credentials-Prepare-fails", true, func(h *testHarness) {
			h.credentials.PrepareReturns(errors.New("preparing credentials failed"))
		}},
		{"BuildBundleOptions-fails", true, func(h *testHarness) {
			h.bundleSigner.BuildBundleOptionsReturns(nil, errors.New("getting signer options fails"))
		}},
		{"SignBundle-fails", true, func(h *testHarness) {
			h.bundleSigner.SignBundleReturns(nil, errors.New("signing bundle failed"))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHarness()
			tt.setup(h)
			sut := h.signer(t)
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

	for _, tt := range []struct {
		name    string
		mustErr bool
		setup   func(*testHarness)
	}{
		{"success", false, func(h *testHarness) {}},
		{"Credentials-Prepare-fails", true, func(h *testHarness) {
			h.credentials.PrepareReturns(errors.New("preparing credentials failed"))
		}},
		{"BuildBundleOptions-fails", true, func(h *testHarness) {
			h.bundleSigner.BuildBundleOptionsReturns(nil, errors.New("getting signer options fails"))
		}},
		{"SignBundle-fails", true, func(h *testHarness) {
			h.bundleSigner.SignBundleReturns(nil, errors.New("signing bundle failed"))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHarness()
			tt.setup(h)
			sut := h.signer(t)
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

	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	fakeBundleSigner := &bundlefakes.FakeSigner{}
	fakeCredentials := &bundlefakes.FakeCredentialProvider{}
	s := &Signer{
		Options:      opts,
		Credentials:  fakeCredentials,
		bundleSigner: fakeBundleSigner,
	}

	bndl, err := s.SignStatement(statementData)
	require.NoError(t, err)
	require.NotNil(t, bndl)

	// Verify the mock signer was called with the expected flow
	require.Equal(t, 1, fakeBundleSigner.VerifyAttestationContentCallCount())
	require.Equal(t, 1, fakeBundleSigner.WrapDataCallCount())
	require.Equal(t, 1, fakeCredentials.PrepareCallCount())
	require.Equal(t, 1, fakeBundleSigner.BuildBundleOptionsCallCount())
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

// TestSigningStateReuse verifies that calling SignStatement multiple times on
// the same Signer reuses the prepared credentials and cached bundle options
// instead of repeating credential preparation and service discovery.
func TestSigningStateReuse(t *testing.T) {
	t.Parallel()

	statementData, err := os.ReadFile("bundle/testdata/statement.json")
	require.NoError(t, err)

	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	fakeBundleSigner := &bundlefakes.FakeSigner{}
	fakeCredentials := &bundlefakes.FakeCredentialProvider{}
	s := &Signer{
		Options:      opts,
		Credentials:  fakeCredentials,
		bundleSigner: fakeBundleSigner,
	}

	// Sign three statements with the same signer
	for i := range 3 {
		bndl, err := s.SignStatement(statementData)
		require.NoError(t, err, "signing attempt %d", i+1)
		require.NotNil(t, bndl)
	}

	// Content verification and wrapping happen for every call
	require.Equal(t, 3, fakeBundleSigner.VerifyAttestationContentCallCount())
	require.Equal(t, 3, fakeBundleSigner.WrapDataCallCount())
	require.Equal(t, 3, fakeBundleSigner.SignBundleCallCount())

	// But credential preparation and bundle options wiring only happen once
	require.Equal(t, 1, fakeCredentials.PrepareCallCount())
	require.Equal(t, 1, fakeBundleSigner.BuildBundleOptionsCallCount())
}

// mintTestCert mints a self-signed ECDSA cert for tests that need a
// DER-encoded x509.Certificate.
func mintTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestSignStatementAttachesIntermediates exercises the bundle post-processing
// path: when the credential provider returns intermediates, the outer Signer
// rewrites the bundle's VerificationMaterial from Certificate (leaf-only) to
// X509CertificateChain carrying [leaf, ...intermediates].
func TestSignStatementAttachesIntermediates(t *testing.T) {
	t.Parallel()

	statementData, err := os.ReadFile("bundle/testdata/statement.json")
	require.NoError(t, err)

	leaf := mintTestCert(t, "leaf")
	intermediate := mintTestCert(t, "intermediate")

	// Fake SignBundle returns a leaf-only bundle — mirrors what sigstore-go's
	// sign.Bundle produces via VerificationMaterial_Certificate.
	fakeBundleSigner := &bundlefakes.FakeSigner{}
	fakeBundleSigner.SignBundleReturns(&protobundle.Bundle{
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw},
			},
		},
	}, nil)

	fakeCredentials := &bundlefakes.FakeCredentialProvider{}
	fakeCredentials.IntermediatesReturns([]*x509.Certificate{intermediate})

	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	s := &Signer{
		Options:      opts,
		Credentials:  fakeCredentials,
		bundleSigner: fakeBundleSigner,
	}

	bndl, err := s.SignStatement(statementData)
	require.NoError(t, err)
	require.NotNil(t, bndl)

	chainContent, ok := bndl.GetVerificationMaterial().GetContent().(*protobundle.VerificationMaterial_X509CertificateChain)
	require.True(t, ok, "expected X509CertificateChain content, got %T", bndl.GetVerificationMaterial().GetContent())
	chainCerts := chainContent.X509CertificateChain.GetCertificates()
	require.Len(t, chainCerts, 2)
	require.Equal(t, leaf.Raw, chainCerts[0].GetRawBytes())
	require.Equal(t, intermediate.Raw, chainCerts[1].GetRawBytes())
}

// TestSignStatementLeavesLeafOnlyBundleUntouched verifies the sigstore path:
// when the credential provider reports no intermediates, the bundle's
// leaf-only VerificationMaterial is preserved.
func TestSignStatementLeavesLeafOnlyBundleUntouched(t *testing.T) {
	t.Parallel()

	statementData, err := os.ReadFile("bundle/testdata/statement.json")
	require.NoError(t, err)

	leaf := mintTestCert(t, "leaf")

	fakeBundleSigner := &bundlefakes.FakeSigner{}
	fakeBundleSigner.SignBundleReturns(&protobundle.Bundle{
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw},
			},
		},
	}, nil)

	fakeCredentials := &bundlefakes.FakeCredentialProvider{}
	// Intermediates defaults to returning nil.

	opts := options.DefaultSigner
	require.NoError(t, opts.Validate())

	s := &Signer{
		Options:      opts,
		Credentials:  fakeCredentials,
		bundleSigner: fakeBundleSigner,
	}

	bndl, err := s.SignStatement(statementData)
	require.NoError(t, err)

	leafContent, ok := bndl.GetVerificationMaterial().GetContent().(*protobundle.VerificationMaterial_Certificate)
	require.True(t, ok, "expected Certificate content, got %T", bndl.GetVerificationMaterial().GetContent())
	require.Equal(t, leaf.Raw, leafContent.Certificate.GetRawBytes())
}

// Compile-time check: bundle.CredentialProvider and bundle.Signer are
// satisfied by the fakes used in the tests above.
var (
	_ bundle.CredentialProvider = (*bundlefakes.FakeCredentialProvider)(nil)
	_ bundle.Signer             = (*bundlefakes.FakeSigner)(nil)
)
