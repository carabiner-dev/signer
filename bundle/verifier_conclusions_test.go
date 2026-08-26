// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
)

// fakeInstance is a VerifyCapable standing in for one sigstore instance.
type fakeInstance struct {
	res   *verify.VerificationResult
	err   error
	calls atomic.Int32
}

func (f *fakeInstance) Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error) {
	f.calls.Add(1)
	return f.res, f.err
}

func testBundle(t *testing.T) *bundle.Bundle {
	t.Helper()
	b, err := (&DefaultVerifier{}).OpenBundle("testdata/public-good.sigstore.json")
	require.NoError(t, err)
	return b
}

func skipIdentity() *options.Verification {
	return &options.Verification{SigstoreVerification: options.SigstoreVerification{SkipIdentityCheck: true}}
}

// spiffeBundle builds a bundle whose leaf certificate carries a spiffe://
// URI SAN, enough for isSpiffeBundle to route it to the SPIFFE verifier.
func spiffeBundle(t *testing.T) *bundle.Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/workload"}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return &bundle.Bundle{Bundle: &protobundle.Bundle{
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: der},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &sdsse.Envelope{
			PayloadType: "application/vnd.in-toto+json", Payload: []byte("{}"),
			Signatures: []*sdsse.Signature{{Sig: []byte("sig")}},
		}},
	}}
}

func TestVerifyConclusions(t *testing.T) {
	t.Parallel()

	good := verify.NewVerificationResult()
	failed := func(msg string) error { return api.VerificationFailedError(msg, errors.New("x")) }
	operational := errors.New("fetching trusted root: connection refused")

	for _, tc := range []struct {
		name      string
		instances []*fakeInstance
		bndl      func(t *testing.T) *bundle.Bundle
		wantRes   bool
		wantIs    error // sentinel the error must wrap; nil with wantRes=false means a plain error
		wantNotIs []error
	}{
		{
			name: "no instances is unverifiable",
			bndl: testBundle, wantIs: api.ErrUnverifiable,
			wantNotIs: []error{api.ErrVerificationFailed},
		},
		{
			name: "spiffe bundle without spiffe verifier is unverifiable",
			bndl: spiffeBundle, instances: []*fakeInstance{{res: good}},
			wantIs: api.ErrUnverifiable, wantNotIs: []error{api.ErrVerificationFailed},
		},
		{
			name: "one instance verifies",
			bndl: testBundle, instances: []*fakeInstance{{res: good}}, wantRes: true,
		},
		{
			name: "one fails, one verifies",
			bndl: testBundle, instances: []*fakeInstance{{err: failed("a")}, {res: good}}, wantRes: true,
		},
		{
			name: "every instance fails is a failed conclusion",
			bndl: testBundle, instances: []*fakeInstance{{err: failed("a")}, {err: failed("b")}},
			wantIs: api.ErrVerificationFailed, wantNotIs: []error{api.ErrUnverifiable},
		},
		{
			// Errors raised inside sigstore-go are conclusions: RunVerification
			// cannot tell a bad signature from a fetch failure there, so the
			// phase rule treats everything past the verifier call as checked.
			name: "error from inside the sigstore verifier is a conclusion",
			bndl: testBundle, instances: []*fakeInstance{{err: operational}},
			wantIs: api.ErrVerificationFailed, wantNotIs: []error{api.ErrUnverifiable},
		},
		{
			name: "instance returns nothing: nothing concluded",
			bndl: testBundle, instances: []*fakeInstance{{}},
			wantNotIs: []error{api.ErrVerificationFailed, api.ErrUnverifiable},
		},
		{
			// One instance concluded, the other could not run: the one that
			// could not run may have verified the bundle, so no conclusion.
			name: "one fails, one cannot run: nothing concluded",
			bndl: testBundle, instances: []*fakeInstance{{err: failed("a")}, {}},
			wantNotIs: []error{api.ErrVerificationFailed, api.ErrUnverifiable},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := &DefaultVerifier{}
			for _, inst := range tc.instances {
				v.Verifiers = append(v.Verifiers, inst)
			}

			res, err := v.Verify(skipIdentity(), tc.bndl(t))
			if tc.wantRes {
				require.NoError(t, err)
				assert.Same(t, good, res)
				return
			}
			require.Error(t, err)
			assert.Nil(t, res)
			if tc.wantIs != nil {
				require.ErrorIs(t, err, tc.wantIs)
			}
			for _, not := range tc.wantNotIs {
				require.NotErrorIs(t, err, not)
			}
		})
	}
}

// A failed conclusion across instances must keep every instance's reason.
func TestVerifyFailedConclusionKeepsCauses(t *testing.T) {
	t.Parallel()

	causeA, causeB := errors.New("cause-a"), errors.New("cause-b")
	v := &DefaultVerifier{Verifiers: []VerifyCapable{
		&fakeInstance{err: api.VerificationFailedError("instance a", causeA)},
		&fakeInstance{err: api.VerificationFailedError("instance b", causeB)},
	}}
	_, err := v.Verify(skipIdentity(), testBundle(t))
	require.ErrorIs(t, err, api.ErrVerificationFailed)
	require.ErrorIs(t, err, causeA)
	require.ErrorIs(t, err, causeB)
}

func TestRunVerificationConclusions(t *testing.T) {
	t.Parallel()

	good := verify.NewVerificationResult()
	sigstoreErr := errors.New("signature verification failed against policy")

	for _, tc := range []struct {
		name     string
		opts     *options.SigstoreVerification
		instance *fakeInstance
		bndl     func(t *testing.T) *bundle.Bundle
		wantRes  bool
		wantIs   error
		wantCall bool
	}{
		{
			name:     "verifies",
			opts:     &options.SigstoreVerification{SkipIdentityCheck: true},
			instance: &fakeInstance{res: good}, bndl: testBundle, wantRes: true, wantCall: true,
		},
		{
			name:     "sigstore verifier failure is a conclusion",
			opts:     &options.SigstoreVerification{SkipIdentityCheck: true},
			instance: &fakeInstance{err: sigstoreErr}, bndl: testBundle,
			wantIs: api.ErrVerificationFailed, wantCall: true,
		},
		{
			name:     "no identity policy is an error, not a conclusion",
			opts:     &options.SigstoreVerification{},
			instance: &fakeInstance{res: good}, bndl: testBundle,
		},
		{
			name:     "invalid artifact digest is an error, not a conclusion",
			opts:     &options.SigstoreVerification{SkipIdentityCheck: true, ArtifactDigest: "not-hex", ArtifactDigestAlgo: "sha256"},
			instance: &fakeInstance{res: good}, bndl: testBundle,
		},
		{
			name:     "envelope without payload is a conclusion",
			opts:     &options.SigstoreVerification{SkipIdentityCheck: true},
			instance: &fakeInstance{res: good},
			bndl: func(t *testing.T) *bundle.Bundle {
				t.Helper()
				return &bundle.Bundle{Bundle: &protobundle.Bundle{
					Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &sdsse.Envelope{PayloadType: "x"}},
				}}
			},
			wantIs: api.ErrVerificationFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res, err := (&DefaultVerifier{}).RunVerification(tc.opts, tc.instance, tc.bndl(t))
			assert.Equal(t, tc.wantCall, tc.instance.calls.Load() == 1, "sigstore verifier call expectation")
			if tc.wantRes {
				require.NoError(t, err)
				assert.Same(t, good, res)
				return
			}
			require.Error(t, err)
			assert.Nil(t, res)
			if tc.wantIs != nil {
				require.ErrorIs(t, err, tc.wantIs)
				if errors.Is(tc.wantIs, api.ErrVerificationFailed) && tc.instance.err != nil {
					require.ErrorIs(t, err, tc.instance.err, "cause must be preserved")
				}
			} else {
				require.NotErrorIs(t, err, api.ErrVerificationFailed)
				require.NotErrorIs(t, err, api.ErrUnverifiable)
			}
		})
	}
}
