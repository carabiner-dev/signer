// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

// fakeSource implements x509svid.Source for tests.
type fakeSource struct {
	svid *x509svid.SVID
	err  error
}

func (f *fakeSource) GetX509SVID() (*x509svid.SVID, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.svid, nil
}

// mintTestSVID creates a self-signed ECDSA-P256 SVID under the given trust
// domain (defaults to "example.org"), with SPIFFE path "/workload". Good
// enough for unit tests — the chain doesn't go back to any real trust bundle.
func mintTestSVID(t *testing.T, td string) *x509svid.SVID {
	t.Helper()

	if td == "" {
		td = "example.org"
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	id := spiffeid.RequireFromPath(spiffeid.RequireTrustDomainFromString(td), "/workload")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-svid"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{id.URL()},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{cert},
		PrivateKey:   key,
	}
}

func TestCredentialProviderLeafOnly(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "")

	p := &CredentialProvider{Source: &fakeSource{svid: svid}}
	require.NoError(t, p.Prepare(context.Background()))

	kp := p.Keypair()
	require.NotNil(t, kp)

	cp, opts := p.CertificateProvider()
	require.NotNil(t, cp)
	require.Nil(t, opts)

	certDER, err := cp.GetCertificate(context.Background(), kp, nil)
	require.NoError(t, err)
	require.Equal(t, svid.Certificates[0].Raw, certDER)
}

func TestPrepareFailsWhenSourceErrors(t *testing.T) {
	t.Parallel()
	p := &CredentialProvider{Source: &fakeSource{err: errors.New("no svid available")}}
	err := p.Prepare(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "fetching initial svid")
}

func TestPrepareRejectsWrongTrustDomain(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "other.example")
	expected := spiffeid.RequireTrustDomainFromString("example.org")

	p := &CredentialProvider{
		Options: Options{ExpectedTrustDomain: expected},
		Source:  &fakeSource{svid: svid},
	}
	err := p.Prepare(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match expected")
}

func TestPrepareAcceptsMatchingTrustDomain(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "")

	p := &CredentialProvider{
		Options: Options{ExpectedTrustDomain: spiffeid.RequireTrustDomainFromString("example.org")},
		Source:  &fakeSource{svid: svid},
	}
	require.NoError(t, p.Prepare(context.Background()))
}

func TestPrepareIsIdempotent(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "")

	p := &CredentialProvider{Source: &fakeSource{svid: svid}}
	require.NoError(t, p.Prepare(context.Background()))
	require.NoError(t, p.Prepare(context.Background()))
}

func TestSignDataVerifiesAgainstSVIDPublicKey(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "")
	kp := &svidKeypair{source: &fakeSource{svid: svid}}

	payload := []byte("some payload bytes")
	sig, digest, err := kp.SignData(context.Background(), payload)
	require.NoError(t, err)

	pub, ok := svid.Certificates[0].PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "test svid should have ECDSA public key")
	require.True(t, ecdsa.VerifyASN1(pub, digest, sig),
		"signature should verify against the SVID public key")
}

func TestGetHintStableForSameSVID(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "")
	kp := &svidKeypair{source: &fakeSource{svid: svid}}

	h1 := kp.GetHint()
	h2 := kp.GetHint()
	require.Equal(t, h1, h2)
	require.NotEmpty(t, h1)
}

func TestKeypairAccessorsForECDSAP256(t *testing.T) {
	t.Parallel()
	svid := mintTestSVID(t, "")
	kp := &svidKeypair{source: &fakeSource{svid: svid}}

	require.Equal(t, "ECDSA", kp.GetKeyAlgorithm())

	pem, err := kp.GetPublicKeyPem()
	require.NoError(t, err)
	require.Contains(t, pem, "BEGIN PUBLIC KEY")
	require.Contains(t, pem, "END PUBLIC KEY")

	require.NotNil(t, kp.GetPublicKey())
}
