// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/stretchr/testify/require"
)

// fakeCA issues short-lived certificates over a caller-provided public key,
// standing in for the Fulcio flow so CertifiedKey can be exercised hermetically.
type fakeCA struct {
	rootCert  *x509.Certificate
	interKey  *ecdsa.PrivateKey
	interCert *x509.Certificate
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	rootCert := signCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "fake-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	interCert := signCert(t, interTmpl, rootCert, &interKey.PublicKey, rootKey)

	return &fakeCA{rootCert: rootCert, interKey: interKey, interCert: interCert}
}

// issueLeaf signs a code-signing leaf over pub using the intermediate key.
func (ca *fakeCA) issueLeaf(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "signer@example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	return signCert(t, leafTmpl, ca.interCert, pub, ca.interKey)
}

func signCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// fakeChainProvider implements sign.CertificateProvider and
// sign.CertificateChainProvider, returning [leaf, intermediate].
type fakeChainProvider struct {
	t  *testing.T
	ca *fakeCA
}

func (f *fakeChainProvider) GetCertificate(_ context.Context, kp sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	return f.ca.issueLeaf(f.t, kp.GetPublicKey()).Raw, nil
}

func (f *fakeChainProvider) GetCertificateChain(_ context.Context, kp sign.Keypair, _ *sign.CertificateProviderOptions) ([][]byte, error) {
	leaf := f.ca.issueLeaf(f.t, kp.GetPublicKey())
	return [][]byte{leaf.Raw, f.ca.interCert.Raw}, nil
}

// fakeLeafProvider implements only sign.CertificateProvider (like the real
// Fulcio provider), returning just the leaf.
type fakeLeafProvider struct {
	t  *testing.T
	ca *fakeCA
}

func (f *fakeLeafProvider) GetCertificate(_ context.Context, kp sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	return f.ca.issueLeaf(f.t, kp.GetPublicKey()).Raw, nil
}

// preparedProvider builds a CredentialProvider that is already prepared so
// CertifiedKey skips the network-bound Prepare and uses the injected cp.
func preparedProvider(cp sign.CertificateProvider) *CredentialProvider {
	return &CredentialProvider{
		Instance: &Instance{},
		Token:    &oauthflow.OIDCIDToken{RawString: "fake-token"},
		cp:       cp,
		prepared: true,
	}
}

func TestCertifiedKeyWithChainProvider(t *testing.T) {
	t.Parallel()
	ca := newFakeCA(t)
	p := preparedProvider(&fakeChainProvider{t: t, ca: ca})

	leaf, chain, key, err := p.CertifiedKey(t.Context())
	require.NoError(t, err)
	require.NotNil(t, leaf)
	require.NotNil(t, key)

	// The returned certificate must bind to the returned private key.
	pub, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, pub.Equal(leaf.PublicKey))

	// The chain carries the intermediate (root excluded) and the leaf verifies
	// against it.
	require.Len(t, chain, 1)
	require.Equal(t, ca.interCert.Raw, chain[0].Raw)
	require.NoError(t, leaf.CheckSignatureFrom(chain[0]))
}

func TestCertifiedKeyLeafOnlyProvider(t *testing.T) {
	t.Parallel()
	ca := newFakeCA(t)
	p := preparedProvider(&fakeLeafProvider{t: t, ca: ca})

	leaf, chain, key, err := p.CertifiedKey(t.Context())
	require.NoError(t, err)
	require.NotNil(t, leaf)
	require.NotNil(t, key)

	// With no chain provider and no trusted root, the intermediate chain is
	// empty but the leaf still binds to the returned key.
	require.Empty(t, chain)
	pub, ok := key.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, pub.Equal(leaf.PublicKey))
}
