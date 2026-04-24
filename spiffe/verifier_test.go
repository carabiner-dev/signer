// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"regexp"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/options"
)

// withExpectedSpiffeID returns a *options.Verification populated with just
// the per-call SPIFFE identity matchers, analogous to what
// options.WithExpectedSpiffeID produces when called by a verifier's caller.
func withExpectedSpiffeID(td, path string) *options.Verification {
	return &options.Verification{
		SpiffeVerification: options.SpiffeVerification{
			ExpectedTrustDomain: td,
			ExpectedPath:        path,
		},
	}
}

// testPKI is a minimal CA + leaf pair used across verifier tests.
type testPKI struct {
	root    *x509.Certificate
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

// newTestPKI mints a self-signed root CA and a leaf cert whose URI SAN is
// spiffe://example.org<path>. Both use ECDSA-P256; the leaf is signed by
// the root.
func newTestPKI(t *testing.T, path string) *testPKI {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-spire-root"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	id := spiffeid.RequireFromPath(spiffeid.RequireTrustDomainFromString("example.org"), path)
	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "svid"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{id.URL()},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return &testPKI{root: root, leaf: leaf, leafKey: leafKey}
}

func (p *testPKI) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return pool
}

func (p *testPKI) rootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.root.Raw})
}

// makeSignedBundle constructs a sigstore Bundle containing a DSSE envelope
// signed with the leaf key and a chain carrying just the leaf.
func makeSignedBundle(t *testing.T, p *testPKI, payload []byte) *sbundle.Bundle {
	t.Helper()

	env := &sdsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     payload,
	}
	pae := dsse.PAEEncode(env)
	digest := sha256.Sum256(pae)
	sig, err := p.leafKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	env.Signatures = []*sdsse.Signature{{Sig: sig}}

	// v0.2 MediaType — v0.3+ forbids the X509CertificateChain variant.
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{
						{RawBytes: p.leaf.Raw},
					},
				},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: env},
	}
	b, err := sbundle.NewBundle(pb)
	require.NoError(t, err)
	return b
}

var testPayload = []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"test"}],"predicateType":"https://example.com/pred/v1","predicate":{}}`)

func TestVerifierSuccess(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{
		TrustRoots:          pki.rootPool(),
		ExpectedTrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		ExpectedPath:        "/workload",
	})
	require.NoError(t, err)

	result, err := v.Verify(nil, bndl)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verified identity carries the SPIFFE ID as its SAN.
	require.NotNil(t, result.VerifiedIdentity)
	require.Equal(t, "spiffe://example.org/workload",
		result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName)

	// Signature summary carries the leaf summary, including the SPIFFE ID.
	require.NotNil(t, result.Signature)
	require.NotNil(t, result.Signature.Certificate)
	require.Equal(t, "spiffe://example.org/workload",
		result.Signature.Certificate.SubjectAlternativeName)

	// The in-toto payload was parsed into result.Statement.
	require.NotNil(t, result.Statement)
}

func TestVerifierFromOptionsViaPEM(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifierFromOptions(&options.SpiffeVerification{
		TrustRootsPEM:       pki.rootPEM(),
		ExpectedTrustDomain: "example.org",
		ExpectedPath:        "/workload",
	})
	require.NoError(t, err)

	_, err = v.Verify(nil, bndl)
	require.NoError(t, err)
}

func TestVerifierRejectsWrongTrustDomain(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{
		TrustRoots:          pki.rootPool(),
		ExpectedTrustDomain: spiffeid.RequireTrustDomainFromString("other.example"),
	})
	require.NoError(t, err)

	_, err = v.Verify(nil, bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "trust domain")
}

func TestVerifierRejectsWrongPath(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{
		TrustRoots:   pki.rootPool(),
		ExpectedPath: "/other",
	})
	require.NoError(t, err)

	_, err = v.Verify(nil, bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "path")
}

func TestVerifierAcceptsPathRegex(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload/api")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{
		TrustRoots:        pki.rootPool(),
		ExpectedPathRegex: regexp.MustCompile(`^/workload/.*$`),
	})
	require.NoError(t, err)

	_, err = v.Verify(nil, bndl)
	require.NoError(t, err)
}

func TestVerifierRejectsUntrustedRoot(t *testing.T) {
	t.Parallel()
	signer := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, signer, testPayload)

	// Build a verifier pool from a *different* CA.
	other := newTestPKI(t, "/other")

	v, err := NewVerifier(VerifierOptions{TrustRoots: other.rootPool()})
	require.NoError(t, err)

	_, err = v.Verify(nil, bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain verification failed")
}

func TestVerifierRejectsTamperedPayload(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	// Tamper with the envelope's payload post-signing. The signature was
	// over the original payload, so PAE reconstruction will mismatch.
	env := bndl.GetDsseEnvelope()
	env.Payload = []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"EVIL"}]}`)

	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	_, err = v.Verify(nil, bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dsse signature")
}

func TestVerifierHonorsPerCallIdentityOptions(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	// Construction time: no identity matchers — only trust roots.
	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	// With matching per-call identity → success.
	_, err = v.Verify(withExpectedSpiffeID("example.org", "/workload"), bndl)
	require.NoError(t, err, "per-call matching identity should verify")

	// With per-call trust domain that doesn't match → reject.
	_, err = v.Verify(withExpectedSpiffeID("other.example", ""), bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "trust domain")

	// With per-call path that doesn't match → reject.
	_, err = v.Verify(withExpectedSpiffeID("example.org", "/other"), bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "path")
}

func TestVerifierPerCallOverridesConstructorIdentity(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	// Construction pins path /workload.
	v, err := NewVerifier(VerifierOptions{
		TrustRoots:   pki.rootPool(),
		ExpectedPath: "/workload",
	})
	require.NoError(t, err)

	// Baseline: construction-time matcher is honored when no per-call opts.
	_, err = v.Verify(nil, bndl)
	require.NoError(t, err)

	// Per-call path that disagrees with construction-time overrides it and rejects.
	_, err = v.Verify(withExpectedSpiffeID("", "/other"), bndl)
	require.Error(t, err, "per-call path override must be applied")
	require.Contains(t, err.Error(), "/other")
}

func TestVerifierPerCallRegexHonored(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload/api")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	opts := &options.Verification{
		SpiffeVerification: options.SpiffeVerification{
			ExpectedPathRegex: `^/workload/.*$`,
		},
	}
	_, err = v.Verify(opts, bndl)
	require.NoError(t, err)
}

func TestVerifierPerCallRejectsAmbiguousPathOptions(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	opts := &options.Verification{
		SpiffeVerification: options.SpiffeVerification{
			ExpectedPath:      "/workload",
			ExpectedPathRegex: `.*`,
		},
	}
	_, err = v.Verify(opts, bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestVerifierRegexAnchoredAgainstPrefixCollision(t *testing.T) {
	t.Parallel()
	// Signer's SVID path is /workload-stealer. A policy meant to pin /work
	// must NOT match this via prefix collision.
	pki := newTestPKI(t, "/workload-stealer")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	// Via per-call option — policy regex is unanchored user input.
	opts := &options.Verification{
		SpiffeVerification: options.SpiffeVerification{
			ExpectedPathRegex: `/work`,
		},
	}
	_, err = v.Verify(opts, bndl)
	require.Error(t, err, "regex /work must not match full path /workload-stealer")

	// Via NewVerifierFromOptions (construction-time) — same guarantee.
	v2, err := NewVerifierFromOptions(&options.SpiffeVerification{
		TrustRootsPEM:     pki.rootPEM(),
		ExpectedPathRegex: `/work`,
	})
	require.NoError(t, err)
	_, err = v2.Verify(nil, bndl)
	require.Error(t, err)
}

func TestVerifierPerCallRejectsInvalidRegex(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	opts := &options.Verification{
		SpiffeVerification: options.SpiffeVerification{
			ExpectedPathRegex: `[invalid`,
		},
	}
	_, err = v.Verify(opts, bndl)
	require.Error(t, err)
}

func TestVerifierPerCallRejectsInvalidTrustDomain(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "/workload")
	bndl := makeSignedBundle(t, pki, testPayload)

	v, err := NewVerifier(VerifierOptions{TrustRoots: pki.rootPool()})
	require.NoError(t, err)

	_, err = v.Verify(withExpectedSpiffeID("not a valid trust domain!!", ""), bndl)
	require.Error(t, err)
	require.Contains(t, err.Error(), "trust domain")
}

func TestNewVerifierRequiresTrustRoots(t *testing.T) {
	t.Parallel()
	_, err := NewVerifier(VerifierOptions{})
	require.Error(t, err)
}

func TestNewVerifierRejectsAmbiguousPathMatch(t *testing.T) {
	t.Parallel()
	pool := x509.NewCertPool()
	pool.AddCert(newTestPKI(t, "/workload").root)

	_, err := NewVerifier(VerifierOptions{
		TrustRoots:        pool,
		ExpectedPath:      "/a",
		ExpectedPathRegex: regexp.MustCompile(`.*`),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "mutually exclusive")
}

func TestNewVerifierFromOptionsRejectsInvalidPEM(t *testing.T) {
	t.Parallel()
	_, err := NewVerifierFromOptions(&options.SpiffeVerification{
		TrustRootsPEM: []byte("not a PEM block"),
	})
	require.Error(t, err)
}
