// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"regexp"

	intoto "github.com/in-toto/attestation/go/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/options"
)

// VerifierOptions configures a SPIFFE Verifier.
type VerifierOptions struct {
	// TrustRoots is the certificate pool used to validate the SVID chain.
	// Required.
	TrustRoots *x509.CertPool

	// ExpectedTrustDomain, when non-zero, asserts the SVID's trust domain.
	ExpectedTrustDomain spiffeid.TrustDomain

	// ExpectedPath, when non-empty, requires an exact match on the SVID's
	// SPIFFE path component.
	ExpectedPath string

	// ExpectedPathRegex, when non-nil, must match the SVID's SPIFFE path.
	// Mutually exclusive with ExpectedPath.
	ExpectedPathRegex *regexp.Regexp
}

// Verifier validates SPIFFE-signed bundles against a pinned SPIRE trust root
// and enforces SPIFFE identity matchers on the SVID leaf.
type Verifier struct {
	opts VerifierOptions
}

// NewVerifier creates a SPIFFE Verifier. Returns an error if the trust roots
// are missing or the identity matchers are ambiguous.
func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	if opts.TrustRoots == nil {
		return nil, errors.New("spiffe verifier requires at least one trust root")
	}
	if opts.ExpectedPath != "" && opts.ExpectedPathRegex != nil {
		return nil, errors.New("spiffe verifier: ExpectedPath and ExpectedPathRegex are mutually exclusive")
	}
	return &Verifier{opts: opts}, nil
}

// NewVerifierFromOptions builds a Verifier from the verification options
// struct carried in the top-level options.Verification. Loads trust roots
// from inline PEM or a file as configured.
func NewVerifierFromOptions(opts *options.SpiffeVerification) (*Verifier, error) {
	pool, err := loadTrustRoots(opts)
	if err != nil {
		return nil, fmt.Errorf("loading spiffe trust roots: %w", err)
	}
	vOpts := VerifierOptions{TrustRoots: pool, ExpectedPath: opts.ExpectedPath}
	if opts.ExpectedTrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(opts.ExpectedTrustDomain)
		if err != nil {
			return nil, fmt.Errorf("parsing expected trust domain: %w", err)
		}
		vOpts.ExpectedTrustDomain = td
	}
	if opts.ExpectedPathRegex != "" {
		re, err := regexp.Compile(opts.ExpectedPathRegex)
		if err != nil {
			return nil, fmt.Errorf("compiling spiffe path regex: %w", err)
		}
		vOpts.ExpectedPathRegex = re
	}
	return NewVerifier(vOpts)
}

func loadTrustRoots(opts *options.SpiffeVerification) (*x509.CertPool, error) {
	var data []byte
	if opts.TrustRootsPath != "" {
		b, err := os.ReadFile(opts.TrustRootsPath)
		if err != nil {
			return nil, fmt.Errorf("reading trust roots file: %w", err)
		}
		data = append(data, b...)
	}
	if len(opts.TrustRootsPEM) > 0 {
		data = append(data, opts.TrustRootsPEM...)
	}
	if len(data) == 0 {
		return nil, errors.New("no trust roots configured")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("no valid PEM certificates found in trust roots")
	}
	return pool, nil
}

// Verify validates the SVID chain in the bundle against the pinned trust
// roots, enforces the SPIFFE identity matchers, and verifies the DSSE
// envelope signature against the leaf public key. Returns a best-effort
// *verify.VerificationResult on success (sigstore-specific fields like
// transparency-log entries are left zero; SPIFFE signatures don't produce
// them).
func (v *Verifier) Verify(_ *options.Verification, bndl *sbundle.Bundle) (*verify.VerificationResult, error) {
	chain, err := extractChain(bndl)
	if err != nil {
		return nil, fmt.Errorf("extracting x509 chain from bundle: %w", err)
	}
	leaf := chain[0]

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.opts.TrustRoots,
		Intermediates: intermediates,
		// Accept any EKU — SPIRE SVIDs typically don't set a code-signing EKU.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("chain verification failed: %w", err)
	}

	id, err := extractSpiffeID(leaf)
	if err != nil {
		return nil, fmt.Errorf("extracting spiffe id: %w", err)
	}
	if err := v.matchIdentity(id); err != nil {
		return nil, err
	}

	if err := verifyDSSESignature(bndl, leaf.PublicKey); err != nil {
		return nil, fmt.Errorf("verifying dsse signature: %w", err)
	}

	return buildResult(bndl), nil
}

func (v *Verifier) matchIdentity(id spiffeid.ID) error {
	if !v.opts.ExpectedTrustDomain.IsZero() && id.TrustDomain() != v.opts.ExpectedTrustDomain {
		return fmt.Errorf(
			"spiffe id trust domain %q does not match expected %q",
			id.TrustDomain(), v.opts.ExpectedTrustDomain,
		)
	}
	if v.opts.ExpectedPath != "" && id.Path() != v.opts.ExpectedPath {
		return fmt.Errorf("spiffe id path %q does not match expected %q", id.Path(), v.opts.ExpectedPath)
	}
	if v.opts.ExpectedPathRegex != nil && !v.opts.ExpectedPathRegex.MatchString(id.Path()) {
		return fmt.Errorf(
			"spiffe id path %q does not match regex %q",
			id.Path(), v.opts.ExpectedPathRegex,
		)
	}
	return nil
}

// extractChain pulls the X.509 chain out of the bundle's VerificationMaterial.
// Accepts either an X509CertificateChain (leaf + intermediates) or a single
// Certificate (leaf only).
func extractChain(bndl *sbundle.Bundle) ([]*x509.Certificate, error) {
	vm := bndl.GetVerificationMaterial()
	if vm == nil {
		return nil, errors.New("bundle has no verification material")
	}
	if chain := vm.GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		out := make([]*x509.Certificate, 0, len(chain.GetCertificates()))
		for i, c := range chain.GetCertificates() {
			cert, err := x509.ParseCertificate(c.GetRawBytes())
			if err != nil {
				return nil, fmt.Errorf("parsing certificate %d: %w", i, err)
			}
			out = append(out, cert)
		}
		return out, nil
	}
	if leaf := vm.GetCertificate(); leaf != nil {
		cert, err := x509.ParseCertificate(leaf.GetRawBytes())
		if err != nil {
			return nil, fmt.Errorf("parsing leaf certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil
	}
	return nil, errors.New("bundle verification material has no certificate")
}

// extractSpiffeID pulls the first spiffe:// URI SAN from the leaf.
func extractSpiffeID(leaf *x509.Certificate) (spiffeid.ID, error) {
	for _, uri := range leaf.URIs {
		if uri.Scheme == "spiffe" {
			return spiffeid.FromURI(uri)
		}
	}
	return spiffeid.ID{}, errors.New("leaf certificate has no spiffe:// URI SAN")
}

// verifyDSSESignature checks that at least one signature in the bundle's DSSE
// envelope verifies against the given public key.
func verifyDSSESignature(bndl *sbundle.Bundle, pub crypto.PublicKey) error {
	env := bndl.GetDsseEnvelope()
	if env == nil {
		return errors.New("bundle has no DSSE envelope")
	}
	sigs := env.GetSignatures()
	if len(sigs) == 0 {
		return errors.New("DSSE envelope has no signatures")
	}

	pae := dsse.PAEEncode(env)

	var lastErr error
	for _, sig := range sigs {
		if err := verifyWithKey(pub, pae, sig.GetSig()); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("no signature verified against leaf key: %w", lastErr)
}

// verifyWithKey dispatches signature verification on the leaf public key
// type. Mirrors the algorithm choices made by spiffe.svidKeypair.SignData.
func verifyWithKey(pub crypto.PublicKey, msg, sig []byte) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return errors.New("ecdsa verification failed")
		}
		return nil
	case *rsa.PublicKey:
		digest := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig)
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return errors.New("ed25519 verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported leaf public key type: %T", pub)
	}
}

// buildResult constructs a best-effort VerificationResult. Tries to parse the
// DSSE payload as an in-toto Statement and populate it; leaves timestamps and
// transparency-log fields empty (SPIFFE signatures don't produce them).
func buildResult(bndl *sbundle.Bundle) *verify.VerificationResult {
	result := verify.NewVerificationResult()
	env := bndl.GetDsseEnvelope()
	if env == nil || len(env.GetPayload()) == 0 {
		return result
	}
	st := &intoto.Statement{}
	if err := protojson.Unmarshal(env.GetPayload(), st); err == nil {
		result.Statement = st
	}
	return result
}
