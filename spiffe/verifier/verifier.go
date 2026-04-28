// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package verifier validates SPIFFE-signed bundles against a pinned
// SPIRE trust root and enforces SPIFFE identity matchers on the SVID
// leaf. It lives in its own subpackage (sibling to the sign-side
// signer/spiffe credential provider) so that it can import
// signer/options without promoting the sign-side package into the
// same cycle — allowing options/spiffe_set.go to import
// signer/spiffe cleanly.
package verifier

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
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
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

	// TSATrustedMaterial, when non-nil, is used to validate any RFC 3161
	// timestamps embedded in the bundle. The earliest verified timestamp
	// time then drives SVID chain validation (CurrentTime in
	// x509.VerifyOptions), letting bundles outlive the SVID's TTL.
	// When the bundle has timestamps but TSATrustedMaterial is nil, or
	// the validation produces no verified timestamps, chain validation
	// falls back to time.Now() — current behavior.
	TSATrustedMaterial root.TrustedMaterial
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

// SetTSATrustedMaterial wires a TrustedMaterial used to validate any
// RFC 3161 timestamps in incoming bundles. Typically called by the
// outer signer.NewVerifier after constructing the SPIFFE verifier
// from SPIFFE-side options, since the trust material lives in the
// sigstore-roots configuration which the SPIFFE options don't carry.
// Nil clears the wiring and reverts the verifier to time.Now()-based
// chain validation.
func (v *Verifier) SetTSATrustedMaterial(tm root.TrustedMaterial) {
	v.opts.TSATrustedMaterial = tm
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
		re, err := regexp.Compile(anchoredRegex(opts.ExpectedPathRegex))
		if err != nil {
			return nil, fmt.Errorf("compiling spiffe path regex: %w", err)
		}
		vOpts.ExpectedPathRegex = re
	}
	return NewVerifier(vOpts)
}

// anchoredRegex wraps a user-supplied pattern so it must match the full
// input end-to-end. Unanchored patterns passed to regexp.MatchString match
// on any substring, which lets a policy regex meant to pin a specific
// SPIFFE path match via prefix/substring collision.
func anchoredRegex(pattern string) string {
	return "^(?:" + pattern + ")$"
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
//
// If the bundle carries RFC 3161 timestamps and TSATrustedMaterial is
// configured on the verifier, the earliest verified timestamp's time is
// used as x509.VerifyOptions.CurrentTime so SVID-signed bundles remain
// verifiable past the SVID's TTL. With timestamps but no
// TSATrustedMaterial, chain validation falls back to time.Now().
func (v *Verifier) Verify(opts *options.Verification, bndl *sbundle.Bundle) (*verify.VerificationResult, error) {
	effective, err := v.effectiveOptions(opts)
	if err != nil {
		return nil, err
	}

	chain, err := extractChain(bndl)
	if err != nil {
		return nil, fmt.Errorf("extracting x509 chain from bundle: %w", err)
	}
	leaf := chain[0]

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	chainTime, verifiedTimestamps, err := chainValidationTime(bndl, effective.TSATrustedMaterial)
	if err != nil {
		return nil, err
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         effective.TrustRoots,
		Intermediates: intermediates,
		// Accept any EKU — SPIRE SVIDs typically don't set a code-signing EKU.
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: chainTime, // zero falls back to time.Now() inside x509.Verify
	}); err != nil {
		return nil, fmt.Errorf("chain verification failed: %w", err)
	}

	id, err := extractSpiffeID(leaf)
	if err != nil {
		return nil, fmt.Errorf("extracting spiffe id: %w", err)
	}
	if err := matchIdentity(effective, id); err != nil {
		return nil, err
	}

	if err := verifyDSSESignature(bndl, leaf.PublicKey); err != nil {
		return nil, fmt.Errorf("verifying dsse signature: %w", err)
	}

	result := buildResult(bndl, leaf, id)
	for _, ts := range verifiedTimestamps {
		result.VerifiedTimestamps = append(result.VerifiedTimestamps,
			verify.TimestampVerificationResult{
				Type:      "TimestampAuthority",
				URI:       ts.URI,
				Timestamp: ts.Time,
			})
	}
	return result, nil
}

// effectiveOptions overlays per-call *options.Verification on top of the
// Verifier's construction-time VerifierOptions. Per-call fields override
// construction-time values when set; unset per-call fields fall back. This
// lets callers pin identity per-invocation via options.WithExpectedSpiffeID
// and friends without mutating shared verifier state.
func (v *Verifier) effectiveOptions(opts *options.Verification) (VerifierOptions, error) {
	eff := v.opts
	if opts == nil {
		return eff, nil
	}
	sv := opts.SpiffeVerification

	if len(sv.TrustRootsPEM) > 0 || sv.TrustRootsPath != "" {
		pool, err := loadTrustRoots(&sv)
		if err != nil {
			return eff, fmt.Errorf("per-call spiffe trust roots: %w", err)
		}
		eff.TrustRoots = pool
	}
	if sv.ExpectedTrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(sv.ExpectedTrustDomain)
		if err != nil {
			return eff, fmt.Errorf("parsing per-call spiffe trust domain: %w", err)
		}
		eff.ExpectedTrustDomain = td
	}
	if sv.ExpectedPath != "" && sv.ExpectedPathRegex != "" {
		return eff, errors.New("per-call spiffe options: ExpectedPath and ExpectedPathRegex are mutually exclusive")
	}
	if sv.ExpectedPath != "" {
		eff.ExpectedPath = sv.ExpectedPath
		eff.ExpectedPathRegex = nil
	}
	if sv.ExpectedPathRegex != "" {
		re, err := regexp.Compile(anchoredRegex(sv.ExpectedPathRegex))
		if err != nil {
			return eff, fmt.Errorf("compiling per-call spiffe path regex: %w", err)
		}
		eff.ExpectedPathRegex = re
		eff.ExpectedPath = ""
	}
	return eff, nil
}

// chainValidationTime returns the time to use for SVID chain
// validation along with any RFC 3161 timestamps that verified against
// tm. If the bundle carries timestamps and tm is non-nil, the
// timestamps are validated against tm and the earliest verified time
// is returned. Bundle without timestamps, or with timestamps but no
// tm, returns the zero time so x509.Verify falls back to time.Now().
// When the bundle has timestamps but every timestamp fails validation
// against tm, an error is returned — silently falling back would be
// a security bypass.
func chainValidationTime(bndl *sbundle.Bundle, tm root.TrustedMaterial) (time.Time, []*root.Timestamp, error) {
	signedTimestamps, err := bndl.Timestamps()
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("reading bundle timestamps: %w", err)
	}
	if len(signedTimestamps) == 0 {
		return time.Time{}, nil, nil
	}
	if tm == nil {
		// Bundle is timestamped but verifier has no TSA roots wired in.
		// Fall through to time.Now() — current behavior.
		return time.Time{}, nil, nil
	}
	verified, _, err := verify.VerifySignedTimestamp(bndl, tm)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("validating bundle timestamps: %w", err)
	}
	if len(verified) == 0 {
		return time.Time{}, nil, errors.New("bundle has timestamps but none verified against the TSA trust material")
	}
	earliest := verified[0].Time
	for _, ts := range verified[1:] {
		if ts.Time.Before(earliest) {
			earliest = ts.Time
		}
	}
	return earliest, verified, nil
}

func matchIdentity(opts VerifierOptions, id spiffeid.ID) error {
	if !opts.ExpectedTrustDomain.IsZero() && id.TrustDomain() != opts.ExpectedTrustDomain {
		return fmt.Errorf(
			"spiffe id trust domain %q does not match expected %q",
			id.TrustDomain(), opts.ExpectedTrustDomain,
		)
	}
	if opts.ExpectedPath != "" && id.Path() != opts.ExpectedPath {
		return fmt.Errorf("spiffe id path %q does not match expected %q", id.Path(), opts.ExpectedPath)
	}
	if opts.ExpectedPathRegex != nil && !opts.ExpectedPathRegex.MatchString(id.Path()) {
		return fmt.Errorf(
			"spiffe id path %q does not match regex %q",
			id.Path(), opts.ExpectedPathRegex,
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

// buildResult constructs a best-effort VerificationResult. Populates:
//   - MediaType (via NewVerificationResult)
//   - Statement  — when the DSSE payload is a valid in-toto Statement
//   - Signature.Certificate — a SummarizeCertificate of the SVID leaf. The
//     Summary's SubjectAlternativeName will carry the SPIFFE ID since it's
//     the leaf's first URI SAN.
//   - VerifiedIdentity.SubjectAlternativeName — the SPIFFE ID. Lets callers
//     read the verified signer using the same sigstore-go result fields the
//     sigstore path populates.
//
// Transparency-log and TSA fields are intentionally left empty; SPIFFE
// signatures don't produce them.
func buildResult(bndl *sbundle.Bundle, leaf *x509.Certificate, id spiffeid.ID) *verify.VerificationResult {
	result := verify.NewVerificationResult()

	// Attach the leaf summary and the verified SPIFFE ID. Populating both
	// keeps parity with how sigstore-go's own verifier fills these fields
	// for Fulcio signatures.
	if summary, err := certificate.SummarizeCertificate(leaf); err == nil {
		result.Signature = &verify.SignatureVerificationResult{
			Certificate: &summary,
		}
	}
	result.VerifiedIdentity = &verify.CertificateIdentity{
		SubjectAlternativeName: verify.SubjectAlternativeNameMatcher{
			SubjectAlternativeName: id.String(),
		},
	}

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
