// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/sha256"
	"fmt"
	"regexp"
)

type VerificationOptFunc func(*Verification) error

// Verification options are generic options that all the Verify* functions take
type Verification struct {
	SigstoreVerification
	KeyVerification
	SpiffeVerification
}

var DefaultVerification = Verification{}

// SpiffeVerification carries the trust material and identity matchers used
// when verifying a bundle signed against a SPIFFE/SPIRE trust domain.
type SpiffeVerification struct {
	// TrustRootsPEM is the inline PEM-encoded set of trust anchors used to
	// validate the SVID chain. At least one of TrustRootsPEM or
	// TrustRootsPath must be set for SPIFFE verification to be enabled.
	TrustRootsPEM []byte

	// TrustRootsPath is a filesystem path to a PEM-encoded trust anchor file.
	TrustRootsPath string

	// ExpectedTrustDomain, when non-empty, asserts the leaf SVID's trust
	// domain matches this string (e.g. "prod.example.org").
	ExpectedTrustDomain string

	// ExpectedPath, when non-empty, requires an exact match on the SVID's
	// SPIFFE path component (e.g. "/workload/api").
	ExpectedPath string

	// ExpectedPathRegex, when non-empty, requires a regex match on the SVID's
	// SPIFFE path component. Mutually exclusive with ExpectedPath.
	ExpectedPathRegex string

	// SkipSVIDValidity disables enforcement of the leaf SVID's
	// NotBefore/NotAfter dates during chain validation. Default
	// (false) is the safe behavior: the verifier checks the leaf is
	// time-valid against either an RFC 3161 timestamp from the bundle
	// or time.Now(). Set true to validate the chain using the leaf's
	// NotBefore as the reference time, so the chain is checked purely
	// on its cryptographic shape — useful for archival verification
	// of bundles whose SVIDs have rotated.
	SkipSVIDValidity bool
}

// WithExpectedIdentity serts the ExpectedIssuer and ExptectedSan options
// and unsets the regex alternatives
func WithExpectedIdentity(issuer, san string) VerificationOptFunc {
	return func(v *Verification) error {
		if issuer != "" {
			v.ExpectedIssuerRegex = ""
			v.ExpectedIssuer = issuer
		}

		if san != "" {
			v.ExpectedSanRegex = ""
			v.ExpectedSan = san
		}
		return nil
	}
}

// WithExpectedIdentityRegex sets the ExpectedIssuerRegex and ExptectedSanRegex
// options and unsets the non-regex alternatives.
func WithExpectedIdentityRegex(issuer, san string) VerificationOptFunc {
	return func(v *Verification) error {
		if issuer != "" {
			if _, err := regexp.Compile(issuer); err != nil {
				return fmt.Errorf("compiling issuer regex: %w", err)
			}
			v.ExpectedIssuerRegex = issuer
			v.ExpectedIssuer = ""
		}

		if san != "" {
			if _, err := regexp.Compile(san); err != nil {
				return fmt.Errorf("compiling SAN regex: %w", err)
			}
			v.ExpectedSanRegex = san
			v.ExpectedSan = ""
		}
		return nil
	}
}

// WithSkipIdentityCheck instructs the verifier to not check the signature
// identities, only the signed payload will be checked.
func WithSkipIdentityCheck(yesno bool) VerificationOptFunc {
	return func(v *Verification) error {
		v.SkipIdentityCheck = yesno
		return nil
	}
}

// WithSpiffeTrustRootsPEM sets the inline PEM-encoded SPIFFE trust anchors.
func WithSpiffeTrustRootsPEM(pem []byte) VerificationOptFunc {
	return func(v *Verification) error {
		v.TrustRootsPEM = pem
		return nil
	}
}

// WithSpiffeTrustRootsFile sets the filesystem path to a PEM-encoded SPIFFE
// trust anchor file.
func WithSpiffeTrustRootsFile(path string) VerificationOptFunc {
	return func(v *Verification) error {
		v.TrustRootsPath = path
		return nil
	}
}

// WithExpectedSpiffeID sets the expected trust domain and path for the SVID
// leaf. Either can be empty to skip that check; both together form an exact
// match (use WithExpectedSpiffeIDRegex for pattern matching on the path).
func WithExpectedSpiffeID(trustDomain, path string) VerificationOptFunc {
	return func(v *Verification) error {
		v.ExpectedTrustDomain = trustDomain
		v.ExpectedPath = path
		v.ExpectedPathRegex = ""
		return nil
	}
}

// WithExpectedSpiffeIDRegex sets the expected trust domain and a regex that
// must match the SVID path. Unsets any exact ExpectedPath.
func WithExpectedSpiffeIDRegex(trustDomain, pathRegex string) VerificationOptFunc {
	return func(v *Verification) error {
		if pathRegex != "" {
			if _, err := regexp.Compile(pathRegex); err != nil {
				return fmt.Errorf("compiling spiffe path regex: %w", err)
			}
		}
		v.ExpectedTrustDomain = trustDomain
		v.ExpectedPathRegex = pathRegex
		v.ExpectedPath = ""
		return nil
	}
}

// WithArtifactData hashes the artifact data to verify along the signature.
// This is required for message verifications
func WithArtifactData(data []byte) VerificationOptFunc {
	return func(opts *Verification) error {
		s256 := sha256.New()
		s256.Write(data)
		hashedBytes := s256.Sum(nil)

		opts.ArtifactDigest = fmt.Sprintf("%x", hashedBytes)
		opts.ArtifactDigestAlgo = "sha256"
		return nil
	}
}
