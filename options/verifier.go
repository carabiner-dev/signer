// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"crypto/sha256"
	"fmt"
	"regexp"

	"github.com/carabiner-dev/signer/internal/tuf"
)

type VerifierOptFunc func(*Verifier) error

type Verifier struct {
	tuf.TufOptions
	// Artifact digest to check when verifier in addition to the signature
	ArtifactDigestAlgo string
	ArtifactDigest     string

	// ExpectedIssuer and ExpectedSan define the issuer and SAN to look for in
	// the fulcio cert. For a broader matching behavior, choose the *Regex
	// alternatives.
	// Verification will fail if thse are not set. To skip the identity check
	// set SkipIdentityCheck to true.
	ExpectedIssuer      string
	ExpectedIssuerRegex string
	ExpectedSan         string
	ExpectedSanRegex    string

	// SkipIdentityCheck makes the verifier skip the identity check. This
	// will ignore any setting in ExpectedIssuer ExpectedIssuerRegex
	// ExpectedSan or ExpectedSanRegex
	SkipIdentityCheck bool

	RequireCTlog     bool
	RequireTimestamp bool
	RequireTlog      bool
}

var DefaultVerifier = Verifier{
	TufOptions: tuf.TufOptions{
		TufRootURL:  tuf.SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     tuf.Defaultfetcher(),
	},
	ArtifactDigestAlgo: "sha256",
	RequireCTlog:       true,
	RequireTimestamp:   true,
	RequireTlog:        true,
}

// WithExpectedIdentity serts the ExpectedIssuer and ExptectedSan options
// and unsets the regex alternatives
func WithExpectedIdentity(issuer, san string) VerifierOptFunc {
	return func(v *Verifier) error {
		v.ExpectedIssuerRegex = ""
		v.ExpectedSanRegex = ""
		v.ExpectedIssuer = issuer
		v.ExpectedSan = san
		return nil
	}
}

// WithExpectedIdentity serts the ExpectedIssuerRegex and ExptectedSanRegex options
// and unsets the non-regex alternatives
func WithExpectedIdentityReged(issuer, san string) VerifierOptFunc {
	return func(v *Verifier) error {
		// Check the regular expressions
		if _, err := regexp.Compile(issuer); err != nil {
			return fmt.Errorf("compiling issuer regex: %w", err)
		}
		if _, err := regexp.Compile(san); err != nil {
			return fmt.Errorf("compiling SAN regex: %w", err)
		}

		v.ExpectedIssuerRegex = issuer
		v.ExpectedSanRegex = san
		v.ExpectedIssuer = ""
		v.ExpectedSan = ""
		return nil
	}
}

// WithSkipIdentityCheck instructs the verifier to no t check the signature
// identities
func WithSkipIdentityCheck(yesno bool) VerifierOptFunc {
	return func(v *Verifier) error {
		v.SkipIdentityCheck = yesno
		return nil
	}
}

// WithArtifactData hashes the artifact data to verify along the signature.
// This is required for message verifications
func WithArtifactData(data []byte) VerifierOptFunc {
	return func(opts *Verifier) error {
		s256 := sha256.New()
		s256.Write(data)
		hashedBytes := s256.Sum(nil)

		opts.ArtifactDigest = fmt.Sprintf("%x", hashedBytes)
		opts.ArtifactDigestAlgo = "sha256"
		return nil
	}
}
