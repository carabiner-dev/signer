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
}

var DefaultVerification = Verification{}

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
