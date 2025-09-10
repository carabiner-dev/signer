// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"fmt"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
)

// NewVerifier creates a new verifier with default options and verifiers
func NewVerifier() *Verifier {
	return &Verifier{
		Options:        options.DefaultVerifier,
		bundleVerifier: &bundle.DefaultVerifier{},
		dsseVerifier:   &dsse.DefaultVerifier{},
	}
}

type Verifier struct {
	Options        options.Verifier
	bundleVerifier bundle.Verifier
	dsseVerifier   dsse.Verifier
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyBundle(bundlePath string, fnOpts ...options.VerifierOptFunc) (*verify.VerificationResult, error) {
	bndl, err := v.bundleVerifier.OpenBundle(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle: %w", err)
	}

	return v.VerifyParsedBundle(bndl, fnOpts...)
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyInlineBundle(bundleContents []byte, fnOpts ...options.VerifierOptFunc) (*verify.VerificationResult, error) {
	var bndl sbundle.Bundle

	// Unmarshal the bundle
	err := bndl.UnmarshalJSON(bundleContents)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling JSON: %w", err)
	}
	return v.VerifyParsedBundle(&bndl, fnOpts...)
}

// VerifyParsedBundle verifies a sigstore bundle with the provided options
func (v *Verifier) VerifyParsedBundle(bndl *sbundle.Bundle, fnOpts ...options.VerifierOptFunc) (*verify.VerificationResult, error) {
	opts := v.Options
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	vrfr, err := v.bundleVerifier.BuildSigstoreVerifier(&opts)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	result, err := v.bundleVerifier.RunVerification(&opts, vrfr, bndl)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}

	return result, err
}

// VerifyDSSE parses a DSSE envelope from a file and returns it
func (v *Verifier) VerifyDSSE(path string, keys []*key.Public, fnOpts ...options.VerifierOptFunc) (*key.VerificationResult, error) {
	env, err := v.dsseVerifier.OpenEnvelope(path)
	if err != nil {
		return nil, fmt.Errorf("parsing DSSE envelope: %w", err)
	}

	return v.VerifyParsedDSSE(env, keys, fnOpts...)
}

// VerifyParsedDSSE verifies an already parsed DSSE envelope
func (v *Verifier) VerifyParsedDSSE(env *sdsse.Envelope, keys []*key.Public, fnOpts ...options.VerifierOptFunc) (*key.VerificationResult, error) {
	opts := v.Options
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	// Build the key verifier to check the envelope signatures
	keyVerifier, err := v.dsseVerifier.BuildKeyVerifier(&opts)
	if err != nil {
		return nil, fmt.Errorf("building key verifier: %w", err)
	}

	// Verify and return the results
	return v.dsseVerifier.RunVerification(&opts, keyVerifier, env, keys)
}
