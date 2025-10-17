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
func NewVerifier(fnOpts ...options.VerifierOptFunc) *Verifier {
	opts := options.DefaultVerifier
	for _, f := range fnOpts {
		f(&opts)
	}

	bv := bundle.New(bundle.WithSigstoreRootsData(opts.SigstoreRootsData))
	return &Verifier{
		Options:        opts,
		bundleVerifier: bv,
		dsseVerifier:   &dsse.DefaultVerifier{},
	}
}

type Verifier struct {
	Options        options.Verifier
	bundleVerifier bundle.Verifier
	dsseVerifier   dsse.Verifier
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyBundle(bundlePath string, fnOpts ...options.VerificationOptFunc) (*verify.VerificationResult, error) {
	bndl, err := v.bundleVerifier.OpenBundle(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle: %w", err)
	}

	return v.VerifyParsedBundle(bndl, fnOpts...)
}

// VerifyBundle verifies a signed bundle containing a dsse envelope
func (v *Verifier) VerifyInlineBundle(bundleContents []byte, fnOpts ...options.VerificationOptFunc) (*verify.VerificationResult, error) {
	var bndl sbundle.Bundle

	// Unmarshal the bundle
	err := bndl.UnmarshalJSON(bundleContents)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling JSON: %w", err)
	}
	return v.VerifyParsedBundle(&bndl, fnOpts...)
}

// VerifyParsedBundle verifies a sigstore bundle with the provided options
func (v *Verifier) VerifyParsedBundle(bndl *sbundle.Bundle, fnOpts ...options.VerificationOptFunc) (*verify.VerificationResult, error) {
	opts := v.Options.Verification
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	// This needs to change to a single verify call
	result, err := v.bundleVerifier.Verify(&opts, bndl)
	if err != nil {
		return nil, fmt.Errorf("verifying bundle: %w", err)
	}
	return result, nil
}

// VerifyDSSE parses a DSSE envelope from a file and returns it
func (v *Verifier) VerifyDSSE(path string, keys []key.PublicKeyProvider, fnOpts ...options.VerificationOptFunc) (*key.VerificationResult, error) {
	env, err := v.dsseVerifier.OpenEnvelope(path)
	if err != nil {
		return nil, fmt.Errorf("parsing DSSE envelope: %w", err)
	}

	return v.VerifyParsedDSSE(env, keys, fnOpts...)
}

// VerifyParsedDSSE verifies an already parsed DSSE envelope
func (v *Verifier) VerifyParsedDSSE(env *sdsse.Envelope, keys []key.PublicKeyProvider, fnOpts ...options.VerificationOptFunc) (*key.VerificationResult, error) {
	opts := v.Options.Verification
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	// Build the key verifier to check the envelope signatures
	keyVerifier, err := v.dsseVerifier.BuildKeyVerifier(&v.Options)
	if err != nil {
		return nil, fmt.Errorf("building key verifier: %w", err)
	}

	// Verify and return the results
	return v.dsseVerifier.RunVerification(&v.Options, keyVerifier, env, keys)
}
