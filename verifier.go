// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"fmt"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/options"
)

func NewVerifier() *Verifier {
	return &Verifier{
		Options:        options.DefaultVerifier,
		bundleVerifier: &bundle.DefaultVerifier{},
		dsseVerifier: &key.defaulDSSEVerifier
	}
}

type Verifier struct {
	Options        options.Verifier
	bundleVerifier bundle.Verifier
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

// VerifyDSSE verifies a DSSE envelope
func (v *Verifier) VerifyDSSE(env *sdsse.Envelope, fnOpts ...options.VerifierOptFunc) (*verify.VerificationResult, error) {
	opts := v.Options
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	kv := key.Verifier{}

}
