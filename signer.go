// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"fmt"
	"io"

	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/options"
)

const GitHubTimeStamperURL = "https://timestamp.githubapp.com/api/v1/timestamp"

func NewSigner() *Signer {
	return &Signer{
		Options:      options.DefaultSigner,
		bundleSigner: &bundle.DefaultSigner{},
	}
}

type Signer struct {
	Options      options.Signer
	bundleSigner bundle.Signer
}

// WriteBundle writes the bundle JSON to
func (s *Signer) WriteBundle(bndl *sbundle.Bundle, w io.Writer) error {
	bundleJSON, err := protojson.Marshal(bndl)
	if err != nil {
		return fmt.Errorf("marshaling bundle: %w", err)
	}

	if _, err := w.Write(bundleJSON); err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}

	return nil
}

// SignBundle signs data using the configured options and
// returns a sigstore bundle. The signing process will try to obtain the
// signer identity in this order:
//
//  1. Try the configured ambient credentials providers
//     (currently only the GitHub actions plugin is supported).
//  2. If a terminal is detected, it will start the sigstore oidc
//     flow in a browser.
//  3. If no terminal is detected, it will start the sigstore device
//     flow.
func (s *Signer) SignBundle(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return nil, err
		}
	}
	// Verify the defined options:
	if err := s.Options.Validate(); err != nil {
		return nil, err
	}
	// check that statement is not empty and it is an intoto attestation
	if err := s.bundleSigner.VerifyContent(&s.Options, data); err != nil {
		return nil, fmt.Errorf("verifying content: %w", err)
	}

	// Wrap the attestation in its DSSE envelope
	content := s.bundleSigner.WrapData(signOpts.PayloadType, data)

	// Get(or generate) the public key
	keypair, err := s.bundleSigner.GetKeyPair(&s.Options)
	if err != nil {
		return nil, err
	}

	// Run the STS providers to check for ambient credentials
	if err := s.bundleSigner.GetAmbientTokens(&s.Options); err != nil {
		return nil, fmt.Errorf("fetching ambient credentials: %w", err)
	}

	// Get the ID token
	if err := s.bundleSigner.GetOidcToken(&s.Options); err != nil {
		return nil, fmt.Errorf("getting ID token: %w", err)
	}

	// Generate the signer options
	bundleSignerOption, err := s.bundleSigner.BuildSigstoreSignerOptions(&s.Options)
	if err != nil {
		return nil, fmt.Errorf("building options: %w", err)
	}

	bndl, err := s.bundleSigner.SignBundle(content, keypair, bundleSignerOption)
	if err != nil {
		return nil, fmt.Errorf("singing statement: %w", err)
	}
	return &sbundle.Bundle{
		Bundle: bndl,
	}, nil
}
