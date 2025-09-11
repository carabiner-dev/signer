// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"fmt"
	"io"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/options"
)

const GitHubTimeStamperURL = "https://timestamp.githubapp.com/api/v1/timestamp"

func NewSigner() *Signer {
	return &Signer{
		Options:      options.DefaultSigner,
		bundleSigner: &bundle.DefaultSigner{},
		dsseSigner:   &dsse.DefaultSigner{},
	}
}

type Signer struct {
	Options      options.Signer
	bundleSigner bundle.Signer
	dsseSigner   dsse.Signer
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

// SignStatement signs an in-toto attestation using the configured options and
// returns a sigstore bundle. The signing process will try to obtain the
// signer identity in this order:
//
//  1. Try the configured ambient credentials providers
//     (currently only the GitHub actions plugin is supported).
//  2. If a terminal is detected, it will start the sigstore oidc
//     flow in a browser.
//  3. If no terminal is detected, it will start the sigstore device
//     flow.
func (s *Signer) SignStatement(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
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
	if err := s.bundleSigner.VerifyAttestationContent(&s.Options, data); err != nil {
		return nil, fmt.Errorf("verifying content: %w", err)
	}

	// Wrap the attestation in its DSSE envelope. Note that we override the
	// payload type as sigstore-go rejects anything that is not in-toto.
	// (plus we already verified the data to be a statement).
	// See https://github.com/sigstore/sigstore-go/issues/509
	content := s.bundleSigner.WrapData("application/vnd.in-toto+json", data)

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

// SignMessage signs a payload as a message digest and returns a sigstore bundle.
func (s *Signer) SignMessage(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
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

	// Wrap the attestation in its DSSE envelope
	content := s.bundleSigner.BuildMessage(data)

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

// SignStatementToDSSE is a convenience method around SignMessageToDSSE that
// sets the in-toto payload type autmatically
func (s *Signer) SignStatementToDSSE(data []byte, funcs ...options.SignOptFn) (*sdsse.Envelope, error) {
	funcs = append(funcs, options.WithPayloadType("https://in-toto.io/Statement/v1"))
	return s.SignMessageToDSSE(data, funcs...)
}

// SignMessageToDSSE wraps a payload in a dsse envelope and signs it.
func (s *Signer) SignMessageToDSSE(message []byte, funcs ...options.SignOptFn) (*sdsse.Envelope, error) {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return nil, err
		}
	}

	if signOpts.PayloadType == "" {
		return nil, errors.New("payload type not defined")
	}

	// Create the new envelope
	envelope, err := s.dsseSigner.WrapPayload(signOpts.PayloadType, message)
	if err != nil {
		return nil, fmt.Errorf("wrapping payload: %w", err)
	}

	if err := s.dsseSigner.Sign(envelope, signOpts.Keys); err != nil {
		return nil, fmt.Errorf("signing envelope: %w", err)
	}

	return envelope, nil
}

// SignEnvelope wraps a payload in a dsse envelope and signs it.
func (s *Signer) SignEnvelope(envelope *sdsse.Envelope, funcs ...options.SignOptFn) (*sdsse.Envelope, error) {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return nil, err
		}
	}

	// Call the underlying signer
	if err := s.dsseSigner.Sign(envelope, signOpts.Keys); err != nil {
		return nil, fmt.Errorf("signing envelope: %w", err)
	}

	return envelope, nil
}

// WriteDSSEEnvelope marshals a DSSE envelope to JSON and writes it to a
// an io.Writer
func (s *Signer) WriteDSSEEnvelope(env *sdsse.Envelope, w io.Writer) error {
	marshaler := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}
	data, err := marshaler.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}

	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing data to writer sink: %w", err)
	}

	return nil
}
