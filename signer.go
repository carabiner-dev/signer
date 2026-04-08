// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/sigstore"
)

// NewSigner creates a new signer and initializes it with the default sigstore
// roots embedded in the package.
func NewSigner() *Signer {
	// Parse the default roots, by default we sign using the first sigstore
	// root which is tested to ensure it is sign-capable
	opts := options.DefaultSigner
	roots, err := sigstore.ParseRoots(opts.SigstoreRootsData)
	if err == nil && len(roots.Roots) > 0 {
		opts.Instance = roots.Roots[0].Instance
	} else {
		// This is a fatal err. This should never happen as the package embeds
		// the roots information and we have unit tests to check they are valid
		// but we rather fail here instead of leaving apps to do something funky
		// with the signer if for some reason the roots data is invalid.
		errm := ""
		if err != nil {
			errm = fmt.Sprintf(" (%s)", err.Error())
		} else if len(roots.Roots) == 0 {
			errm = " (no roots defined)"
		}
		logrus.Fatalf("failed parsing roots config%s", errm)
	}
	return &Signer{
		Options:      opts,
		bundleSigner: bundle.NewSigner(),
		dsseSigner:   dsse.NewSigner(),
	}
}

type Signer struct {
	Options      options.Signer
	bundleSigner bundle.Signer
	dsseSigner   dsse.Signer

	// Cached signing state reused across multiple signing operations to avoid
	// repeated OIDC flows and Fulcio certificate requests.
	signingReady bool
	keypair      *sign.EphemeralKeypair
	bundleOpts   *sign.BundleOptions
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

// signingState returns the cached keypair and bundle options, initializing them
// on the first call. This ensures that the OIDC flow, Fulcio certificate request,
// and keypair generation happen only once even when signing multiple artifacts.
func (s *Signer) signingState() (*sign.EphemeralKeypair, *sign.BundleOptions, error) {
	if s.signingReady {
		return s.keypair, s.bundleOpts, nil
	}

	// Verify the defined options:
	if err := s.Options.Validate(); err != nil {
		return nil, nil, fmt.Errorf("validating options for signing: %w", err)
	}

	// Generate the ephemeral keypair
	keypair, err := s.bundleSigner.GetKeyPair(&s.Options)
	if err != nil {
		return nil, nil, err
	}

	// Run the STS providers to check for ambient credentials
	if err := s.bundleSigner.GetAmbientTokens(&s.Options); err != nil {
		return nil, nil, fmt.Errorf("fetching ambient credentials: %w", err)
	}

	// Get the ID token
	if err := s.bundleSigner.GetOidcToken(&s.Options); err != nil {
		return nil, nil, fmt.Errorf("getting ID token: %w", err)
	}

	// Generate the signer options
	bundleOpts, err := s.bundleSigner.BuildSigstoreSignerOptions(&s.Options)
	if err != nil {
		return nil, nil, fmt.Errorf("building options: %w", err)
	}

	// Wrap the certificate provider so the Fulcio certificate is fetched once
	// and reused for all subsequent signing operations with this keypair.
	if bundleOpts != nil && bundleOpts.CertificateProvider != nil {
		bundleOpts.CertificateProvider = &cachingCertProvider{
			inner: bundleOpts.CertificateProvider,
		}
	}

	s.keypair = keypair
	s.bundleOpts = bundleOpts
	s.signingReady = true
	return keypair, bundleOpts, nil
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
//
// When called multiple times on the same Signer, the keypair, OIDC token,
// and Fulcio certificate are reused across calls.
func (s *Signer) SignStatement(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return nil, err
		}
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

	keypair, bundleOpts, err := s.signingState()
	if err != nil {
		return nil, err
	}

	bndl, err := s.bundleSigner.SignBundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("singing statement: %w", err)
	}
	return &sbundle.Bundle{
		Bundle: bndl,
	}, nil
}

// SignMessage signs a payload as a message digest and returns a sigstore bundle.
// When called multiple times on the same Signer, the keypair, OIDC token,
// and Fulcio certificate are reused across calls.
func (s *Signer) SignMessage(data []byte, funcs ...options.SignOptFn) (*sbundle.Bundle, error) {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return nil, err
		}
	}

	// Wrap the payload as a message
	content := s.bundleSigner.BuildMessage(data)

	keypair, bundleOpts, err := s.signingState()
	if err != nil {
		return nil, err
	}

	bndl, err := s.bundleSigner.SignBundle(content, keypair, bundleOpts)
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

// SignEnvelope signs an existing envelope with the specified keys
func (s *Signer) SignEnvelope(envelope *sdsse.Envelope, funcs ...options.SignOptFn) error {
	signOpts := options.DefaultSign
	for _, f := range funcs {
		if err := f(&signOpts); err != nil {
			return err
		}
	}

	// Call the underlying signer
	if err := s.dsseSigner.Sign(envelope, signOpts.Keys); err != nil {
		return fmt.Errorf("signing envelope: %w", err)
	}

	return nil
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

// cachingCertProvider wraps a CertificateProvider and caches the certificate
// after the first successful request. This avoids issuing multiple Fulcio
// certificate requests when the same keypair is used to sign several artifacts.
// The cached certificate is discarded when it expires.
type cachingCertProvider struct {
	inner     sign.CertificateProvider
	cert      []byte
	notBefore time.Time
	notAfter  time.Time
}

func (c *cachingCertProvider) GetCertificate(ctx context.Context, kp sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	now := time.Now()
	if c.cert != nil && now.After(c.notBefore) && now.Before(c.notAfter) {
		return c.cert, nil
	}

	cert, err := c.inner.GetCertificate(ctx, kp, opts)
	if err != nil {
		return nil, err
	}

	// Parse the DER certificate to read its expiry time
	x509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("parsing cached certificate: %w", err)
	}

	c.cert = cert
	c.notBefore = x509Cert.NotBefore
	c.notAfter = x509Cert.NotAfter
	return cert, nil
}
