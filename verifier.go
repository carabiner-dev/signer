// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"fmt"
	"os"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/signer/bundle"
	"github.com/carabiner-dev/signer/dsse"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/sigstore"
	spiffeverifier "github.com/carabiner-dev/signer/spiffe/verifier"
)

// NewVerifierFromSet builds a *Verifier from a VerifierSet. Equivalent
// to BuildVerifier + NewVerifier with the resolved options applied,
// in one call. Lives in this package (not options/) because options/
// cannot import signer/.
func NewVerifierFromSet(set *options.VerifierSet) (*Verifier, error) {
	if set == nil {
		return nil, errors.New("NewVerifierFromSet: set is nil")
	}
	opts, err := set.BuildVerifier()
	if err != nil {
		return nil, err
	}
	return NewVerifier(func(o *options.Verifier) { *o = *opts }), nil
}

// NewVerifier creates a new verifier with default options and verifiers
func NewVerifier(fnOpts ...options.VerifierOptFunc) *Verifier {
	opts := options.DefaultVerifier
	for _, f := range fnOpts {
		f(&opts)
	}

	rootsData := opts.SigstoreRootsData
	if opts.SigstoreRootsPath != "" {
		loaded, err := os.ReadFile(opts.SigstoreRootsPath)
		if err != nil {
			// Match the bundle.New contract for trust-material init:
			// log and fall through to the embedded default rather than
			// blow up the verifier at construction time.
			logrus.Errorf("reading sigstore roots from %q: %v", opts.SigstoreRootsPath, err)
		} else {
			rootsData = loaded
		}
	}

	bundleOpts := []bundle.BundleOptsFunc{bundle.WithSigstoreRootsData(rootsData)}
	if opts.TrustRootsPEM != nil || opts.TrustRootsPath != "" {
		sv, err := spiffeverifier.NewVerifierFromOptions(&opts.SpiffeVerification)
		if err != nil {
			// Initialization errors are logged but not fatal, matching the
			// bundle.New contract for the sigstore-roots option.
			logrus.Errorf("building spiffe verifier: %v", err)
		} else {
			// Wire TSA trust material from the embedded sigstore roots so
			// SVID-signed bundles carrying an RFC 3161 timestamp can be
			// validated past the SVID's TTL. Best-effort — if the roots
			// don't carry a usable trusted root we log and let the SPIFFE
			// verifier fall back to time.Now() chain validation.
			if tm, terr := tsaTrustedMaterial(rootsData); terr != nil {
				logrus.Errorf("building TSA trust material for spiffe verifier: %v", terr)
			} else {
				sv.SetTSATrustedMaterial(tm)
			}
			bundleOpts = append(bundleOpts, bundle.WithSpiffeVerifier(sv))
		}
	}

	bv := bundle.New(bundleOpts...)
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

	if len(keys) == 0 {
		keys = opts.PubKeys
	}

	// Build the key verifier to check the envelope signatures
	keyVerifier, err := v.dsseVerifier.BuildKeyVerifier(&v.Options)
	if err != nil {
		return nil, fmt.Errorf("building key verifier: %w", err)
	}

	// Verify and return the results
	return v.dsseVerifier.RunVerification(&v.Options, keyVerifier, env, keys)
}

// tsaTrustedMaterial parses the embedded sigstore-roots data and
// returns a TrustedMaterial backed by the first instance's trusted
// root JSON. Used by the SPIFFE verifier to validate RFC 3161
// timestamps anchored to sigstore's TSA without requiring a TUF fetch
// at verify time.
func tsaTrustedMaterial(rootsData []byte) (root.TrustedMaterial, error) {
	parsed, err := sigstore.ParseRoots(rootsData)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore roots: %w", err)
	}
	if len(parsed.Roots) == 0 || len(parsed.Roots[0].RootData) == 0 {
		return nil, errors.New("no trusted root data in sigstore roots")
	}
	tr, err := root.NewTrustedRootFromJSON(parsed.Roots[0].RootData)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted root JSON: %w", err)
	}
	return tr, nil
}
