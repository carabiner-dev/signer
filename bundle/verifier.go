// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/signer/internal/tuf"
	"github.com/carabiner-dev/signer/options"
)

type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

// BundleVerifier abstracts the verification implementation to make it easy to
// mock for testing.
type Verifier interface {
	OpenBundle(string) (*bundle.Bundle, error)
	BuildSigstoreVerifier(*options.Verifier) (VerifyCapable, error)
	RunVerification(*options.Verifier, VerifyCapable, *bundle.Bundle) (*verify.VerificationResult, error)
}

// DefaultVerifier implements the BundleVerifier interface.
type DefaultVerifier struct{}

// OpenBundle opens a bundle file
func (bv *DefaultVerifier) OpenBundle(path string) (*bundle.Bundle, error) {
	b, err := bundle.LoadJSONFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("opening path: %w", err)
	}
	return b, nil
}

// BuildSigstoreVerifier creates a configured sigstore verifier from the
// configured options
// TODO(puerco): Abstract the returned verifier
func (bv *DefaultVerifier) BuildSigstoreVerifier(opts *options.Verifier) (VerifyCapable, error) {
	trustedMaterial, err := bv.assembleTrustedMaterial(opts)
	if err != nil {
		return nil, fmt.Errorf("building trusted materials: %w", err)
	}
	if len(trustedMaterial) == 0 {
		return nil, errors.New("no trusted material assembled")
	}

	// Create the verifier
	sigstoreVerifier, err := verify.NewVerifier(trustedMaterial, bv.buildVerifierConfig(opts)...)
	if err != nil {
		return nil, fmt.Errorf("building sigstore verifier: %w", err)
	}
	return sigstoreVerifier, nil
}

func (bv *DefaultVerifier) assembleTrustedMaterial(opts *options.Verifier) (root.TrustedMaterialCollection, error) {
	trustedMaterial := make(root.TrustedMaterialCollection, 0)

	// Fetch the trusted root data
	data, err := tuf.GetRoot(&opts.TufOptions)
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, err
	}
	trustedMaterial = append(trustedMaterial, trustedRoot)

	return trustedMaterial, nil
}

// buildVerifierConfig creates a verifier configuration from an options set
func (bv *DefaultVerifier) buildVerifierConfig(opts *options.Verifier) []verify.VerifierOption {
	config := []verify.VerifierOption{}

	if opts.RequireCTlog {
		config = append(config, verify.WithSignedCertificateTimestamps(1))
	}

	if opts.RequireTimestamp {
		config = append(config, verify.WithObserverTimestamps(1))
	}

	if opts.RequireTlog {
		config = append(config, verify.WithTransparencyLog(1))
	}

	return config
}

// RunVerification verifies an artifact using the provided verifier
func (bv *DefaultVerifier) RunVerification(
	opts *options.Verifier, sigstoreVerifier VerifyCapable, bndl *bundle.Bundle,
) (*verify.VerificationResult, error) {
	// If this is a DSSE envelope, check it as a payload
	dsse := bndl.GetDsseEnvelope()
	if dsse != nil {
		if dsse.GetPayload() == nil {
			return nil, fmt.Errorf("unable to extract payload from DSSE envelope")
		}
	}

	// Build the identity policy if set in the options
	identityPolicies := []verify.PolicyOption{}
	switch {
	// Only ignore the isentity check if the options is explicitly set
	case opts.SkipIdentityCheck:
		identityPolicies = append(identityPolicies, verify.WithoutIdentitiesUnsafe())

	case opts.ExpectedIssuer != "" || opts.ExpectedIssuerRegex != "" ||
		opts.ExpectedSan != "" || opts.ExpectedSanRegex != "":
		// Here we pass the expected identities to the sigstore-go library
		expectedIdentity, err := verify.NewShortCertificateIdentity(
			opts.ExpectedIssuer,      // Issuer
			opts.ExpectedIssuerRegex, // issuerRegex
			opts.ExpectedSan,         // SAN
			opts.ExpectedSanRegex,    // SAN regex
		)
		if err != nil {
			return nil, fmt.Errorf("creating expected identity: %w", err)
		}
		identityPolicies = append(identityPolicies, verify.WithCertificateIdentity(expectedIdentity))
	default:
		return nil, fmt.Errorf("expected certificate issuer/identity not defined")
	}

	// Build the artifact policy if we have a digest in the options
	var artifactPolicy verify.ArtifactPolicyOption
	if opts.ArtifactDigest != "" {
		hexdigest, err := hex.DecodeString(opts.ArtifactDigest)
		if err != nil {
			return nil, fmt.Errorf("error decoding artifact digest hex string")
		}
		artifactPolicy = verify.WithArtifactDigest(opts.ArtifactDigestAlgo, hexdigest)
	} else {
		logrus.Debug("No artifact hash set, no subject matching will be done")
		artifactPolicy = verify.WithoutArtifactUnsafe()
	}
	res, err := sigstoreVerifier.Verify(
		bndl, verify.NewPolicy(artifactPolicy, identityPolicies...),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying: %w", err)
	}

	return res, nil
}
