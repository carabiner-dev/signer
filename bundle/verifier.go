// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/nozzle/throttler"
	commonv1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sirupsen/logrus"

	"github.com/carabiner-dev/signer/internal/tuf"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/sigstore"
)

type BundleOptsFunc func(*DefaultVerifier) error

// WithSigstoreRootsData sets the raw json data holding the sigstore instances
// configuration
func WithSigstoreRootsData(data []byte) BundleOptsFunc {
	return func(v *DefaultVerifier) error {
		roots, err := sigstore.ParseRoots(data)
		if err != nil {
			return err
		}

		for i := range roots.Roots {
			ver, err := v.BuildSigstoreVerifier(&roots.Roots[i])
			if err != nil {
				return fmt.Errorf("building verifier %d: %w", i, err)
			}
			v.Verifiers = append(v.Verifiers, ver)
		}
		return nil
	}
}

// WithSpiffeVerifier installs the verifier used when a bundle carries a
// SPIFFE-shaped identity (leaf cert with a spiffe:// URI SAN).
func WithSpiffeVerifier(sv SpiffeVerifier) BundleOptsFunc {
	return func(v *DefaultVerifier) error {
		v.SPIFFE = sv
		return nil
	}
}

// New creates a new verifier. Initialization errors are logged to stderr
// but not returned. Use NewWithError if you need to handle errors.
func New(funcs ...BundleOptsFunc) Verifier {
	v, err := NewWithError(funcs...)
	if err != nil {
		log.Default().Print(err)
	}
	return v
}

// NewWithError creates a new verifier and returns any initialization error.
func NewWithError(funcs ...BundleOptsFunc) (Verifier, error) {
	ret := &DefaultVerifier{}
	for _, f := range funcs {
		if err := f(ret); err != nil {
			return ret, err
		}
	}

	return ret, nil
}

// VerifyCapable abstracts the verifier to mock
type VerifyCapable interface {
	Verify(verify.SignedEntity, verify.PolicyBuilder) (*verify.VerificationResult, error)
}

// SpiffeVerifier verifies bundles signed against a SPIFFE/SPIRE trust domain.
// Implemented by spiffe.Verifier; typed as an interface here so the bundle
// package doesn't have to import the spiffe package.
type SpiffeVerifier interface {
	Verify(*options.Verification, *bundle.Bundle) (*verify.VerificationResult, error)
}

// BundleVerifier abstracts the verification implementation to make it easy to
// mock for testing.
//
//counterfeiter:generate . Verifier
type Verifier interface {
	Verify(*options.Verification, *bundle.Bundle) (*verify.VerificationResult, error)
	OpenBundle(string) (*bundle.Bundle, error)
	BuildSigstoreVerifier(*sigstore.InstanceConfig) (VerifyCapable, error)
	RunVerification(*options.SigstoreVerification, VerifyCapable, *bundle.Bundle) (*verify.VerificationResult, error)
}

// DefaultVerifier implements the BundleVerifier interface.
type DefaultVerifier struct {
	Verifiers []VerifyCapable

	// SPIFFE, when set, handles bundles whose leaf certificate carries a
	// spiffe:// URI SAN. Constructed outside this package (typically in
	// signer.NewVerifier) to avoid a bundle -> spiffe import dependency.
	SPIFFE SpiffeVerifier
}

// OpenBundle opens a bundle file
func (bv *DefaultVerifier) OpenBundle(path string) (*bundle.Bundle, error) {
	b, err := bundle.LoadJSONFromPath(path)
	if err != nil {
		return nil, fmt.Errorf("opening path: %w", err)
	}
	return b, nil
}

// Verify is the main verification function to check bundles. Dispatches to
// the SPIFFE verifier when the bundle carries a spiffe:// URI SAN; otherwise
// iterates the configured sigstore instances.
func (bv *DefaultVerifier) Verify(opts *options.Verification, bndl *bundle.Bundle) (*verify.VerificationResult, error) {
	if isSpiffeBundle(bndl) {
		if bv.SPIFFE == nil {
			return nil, errors.New("bundle carries a spiffe identity but no spiffe verifier is configured")
		}
		return bv.SPIFFE.Verify(opts, bndl)
	}
	if len(bv.Verifiers) == 0 {
		return nil, fmt.Errorf("unable to verify bundle, no sigstore instances loaded")
	}

	// TODO(puerco): Befor brute forcing all instances, we could try to guess which
	// instance should be used by looking at the cert issuer.

	var finalRes *verify.VerificationResult

	t := throttler.New(4, len(bv.Verifiers))
	for i := range bv.Verifiers {
		go func() {
			if finalRes != nil {
				t.Done(nil)
				return
			}

			// Run the verification
			res, err := bv.RunVerification(&opts.SigstoreVerification, bv.Verifiers[i], bndl)
			if err != nil {
				t.Done(err)
				return
			}

			// No error with a result? Then we got it.
			if res != nil {
				finalRes = res
			}

			t.Done(nil)
		}()
		t.Throttle()
	}

	if finalRes != nil {
		return finalRes, nil
	}
	return nil, fmt.Errorf("unable to verify with the configured sigstore instances: %w", t.Err())
}

// BuildSigstoreVerifier creates a configured sigstore verifier from the
// configured options.
// TODO(puerco): Abstract the returned verifier
func (bv *DefaultVerifier) BuildSigstoreVerifier(conf *sigstore.InstanceConfig) (VerifyCapable, error) {
	trustedMaterial, err := bv.assembleTrustedMaterial(conf)
	if err != nil {
		return nil, fmt.Errorf("building trusted materials: %w", err)
	}
	if len(trustedMaterial) == 0 {
		return nil, errors.New("no trusted material assembled")
	}

	// Create the verifier
	sigstoreVerifier, err := verify.NewVerifier(trustedMaterial, bv.buildVerifierConfig(conf)...)
	if err != nil {
		return nil, fmt.Errorf("building sigstore verifier: %w", err)
	}
	return sigstoreVerifier, nil
}

func (bv *DefaultVerifier) assembleTrustedMaterial(conf *sigstore.InstanceConfig) (root.TrustedMaterialCollection, error) {
	trustedMaterial := make(root.TrustedMaterialCollection, 1)

	// Fetch the trusted root data
	data, err := tuf.GetRoot(&conf.TufOptions)
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, err
	}
	trustedMaterial[0] = trustedRoot
	return trustedMaterial, nil
}

// buildVerifierConfig creates a verifier configuration from an options set
func (bv *DefaultVerifier) buildVerifierConfig(conf *sigstore.InstanceConfig) []verify.VerifierOption {
	config := []verify.VerifierOption{}

	vc := conf.VerifierConfig

	if vc.RequireCTlog {
		config = append(config, verify.WithSignedCertificateTimestamps(1))
	}

	if vc.RequireSignedTimestamps {
		config = append(config, verify.WithSignedTimestamps(1))
	}

	if vc.RequireObserverTimestamp {
		config = append(config, verify.WithObserverTimestamps(1))
	}

	if vc.RequireTlog {
		config = append(config, verify.WithTransparencyLog(1))
	}

	return config
}

// RunVerification verifies an artifact using the provided verifier
func (bv *DefaultVerifier) RunVerification(
	opts *options.SigstoreVerification, sigstoreVerifier VerifyCapable, bndl *bundle.Bundle,
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
			opts.ExpectedIssuerRegex, // IssuerRegex
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
	switch {
	case opts.ArtifactDigest != "":
		hexdigest, err := hex.DecodeString(opts.ArtifactDigest)
		if err != nil {
			return nil, fmt.Errorf("error decoding artifact digest hex string")
		}
		artifactPolicy = verify.WithArtifactDigest(opts.ArtifactDigestAlgo, hexdigest)

	case bndl.GetMessageSignature() != nil && bndl.GetMessageSignature().GetMessageDigest() != nil:
		// When the bundle has a messageSignature with an embedded digest,
		// use it for artifact verification.
		md := bndl.GetMessageSignature().GetMessageDigest()
		algo, err := hashAlgorithmToString(md.GetAlgorithm())
		if err != nil {
			return nil, err
		}
		artifactPolicy = verify.WithArtifactDigest(algo, md.GetDigest())

	default:
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

// isSpiffeBundle reports whether the bundle's leaf certificate carries a
// spiffe:// URI SAN. Used to dispatch between the sigstore and SPIFFE paths.
func isSpiffeBundle(bndl *bundle.Bundle) bool {
	vm := bndl.GetVerificationMaterial()
	if vm == nil {
		return false
	}
	var der []byte
	if chain := vm.GetX509CertificateChain(); chain != nil && len(chain.GetCertificates()) > 0 {
		der = chain.GetCertificates()[0].GetRawBytes()
	} else if cert := vm.GetCertificate(); cert != nil {
		der = cert.GetRawBytes()
	}
	if len(der) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	for _, uri := range leaf.URIs {
		if uri.Scheme == "spiffe" {
			return true
		}
	}
	return false
}

// hashAlgorithmToString maps a protobuf HashAlgorithm enum to the string
// expected by sigstore-go's WithArtifactDigest.
func hashAlgorithmToString(algo commonv1.HashAlgorithm) (string, error) {
	//nolint:exhaustive
	switch algo {
	case commonv1.HashAlgorithm_SHA2_256:
		return "sha256", nil
	case commonv1.HashAlgorithm_SHA2_384:
		return "sha384", nil
	case commonv1.HashAlgorithm_SHA2_512:
		return "sha512", nil
	case commonv1.HashAlgorithm_SHA3_256: //nolint:staticcheck // Keeping these for compat
		return "sha3-256", nil
	case commonv1.HashAlgorithm_SHA3_384: //nolint:staticcheck // Keeping these for compat
		return "sha3-384", nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
}
