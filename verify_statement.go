// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"fmt"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
)

var (
	// ErrVerificationFailed marks a verification error whose cause is a
	// negative conclusion: the signatures were checked against the
	// available key or trust material and none verified. Wrap it with
	// the reason so callers can tell a failed verification apart from a
	// verification that could not run.
	ErrVerificationFailed = errors.New("signature verification failed")

	// ErrUnverifiable marks a verification error whose cause is missing
	// material: the statement is signed, but the verifier has no key,
	// trust root or backend able to check the signatures.
	ErrUnverifiable = errors.New("signature could not be verified")
)

// VerifyStatement is the inverse of Signer.SignStatement. It takes a
// signed statement in any supported format and returns the verification
// conclusion as an api.Verification carrying the three signals a
// consumer can read: whether the statement is signed (status UNSIGNED),
// whether the signatures could be checked (UNVERIFIABLE), and whether
// they verified against the content (FAILED or VERIFIED, in which case
// Identities names the signers).
//
// A non-nil error means nothing was concluded: the options, key or
// trust material could not be used, or the artifact is not a statement.
// A negative conclusion is not an error; it is returned as a
// Verification with the corresponding status and the reason in Error.
//
// Keys for DSSE envelopes come from options.WithPublicKeys or from the
// keys configured on the verifier. Bundles verify against the sigstore
// or SPIFFE trust material configured on the verifier.
func (v *Verifier) VerifyStatement(art SignedArtifact, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	if art == nil {
		return nil, errors.New("no signed artifact to verify")
	}
	switch a := art.(type) {
	case *EnvelopeArtifact:
		return v.verifyEnvelopeStatement(a.Envelope, fnOpts...)
	case *BundleArtifact:
		return v.verifyBundleStatement(a.Bundle, fnOpts...)
	default:
		return nil, fmt.Errorf("unsupported signed artifact kind %q", art.Kind())
	}
}

// VerifyStatementBytes parses the serialized form of a signed statement
// (a sigstore bundle or a DSSE envelope) and verifies it with
// VerifyStatement.
func (v *Verifier) VerifyStatementBytes(data []byte, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	art, err := ParseArtifact(data)
	if err != nil {
		return nil, err
	}
	return v.VerifyStatement(art, fnOpts...)
}

// verifyEnvelopeStatement verifies a bare DSSE envelope against the
// configured public keys.
func (v *Verifier) verifyEnvelopeStatement(env *sdsse.Envelope, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	if env == nil {
		return nil, errors.New("envelope artifact has no DSSE envelope")
	}
	if len(env.GetSignatures()) == 0 {
		return conclude(api.VerificationStatus_UNSIGNED, "DSSE envelope has no signatures"), nil
	}

	opts := v.Options.Verification
	for _, fn := range fnOpts {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}
	if len(opts.PubKeys) == 0 {
		return conclude(api.VerificationStatus_UNVERIFIABLE, "no public keys to verify the DSSE signatures against"), nil
	}

	res, err := v.VerifyParsedDSSE(env, opts.PubKeys, fnOpts...)
	if err != nil {
		return nil, err
	}
	if !res.Verified {
		return conclude(api.VerificationStatus_FAILED, fmt.Sprintf(
			"none of the %d signatures verified against the %d supplied public keys",
			len(env.GetSignatures()), len(opts.PubKeys),
		)), nil
	}

	ids := make([]*api.Identity, 0, len(res.Keys))
	for _, k := range res.Keys {
		ids = append(ids, &api.Identity{
			Key: &api.IdentityKey{
				Id:                 k.ID(),
				Type:               string(k.Scheme),
				Data:               k.Data,
				SigningFingerprint: k.SigningKeyFingerprint,
			},
		})
	}
	return verified(ids), nil
}

// verifyBundleStatement verifies a sigstore bundle wrapping a DSSE
// envelope against the configured sigstore or SPIFFE trust material,
// translating the bundle verifier's typed errors into conclusions.
func (v *Verifier) verifyBundleStatement(bndl *sbundle.Bundle, fnOpts ...options.VerificationOptFunc) (*api.Verification, error) {
	if bndl == nil || bndl.Bundle == nil {
		return nil, errors.New("bundle artifact has no bundle")
	}
	env := bndl.GetDsseEnvelope()
	if env == nil {
		return nil, errors.New("bundle does not wrap a DSSE envelope, it is not a signed statement")
	}
	if len(env.GetSignatures()) == 0 {
		return conclude(api.VerificationStatus_UNSIGNED, "bundle DSSE envelope has no signatures"), nil
	}

	res, err := v.VerifyParsedBundle(bndl, fnOpts...)
	switch {
	case errors.Is(err, ErrUnverifiable):
		return conclude(api.VerificationStatus_UNVERIFIABLE, err.Error()), nil
	case errors.Is(err, ErrVerificationFailed):
		return conclude(api.VerificationStatus_FAILED, err.Error()), nil
	case err != nil:
		return nil, err
	case res == nil:
		return nil, errors.New("bundle verifier returned no result and no error")
	}

	sv := api.SignatureVerificationFromResult(res)
	sv.Date = timestamppb.Now()
	sv.Verified = true
	sv.Status = api.VerificationStatus_VERIFIED
	return &api.Verification{Signature: sv}, nil
}

// conclude builds a Verification for an outcome other than VERIFIED.
func conclude(status api.VerificationStatus, reason string) *api.Verification {
	return &api.Verification{
		Signature: &api.SignatureVerification{
			Date:     timestamppb.Now(),
			Status:   status,
			Verified: false,
			Error:    reason,
		},
	}
}

// verified builds a VERIFIED Verification naming the signers.
func verified(ids []*api.Identity) *api.Verification {
	return &api.Verification{
		Signature: &api.SignatureVerification{
			Date:       timestamppb.Now(),
			Status:     api.VerificationStatus_VERIFIED,
			Verified:   true,
			Identities: ids,
		},
	}
}
