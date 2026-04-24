// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"regexp"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/proto"
)

// Ensure we are implementing the framworks verification
var _ attestation.Verification = (*Verification)(nil) //nolint:errcheck

// SignatureVerificationFromResult translates sigstore-go's
// *verify.VerificationResult into the api/v1 SignatureVerification used for
// policy matching. Handles both sigstore and SPIFFE flows by inspecting
// VerifiedIdentity: a spiffe:// SAN produces an IdentitySpiffe; any other
// SAN/Issuer pair produces an IdentitySigstore.
//
// Pass a nil result (e.g. when verification failed) to get back an empty,
// unverified SignatureVerification. Callers typically invoke this after a
// successful Verify call:
//
//	result, err := verifier.Verify(nil, bndl)
//	if err != nil {
//	    return err
//	}
//	sv := api.SignatureVerificationFromResult(result)
//	if !sv.MatchesIdentity(policyIdentity) {
//	    return errors.New("signer not authorized by policy")
//	}
func SignatureVerificationFromResult(r *verify.VerificationResult) *SignatureVerification {
	if r == nil {
		return &SignatureVerification{}
	}
	sv := &SignatureVerification{Verified: true}
	if r.VerifiedIdentity == nil {
		return sv
	}
	san := r.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName
	issuer := r.VerifiedIdentity.Issuer.Issuer

	switch {
	case strings.HasPrefix(san, "spiffe://"):
		id, err := IdentitySpiffeFromString(san)
		if err != nil {
			return sv
		}
		sv.Identities = append(sv.Identities, &Identity{Spiffe: id})
	case san != "" || issuer != "":
		sv.Identities = append(sv.Identities, &Identity{
			Sigstore: &IdentitySigstore{Issuer: issuer, Identity: san},
		})
	}
	return sv
}

// anchoredRegex wraps a user-supplied pattern so it must match the full
// input end-to-end. Without anchoring, Go's regexp.MatchString returns
// true on any substring match — a policy author writing an identity
// regex would reasonably expect full-string semantics (same convention
// as sigstore-go's cert-identity verification and cosign), and an
// unanchored pattern enables prefix/substring collision attacks.
func anchoredRegex(pattern string) string {
	return "^(?:" + pattern + ")$"
}

// Error implements the Go error interface when verification fails
func (v *Verification) Error() string {
	if !v.GetVerified() && v.GetSignature() != nil {
		return v.GetSignature().GetError()
	}
	return ""
}

// MatchesIdentity returns true if one of the verified signatures matches
// the identity.
func (v *Verification) MatchesIdentity(rawID any) bool {
	id, ok := rawID.(*Identity)
	if !ok {
		return false
	}
	if v.GetSignature() == nil {
		return false
	}

	return v.GetSignature().MatchesIdentity(id)
}

// GetVerified returns true if verification passed
func (v *Verification) GetVerified() bool {
	if v.GetSignature() == nil {
		return false
	}
	return v.GetSignature().GetVerified()
}

// HasIdentity returns true if one of the verifiers matches the passed identity
func (sv *SignatureVerification) MatchesIdentity(id *Identity) bool {
	switch {
	case id.GetSigstore() != nil:
		return sv.MatchesSigstoreIdentity(id.GetSigstore())
	case id.GetKey() != nil:
		return sv.MatchesKeyIdentity(id.GetKey())
	case id.GetSpiffe() != nil:
		return sv.MatchesSpiffeIdentity(id.GetSpiffe())
	default:
		return false //  This would be an error
	}
}

// HasIdentity returns true if one of the verifiers matches the passed sigstore
// identity.
func (sv *SignatureVerification) MatchesSigstoreIdentity(id *IdentitySigstore) bool {
	// If the identity is missing either the issuer or its ID string, then
	// we reject it.
	if id.GetIdentity() == "" || id.GetIssuer() == "" {
		return false
	}

	// If this is a regexp matcher, compile them. Policy-supplied patterns
	// are anchored to the full input so a pattern meant to pin a specific
	// identity can't match via substring or prefix (e.g. pattern "myorg"
	// would otherwise match SAN "myorg-evil/..."). Anchoring matches the
	// convention sigstore-go and cosign use for certificate-identity regex
	// policies.
	var regIdentity, regIssuer *regexp.Regexp
	if id.Mode != nil && id.GetMode() == SigstoreModeRegexp {
		var err error
		regIdentity, err = regexp.Compile(anchoredRegex(id.GetIdentity()))
		if err != nil {
			return false
		}
		regIssuer, err = regexp.Compile(anchoredRegex(id.GetIssuer()))
		if err != nil {
			return false
		}
	}

	// Check each identity in the verification until one matches.
	for _, signer := range sv.GetIdentities() {
		if signer.GetSigstore() == nil {
			continue
		}

		if id.Mode == nil || id.GetMode() == SigstoreModeExact {
			if signer.GetSigstore().GetIdentity() == id.GetIdentity() &&
				signer.GetSigstore().GetIssuer() == id.GetIssuer() {
				return true
			}
		} else if id.GetMode() == SigstoreModeRegexp {
			if regIdentity.MatchString(signer.GetSigstore().GetIdentity()) &&
				regIssuer.MatchString(signer.GetSigstore().GetIssuer()) {
				return true
			}
		}
	}
	return false
}

// MatchesSpiffeIdentity returns true if one of the verified signatures was
// produced by a SPIFFE workload matching the supplied identity. Matching
// rules:
//
//   - TrustDomain (required): compared exactly against the signer's trust
//     domain. An empty TrustDomain in the policy is rejected since a
//     wildcard match across trust domains is almost never the intent.
//   - Path (optional): when set, the signer's SPIFFE path must match
//     exactly. Mutually exclusive with PathRegex.
//   - PathRegex (optional): when set, compiled and applied to the signer's
//     SPIFFE path. Mutually exclusive with Path.
//   - TrustRoots is not consulted here — it is policy configuration used
//     by the verifier to validate the chain, not an attribute of the
//     signer.
//
// If both Path and PathRegex are set the policy is treated as malformed
// and no match is returned.
func (sv *SignatureVerification) MatchesSpiffeIdentity(id *IdentitySpiffe) bool {
	if id.GetTrustDomain() == "" {
		return false
	}
	if id.GetPath() != "" && id.GetPathRegex() != "" {
		return false
	}

	// PathRegex is anchored — see anchoredRegex comment in
	// MatchesSigstoreIdentity for rationale.
	var pathRegex *regexp.Regexp
	if id.GetPathRegex() != "" {
		re, err := regexp.Compile(anchoredRegex(id.GetPathRegex()))
		if err != nil {
			return false
		}
		pathRegex = re
	}

	for _, signer := range sv.GetIdentities() {
		signerSpiffe := signer.GetSpiffe()
		if signerSpiffe == nil {
			continue
		}
		if signerSpiffe.GetTrustDomain() != id.GetTrustDomain() {
			continue
		}
		switch {
		case id.GetPath() != "":
			if signerSpiffe.GetPath() != id.GetPath() {
				continue
			}
		case pathRegex != nil:
			if !pathRegex.MatchString(signerSpiffe.GetPath()) {
				continue
			}
		}
		return true
	}
	return false
}

// MatchesKeyIdentity returns true if one of the verified signatures was
// performed with the specified key. Matching rules:
//
//   - Id (required): compared against both the signer's primary key Id and
//     its signing subkey fingerprint — a policy can name a GPG identity by
//     either its primary or its signing subkey.
//   - Type (optional): narrows the match when both sides set it.
//   - SigningFingerprint (optional): additional pin requiring the signer's
//     subkey fingerprint to match exactly. Useful for policies that accept
//     a key's identity but constrain which subkey is authorized.
//
// Id and SigningFingerprint comparisons are case-insensitive since hex
// fingerprints appear in both cases in the wild. If the identity has Data
// but no Id, Normalize is called first to populate it.
func (sv *SignatureVerification) MatchesKeyIdentity(keyIdentity *IdentityKey) bool {
	ki := keyIdentity
	if ki.GetId() == "" && ki.GetData() != "" {
		cloned, ok := proto.Clone(keyIdentity).(*IdentityKey)
		if ok {
			_ = cloned.Normalize() //nolint:errcheck // best effort
			ki = cloned
		}
	}

	id := strings.TrimSpace(ki.GetId())
	keyType := strings.TrimSpace(ki.GetType())
	signingFP := strings.TrimSpace(ki.GetSigningFingerprint())

	// We need at least the key ID to match.
	if id == "" {
		return false
	}

	// Check each identity in the verification until one matches.
	for _, signer := range sv.GetIdentities() {
		signerKeyData := signer.GetKey()
		if signerKeyData == nil {
			continue
		}

		signerID := strings.TrimSpace(signerKeyData.GetId())
		signerSubFP := strings.TrimSpace(signerKeyData.GetSigningFingerprint())

		// Id matches either the signer's primary or its signing subkey.
		if !strings.EqualFold(id, signerID) && !strings.EqualFold(id, signerSubFP) {
			continue
		}

		if keyType != "" && strings.TrimSpace(signerKeyData.GetType()) != "" &&
			strings.TrimSpace(signerKeyData.GetType()) != keyType {
			continue
		}

		// When the policy additionally pins a signing subkey, the verified
		// identity must carry the same fingerprint.
		if signingFP != "" && !strings.EqualFold(signerSubFP, signingFP) {
			continue
		}

		// Match
		return true
	}
	return false
}
