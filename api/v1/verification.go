// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"regexp"
	"strings"

	"github.com/carabiner-dev/attestation"
	"google.golang.org/protobuf/proto"
)

// Ensure we are implementing the framworks verification
var _ attestation.Verification = (*Verification)(nil) //nolint:errcheck

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

	// If this is a regexp matcher, compile them
	var regIdentity, regIssuer *regexp.Regexp
	if id.Mode != nil && id.GetMode() == SigstoreModeRegexp {
		var err error
		regIdentity, err = regexp.Compile(id.GetIdentity())
		if err != nil {
			return false
		}
		regIssuer, err = regexp.Compile(id.GetIssuer())
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
