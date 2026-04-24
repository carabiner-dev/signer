// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"path"
	"regexp"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
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

// MatchesSigstoreIdentity returns true if one of the verified signatures
// matches the supplied sigstore identity. Matching rules:
//
//   - Legacy fields (Issuer + Identity + Mode): when used, BOTH Issuer
//     and Identity must be set. Mode chooses literal-equality or
//     (anchored) regex semantics for the pair. Both must match.
//   - Convenience matchers (IssuerMatch / IdentityMatch): independent
//     StringMatchers layered on top. Each, when set, must pass.
//   - Legacy and convenience forms may be combined — all constraints
//     that are set must match the signer (AND semantics).
//
// A policy that sets NO constraint across either path matches nothing.
// A policy that sets exactly one legacy field (Issuer OR Identity but
// not both) is treated as malformed and matches nothing, preserving the
// previous "both required" contract for legacy-only policies.
func (sv *SignatureVerification) MatchesSigstoreIdentity(id *IdentitySigstore) bool {
	// Old style matching way: The regexp is in the Identity and Isuser
	issuerLegacy := id.GetIssuer()
	identityLegacy := id.GetIdentity()

	// New (v0.5+) matcher fields
	issuerMatch := id.GetIssuerMatch()
	identityMatch := id.GetIdentityMatch()

	useLegacy := issuerLegacy != "" || identityLegacy != ""
	useMatchers := issuerMatch != nil || identityMatch != nil
	if !useLegacy && !useMatchers {
		return false
	}
	// Preserve the legacy "both required" rule when ONLY legacy fields
	// are used — a half-specified policy is very likely a mistake.
	if useLegacy && (issuerLegacy == "" || identityLegacy == "") && !useMatchers {
		return false
	}

	// Precompile legacy regex patterns once. The anchoredRegex wrap
	// forces a full-input match so a pattern meant to pin a specific
	// identity can't match via substring/prefix collision.
	var regIssuer, regIdentity *regexp.Regexp
	if id.GetMode() == SigstoreModeRegexp {
		if issuerLegacy != "" {
			re, err := regexp.Compile(anchoredRegex(issuerLegacy))
			if err != nil {
				return false
			}
			regIssuer = re
		}
		if identityLegacy != "" {
			re, err := regexp.Compile(anchoredRegex(identityLegacy))
			if err != nil {
				return false
			}
			regIdentity = re
		}
	}
	regexpMode := id.GetMode() == SigstoreModeRegexp

	for _, signer := range sv.GetIdentities() {
		ss := signer.GetSigstore()
		if ss == nil {
			continue
		}
		signerIssuer := ss.GetIssuer()
		signerIdentity := ss.GetIdentity()

		// Legacy issuer
		if issuerLegacy != "" {
			if regexpMode {
				if !regIssuer.MatchString(signerIssuer) {
					continue
				}
			} else if signerIssuer != issuerLegacy {
				continue
			}
		}
		// Legacy identity
		if identityLegacy != "" {
			if regexpMode {
				if !regIdentity.MatchString(signerIdentity) {
					continue
				}
			} else if signerIdentity != identityLegacy {
				continue
			}
		}
		// Convenience matchers (layered on)
		if issuerMatch != nil && !matchString(issuerMatch, signerIssuer) {
			continue
		}
		if identityMatch != nil && !matchString(identityMatch, signerIdentity) {
			continue
		}
		return true
	}
	return false
}

// MatchesSpiffeIdentity returns true if one of the verified signatures was
// produced by a SPIFFE workload matching the supplied identity. Matching
// rules:
//
//   - Svid (optional, exact): when set, the signer's svid must match this
//     URI exactly.
//   - SvidMatch (optional): StringMatcher applied to the full signer
//     svid URI.
//   - TrustDomainMatch / PathMatch (optional): StringMatchers applied to
//     the trust-domain / path components parsed from the signer's svid
//     at eval time. If the signer's svid doesn't parse as a valid SPIFFE
//     ID, these matchers fail closed.
//   - TrustRoots is not consulted here — it is policy configuration used
//     by the verifier to validate the chain, not an attribute of the
//     signer.
//
// All conditions that are set must pass (AND semantics). At least one
// constraint must be specified; an identity with none of svid, svid_match,
// trust_domain_match, or path_match set matches nothing.
func (sv *SignatureVerification) MatchesSpiffeIdentity(id *IdentitySpiffe) bool {
	hasConstraint := id.GetSvid() != "" ||
		id.GetSvidMatch() != nil ||
		id.GetTrustDomainMatch() != nil ||
		id.GetPathMatch() != nil
	if !hasConstraint {
		return false
	}

	needsParsed := id.GetTrustDomainMatch() != nil || id.GetPathMatch() != nil

	for _, signer := range sv.GetIdentities() {
		signerSpiffe := signer.GetSpiffe()
		if signerSpiffe == nil {
			continue
		}
		signerSvid := signerSpiffe.GetSvid()

		if want := id.GetSvid(); want != "" && signerSvid != want {
			continue
		}
		if m := id.GetSvidMatch(); m != nil && !matchString(m, signerSvid) {
			continue
		}

		if needsParsed {
			parsed, err := spiffeid.FromString(signerSvid)
			if err != nil {
				continue
			}
			if m := id.GetTrustDomainMatch(); m != nil && !matchString(m, parsed.TrustDomain().Name()) {
				continue
			}
			if m := id.GetPathMatch(); m != nil && !matchString(m, parsed.Path()) {
				continue
			}
		}

		return true
	}
	return false
}

// matchString evaluates a StringMatcher against value. An unset matcher
// matches any value (caller-controlled guard).
func matchString(m *StringMatcher, value string) bool {
	if m == nil {
		return true
	}
	switch kind := m.GetKind().(type) {
	case *StringMatcher_Exact:
		if m.GetCaseInsensitive() {
			return strings.EqualFold(kind.Exact, value)
		}
		return kind.Exact == value
	case *StringMatcher_Regex:
		pattern := anchoredRegex(kind.Regex)
		if m.GetCaseInsensitive() {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case *StringMatcher_Prefix:
		if m.GetCaseInsensitive() {
			return strings.HasPrefix(strings.ToLower(value), strings.ToLower(kind.Prefix))
		}
		return strings.HasPrefix(value, kind.Prefix)
	case *StringMatcher_Glob:
		target := value
		pattern := kind.Glob
		if m.GetCaseInsensitive() {
			target = strings.ToLower(target)
			pattern = strings.ToLower(pattern)
		}
		ok, err := path.Match(pattern, target)
		return err == nil && ok
	default:
		return false
	}
}

// MatchesKeyIdentity returns true if one of the verified signatures was
// performed with the specified key. Matching rules:
//
//   - Id (required via legacy field OR IdMatch): compared against both
//     the signer's primary key Id and its signing subkey fingerprint —
//     a policy can name a GPG identity by either. Legacy Id is
//     case-insensitive; IdMatch follows its StringMatcher configuration.
//   - Type (optional, legacy): narrows the match when both sides set it.
//     An unset signer type skips the check. TypeMatch (new) is strict:
//     when set, the signer's type must satisfy it.
//   - SigningFingerprint (optional, legacy): case-insensitive exact pin.
//     SigningFingerprintMatch (new) is strict when set.
//
// If the identity has Data but no Id, Normalize is called first.
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
	idMatch := ki.GetIdMatch()
	typeMatch := ki.GetTypeMatch()
	sfpMatch := ki.GetSigningFingerprintMatch()

	// Need at least an id dimension from somewhere.
	if id == "" && idMatch == nil {
		return false
	}

	for _, signer := range sv.GetIdentities() {
		signerKeyData := signer.GetKey()
		if signerKeyData == nil {
			continue
		}

		signerID := strings.TrimSpace(signerKeyData.GetId())
		signerSubFP := strings.TrimSpace(signerKeyData.GetSigningFingerprint())
		signerType := strings.TrimSpace(signerKeyData.GetType())

		// Legacy Id: case-insensitive primary-or-subkey.
		if id != "" {
			if !strings.EqualFold(id, signerID) && !strings.EqualFold(id, signerSubFP) {
				continue
			}
		}
		// IdMatch: apply against primary OR subkey fingerprint; accept
		// if either passes. Preserves the legacy Id disjunction semantic
		// for callers that moved to the matcher form.
		if idMatch != nil && !matchString(idMatch, signerID) && !matchString(idMatch, signerSubFP) {
			continue
		}

		// Legacy Type: narrows only when both sides set the field.
		if keyType != "" && signerType != "" && signerType != keyType {
			continue
		}
		// TypeMatch: strict — when set, the signer's type must satisfy it
		// regardless of whether the signer has a type at all.
		if typeMatch != nil && !matchString(typeMatch, signerType) {
			continue
		}

		// Legacy SigningFingerprint: case-insensitive exact pin.
		if signingFP != "" && !strings.EqualFold(signerSubFP, signingFP) {
			continue
		}
		// SigningFingerprintMatch: strict when set.
		if sfpMatch != nil && !matchString(sfpMatch, signerSubFP) {
			continue
		}

		return true
	}
	return false
}
