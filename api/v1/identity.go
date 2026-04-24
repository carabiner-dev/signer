// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/x509"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/carabiner-dev/signer/key"
)

// NewIdentityFromPrincipal parses an Identity from its canonical principal
// string — a compact, self-describing name for the signer. Supported forms:
//
//	sigstore::<issuer>::<identity>
//	key::<type>::<id>
//	ref:<id>
//
// Round-trips with (*Identity).Principal.
func NewIdentityFromPrincipal(principal string) (*Identity, error) {
	itype, identityString, ok := strings.Cut(principal, "::")
	if !ok {
		refId, isRef := strings.CutPrefix(principal, "ref:")
		if isRef {
			return &Identity{Ref: &IdentityRef{Id: refId}}, nil
		}
	}

	switch itype {
	case "sigstore", "sigstore(regexp)":
		issuer, ident, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse sigstore identity from principal string")
		}
		mode := SigstoreModeExact
		if itype == "sigstore(regexp)" {
			mode = SigstoreModeRegexp
		}
		return &Identity{
			Sigstore: &IdentitySigstore{
				Mode:     &mode,
				Issuer:   issuer,
				Identity: ident,
			},
		}, nil
	case "key":
		keyType, keyId, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse key details from principal string")
		}
		return &Identity{
			Key: &IdentityKey{
				Id:   keyId,
				Type: keyType,
			},
		}, nil
	}
	return nil, fmt.Errorf("unable to parse identity from principal string")
}

// NewIdentityFromSlug is a compatibility alias for NewIdentityFromPrincipal.
//
// This will be deprecated: use NewIdentityFromPrincipal. Retained for existing callers.
func NewIdentityFromSlug(slug string) (*Identity, error) {
	return NewIdentityFromPrincipal(slug)
}

// Principal returns the canonical string naming this identity — the
// security-domain "principal" that uniquely identifies who signed.
// Round-trips with NewIdentityFromPrincipal.
func (i *Identity) Principal() string {
	switch {
	case i.GetSigstore() != nil:
		mode := ""
		if i.GetSigstore().GetMode() == SigstoreModeRegexp {
			mode = "(regexp)"
		}
		return fmt.Sprintf("sigstore%s::%s::%s", mode, i.GetSigstore().GetIssuer(), i.GetSigstore().GetIdentity())
	case i.GetKey() != nil:
		return fmt.Sprintf("key::%s::%s", i.GetKey().GetType(), i.GetKey().GetId())
	case i.GetRef() != nil:
		return fmt.Sprintf("ref:%s", i.GetRef().GetId())
	case i.GetSpiffe() != nil:
		// SPIFFE IDs are canonical URIs — the svid string IS the principal.
		return i.GetSpiffe().GetSvid()
	default:
		return ""
	}
}

// Slug is a compatibility alias for Principal.
//
// This will be deprecated: use Principal. Retained for existing callers.
func (i *Identity) Slug() string {
	return i.Principal()
}

// Validate checks the integrity of the identity and returns an error if
// fields are missing or invalid. Validates each variant's required fields,
// compiles regex patterns on legacy sigstore fields (when Mode=regexp)
// and on any StringMatcher regex/glob kinds, and checks spiffe svid parses
// as a valid SPIFFE ID — surfacing policy-authoring errors early rather
// than at match time.
func (i *Identity) Validate() error {
	errs := []error{}
	typesDefined := []string{}

	if i.GetSigstore() != nil {
		typesDefined = append(typesDefined, "sigstore")
		errs = append(errs, validateSigstore(i.GetSigstore())...)
	}

	if i.GetKey() != nil {
		typesDefined = append(typesDefined, "key")
		errs = append(errs, validateKey(i.GetKey())...)
	}

	if i.GetRef() != nil {
		typesDefined = append(typesDefined, "ref")
	}

	if i.GetSpiffe() != nil {
		typesDefined = append(typesDefined, "spiffe")
		errs = append(errs, validateSpiffe(i.GetSpiffe())...)
	}

	for idx, m := range i.GetMatchers() {
		if err := validateMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("matchers[%d]: %w", idx, err))
		}
	}

	if len(typesDefined) == 0 {
		errs = append(errs, errors.New("at least one type of identity must be set (sigstore, key, ref or spiffe)"))
	}

	if len(typesDefined) > 1 {
		errs = append(errs, fmt.Errorf("only one type of identity can be set at a time (got %v)", typesDefined))
	}
	return errors.Join(errs...)
}

// validateSigstore checks a sigstore identity's legacy fields + convenience
// matchers. Legacy Issuer/Identity as regex (Mode=regexp) are compiled up
// front so bad patterns surface at policy-load time.
func validateSigstore(s *IdentitySigstore) []error {
	var errs []error

	useLegacy := s.GetIssuer() != "" || s.GetIdentity() != ""
	useMatchers := s.GetIssuerMatch() != nil || s.GetIdentityMatch() != nil
	if !useLegacy && !useMatchers {
		errs = append(errs, errors.New("sigstore identity requires issuer, identity, issuer_match, or identity_match"))
	}
	if useLegacy && !useMatchers && (s.GetIssuer() == "" || s.GetIdentity() == "") {
		errs = append(errs, errors.New("sigstore legacy form requires both issuer and identity when matchers are not used"))
	}

	if s.GetMode() == SigstoreModeRegexp {
		if v := s.GetIssuer(); v != "" {
			if _, err := regexp.Compile(anchoredRegex(v)); err != nil {
				errs = append(errs, fmt.Errorf("sigstore issuer regex: %w", err))
			}
		}
		if v := s.GetIdentity(); v != "" {
			if _, err := regexp.Compile(anchoredRegex(v)); err != nil {
				errs = append(errs, fmt.Errorf("sigstore identity regex: %w", err))
			}
		}
	}

	if m := s.GetIssuerMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("issuer_match: %w", err))
		}
	}
	if m := s.GetIdentityMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("identity_match: %w", err))
		}
	}
	return errs
}

func validateKey(k *IdentityKey) []error {
	var errs []error
	if k.GetId() == "" && k.GetData() == "" && k.GetIdMatch() == nil {
		errs = append(errs, errors.New("key identity requires id, data, or id_match"))
	}
	if m := k.GetIdMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("id_match: %w", err))
		}
	}
	if m := k.GetTypeMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("type_match: %w", err))
		}
	}
	if m := k.GetSigningFingerprintMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("signing_fingerprint_match: %w", err))
		}
	}
	return errs
}

func validateSpiffe(s *IdentitySpiffe) []error {
	var errs []error
	if s.GetSvid() == "" &&
		s.GetSvidMatch() == nil &&
		s.GetTrustDomainMatch() == nil &&
		s.GetPathMatch() == nil {
		errs = append(errs, errors.New("spiffe identity requires svid, svid_match, trust_domain_match, or path_match"))
	}
	if v := s.GetSvid(); v != "" {
		if _, err := spiffeid.FromString(v); err != nil {
			errs = append(errs, fmt.Errorf("spiffe svid: %w", err))
		}
	}
	if m := s.GetSvidMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("svid_match: %w", err))
		}
	}
	if m := s.GetTrustDomainMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("trust_domain_match: %w", err))
		}
	}
	if m := s.GetPathMatch(); m != nil {
		if err := validateStringMatcher(m); err != nil {
			errs = append(errs, fmt.Errorf("path_match: %w", err))
		}
	}
	return errs
}

// validateMatcher checks an outer Matcher entry: field is required, the
// embedded kind is validated by its concrete type.
func validateMatcher(m *Matcher) error {
	if m.GetField() == "" {
		return errors.New("field is required")
	}
	switch kind := m.GetKind().(type) {
	case *Matcher_String_:
		if kind.String_ == nil {
			return errors.New("string matcher is nil")
		}
		return validateStringMatcher(kind.String_)
	case nil:
		return errors.New("matcher kind is not set")
	default:
		return fmt.Errorf("unsupported matcher kind %T", kind)
	}
}

// validateStringMatcher ensures regex patterns compile and glob patterns
// are well-formed. Exact/Prefix kinds have no format requirements.
func validateStringMatcher(m *StringMatcher) error {
	switch kind := m.GetKind().(type) {
	case *StringMatcher_Regex:
		pattern := anchoredRegex(kind.Regex)
		if m.GetCaseInsensitive() {
			pattern = "(?i)" + pattern
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("regex %q: %w", kind.Regex, err)
		}
	case *StringMatcher_Glob:
		if _, err := path.Match(kind.Glob, ""); err != nil {
			return fmt.Errorf("glob %q: %w", kind.Glob, err)
		}
	case *StringMatcher_Exact, *StringMatcher_Prefix:
		// no format to validate
	case nil:
		return errors.New("matcher kind is not set")
	default:
		return fmt.Errorf("unsupported string matcher kind %T", kind)
	}
	return nil
}

// IdentitySpiffeFromString parses a SPIFFE ID string (e.g.
// "spiffe://example.org/workload") into an IdentitySpiffe.
//
// TrustRoots is intentionally NOT populated — it is a verifier configuration
// (which root(s) the chain was validated against), not an attribute of the
// signer. Policy-side IdentitySpiffe values carry TrustRoots to tell the
// verifier what to trust; verified-side IdentitySpiffe values describe who
// signed.
func IdentitySpiffeFromString(spiffeID string) (*IdentitySpiffe, error) {
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parsing spiffe id: %w", err)
	}
	return &IdentitySpiffe{
		Svid: id.String(),
	}, nil
}

// IdentitySpiffeFromCert builds an IdentitySpiffe from a leaf certificate by
// extracting the SPIFFE ID from its URI SAN and then delegating to
// IdentitySpiffeFromString once the SAN is found. Useful when a caller has
// only the leaf (e.g. test fixtures or standalone cert inspection); when a
// VerificationResult is available, read the SAN from VerifiedIdentity and
// call IdentitySpiffeFromString directly.
func IdentitySpiffeFromCert(leaf *x509.Certificate) (*IdentitySpiffe, error) {
	if leaf == nil {
		return nil, errors.New("leaf certificate is nil")
	}
	for _, uri := range leaf.URIs {
		if uri.Scheme != "spiffe" {
			continue
		}
		return IdentitySpiffeFromString(uri.String())
	}
	return nil, errors.New("certificate has no spiffe:// URI SAN")
}

// IdentityKeyFromPublic builds an IdentityKey from a verified *key.Public.
// It copies the key Id, Scheme (as Type) and — critically for GPG — the
// SigningKeyFingerprint populated during verification, so the resulting
// IdentityKey names the actual signing (sub)key rather than just the
// primary/identity key.
func IdentityKeyFromPublic(pub *key.Public) *IdentityKey {
	if pub == nil {
		return nil
	}
	return &IdentityKey{
		Id:                 pub.ID(),
		Type:               string(pub.Scheme),
		SigningFingerprint: pub.SigningKeyFingerprint,
	}
}

// Normalize populates empty Type and Id fields by parsing the key Data.
// This ensures identities defined with only key material (e.g. a GPG
// key block) have their Id and Type resolved before matching.
func (ik *IdentityKey) Normalize() error {
	if ik.GetData() == "" {
		return nil
	}

	provider, err := key.NewParser().ParsePublicKeyProvider([]byte(ik.GetData()))
	if err != nil {
		return fmt.Errorf("parsing key data: %w", err)
	}

	pub, err := provider.PublicKey()
	if err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}

	if ik.GetType() == "" {
		ik.Type = string(pub.Scheme)
	}

	if ik.GetId() == "" {
		ik.Id = pub.ID()
	}

	return nil
}

// PublicKey returns the identity public key by parsing the data if set.
// It uses ParsePublicKeyProvider to preserve full key metadata (e.g. GPG
// key IDs and subkeys) required for PGP signature verification.
func (i *Identity) PublicKey() (key.PublicKeyProvider, error) {
	var data string
	if data = i.GetKey().GetData(); data == "" {
		return nil, nil
	}
	k, err := key.NewParser().ParsePublicKeyProvider([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	return k, nil
}
