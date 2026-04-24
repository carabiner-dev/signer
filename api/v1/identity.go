// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/carabiner-dev/signer/key"
)

// NewIdentityFromSlug returns a new identity by parsing a slug string.
//
// There are three kinds of identities supported: sigstore, key and reference.
func NewIdentityFromSlug(slug string) (*Identity, error) {
	itype, identityString, ok := strings.Cut(slug, "::")
	if !ok {
		refId, isRef := strings.CutPrefix(slug, "ref:")
		if isRef {
			return &Identity{Ref: &IdentityRef{Id: refId}}, nil
		}
	}

	switch itype {
	case "sigstore", "sigstore(regexp)":
		issuer, ident, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse sigstore identity from identity string")
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
			return nil, fmt.Errorf("unable to parse key details from identity string")
		}
		return &Identity{
			Key: &IdentityKey{
				Id:   keyId,
				Type: keyType,
			},
		}, nil
	}
	return nil, fmt.Errorf("unable to parse identity from slug string")
}

// Slug returns a string representing the identity
func (i *Identity) Slug() string {
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
	default:
		return ""
	}
}

// Validate checks the integrity of the identity and returns an error if
// fields are missing or invalid
func (i *Identity) Validate() error {
	errs := []error{}
	typesDefined := []string{}
	if i.GetSigstore() != nil {
		typesDefined = append(typesDefined, "sigstore")
		if i.GetSigstore().GetIssuer() == "" {
			errs = append(errs, fmt.Errorf("sigstore identity has no issuer defined"))
		}

		if i.GetSigstore().GetIdentity() == "" {
			errs = append(errs, fmt.Errorf("sigstore identity has no identifier (email/account) defined"))
		}
	}

	if i.GetKey() != nil {
		typesDefined = append(typesDefined, "key")
		if i.GetKey().GetId() == "" && i.GetKey().GetData() == "" {
			errs = append(errs, errors.New("key identity has to have either id or data set"))
		}
	}

	if i.GetRef() != nil {
		typesDefined = append(typesDefined, "ref")
	}

	if len(typesDefined) == 0 {
		errs = append(errs, errors.New("at least one type of identity must be set (sigstore, key or ref)"))
	}

	if len(typesDefined) > 1 {
		errs = append(errs, fmt.Errorf("only one type of identity can be set at a time (got %v)", typesDefined))
	}
	return errors.Join(errs...)
}

// IdentitySpiffeFromString parses a SPIFFE ID string (e.g.
// "spiffe://example.org/workload") into an IdentitySpiffe populated with the
// parsed trust domain and path. This is the primary helper for turning the
// SPIFFE ID a verifier surfaces in its VerificationResult (via
// VerifiedIdentity.SubjectAlternativeName) into an api/v1 identity value
// suitable for SignatureVerification.Identities.
//
// TrustRoots is intentionally NOT populated — it is verifier configuration
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
		TrustDomain: id.TrustDomain().Name(),
		Path:        id.Path(),
	}, nil
}

// IdentitySpiffeFromCert builds an IdentitySpiffe from a leaf certificate by
// extracting the SPIFFE ID from its URI SAN. Delegates to
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
