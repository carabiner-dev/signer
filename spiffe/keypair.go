// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

var _ sign.Keypair = (*svidKeypair)(nil)

// svidKeypair satisfies sign.Keypair by delegating to the current X.509-SVID
// from the injected source. Signing uses the SVID private key; key material
// is refreshed on every call so SVID rotation is transparent.
type svidKeypair struct {
	source x509svid.Source
}

// GetHashAlgorithm returns SHA-256 for ECDSA/RSA SVIDs and SHA_UNSPECIFIED
// for Ed25519 (which signs the raw message). Picked from the SVID's leaf.
func (k *svidKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	pub := k.publicKey()
	if _, ok := pub.(ed25519.PublicKey); ok {
		return protocommon.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
	}
	return protocommon.HashAlgorithm_SHA2_256
}

// GetSigningAlgorithm maps the SVID leaf's public key to the corresponding
// protocommon.PublicKeyDetails. Unknown combinations return UNSPECIFIED.
func (k *svidKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	switch pub := k.publicKey().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
		case elliptic.P384():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
		case elliptic.P521():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512
		}
	case *rsa.PublicKey:
		// crypto.Signer defaults to PKCS1v15 when opts is a crypto.Hash,
		// which is what SignData below uses, so advertise the matching
		// PKCS1v15 algorithms.
		switch pub.Size() * 8 {
		case 2048:
			return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256
		case 3072:
			return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256
		case 4096:
			return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256
		}
	case ed25519.PublicKey:
		return protocommon.PublicKeyDetails_PKIX_ED25519
	}
	return protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED
}

// GetHint returns a stable, opaque identifier for the SVID public key,
// matching sigstore-go's base64(sha256(DER(PKIX))) convention.
func (k *svidKeypair) GetHint() []byte {
	pub := k.publicKey()
	if pub == nil {
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(der)
	return []byte(base64.StdEncoding.EncodeToString(sum[:]))
}

// GetKeyAlgorithm maps the SVID public key type to the string tokens used
// by sigstore-go's Fulcio client. Mirrors EphemeralKeypair's mapping for
// consistency; Fulcio isn't called on the SPIFFE path.
func (k *svidKeypair) GetKeyAlgorithm() string {
	switch k.publicKey().(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey:
		return "ED25519"
	}
	return ""
}

// GetPublicKey returns the SVID leaf public key.
func (k *svidKeypair) GetPublicKey() crypto.PublicKey { return k.publicKey() }

// GetPublicKeyPem PEM-encodes the SVID leaf public key.
func (k *svidKeypair) GetPublicKeyPem() (string, error) {
	pub := k.publicKey()
	if pub == nil {
		return "", errors.New("svid has no certificates")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// SignData signs the data with the current SVID private key. For ECDSA and
// RSA, data is hashed with SHA-256 first; for Ed25519, the raw data is
// signed. Returns (signature, dataToSign) matching sigstore-go's
// EphemeralKeypair contract.
func (k *svidKeypair) SignData(_ context.Context, data []byte) (signature, signed []byte, err error) {
	svid, err := k.source.GetX509SVID()
	if err != nil {
		return nil, nil, fmt.Errorf("fetching svid: %w", err)
	}
	if svid.PrivateKey == nil {
		return nil, nil, errors.New("svid has no private key")
	}

	if _, ok := svid.PrivateKey.Public().(ed25519.PublicKey); ok {
		sig, err := svid.PrivateKey.Sign(rand.Reader, data, crypto.Hash(0))
		if err != nil {
			return nil, nil, fmt.Errorf("signing with svid private key: %w", err)
		}
		return sig, data, nil
	}

	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	sig, signErr := svid.PrivateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if signErr != nil {
		return nil, nil, fmt.Errorf("signing with svid private key: %w", signErr)
	}
	return sig, digest, nil
}

// publicKey returns the SVID leaf public key, or nil if the source has no
// SVID yet. Used by the accessor methods that can't return an error.
func (k *svidKeypair) publicKey() crypto.PublicKey {
	svid, err := k.source.GetX509SVID()
	if err != nil || len(svid.Certificates) == 0 {
		return nil
	}
	return svid.Certificates[0].PublicKey
}
