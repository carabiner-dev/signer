// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// SignerKeypairOptions configures a SignerKeypair.
type SignerKeypairOptions struct {
	// Hint is the optional public-key fingerprint sent to Fulcio. When empty a
	// base64-encoded SHA-256 hash of the DER-encoded public key is used, exactly
	// like sigstore-go's EphemeralKeypair.
	Hint []byte

	// Algorithm selects the signing algorithm. Defaults to ECDSA P-256 SHA-256.
	Algorithm protocommon.PublicKeyDetails
}

// SignerKeypair adapts a caller-provided crypto.Signer to the sigstore-go
// sign.Keypair interface. Unlike sign.EphemeralKeypair — which generates its
// private key internally and never exposes it — SignerKeypair signs with a key
// the caller owns and keeps. That is what lets CertifiedKey hand the private key
// back so callers can build a detached CMS/PKCS7 signature (e.g. a signed git
// tag) with the same keyless identity the signer uses.
type SignerKeypair struct {
	options    SignerKeypairOptions
	signer     crypto.Signer
	algDetails signature.AlgorithmDetails
}

// Assert that SignerKeypair implements the sigstore-go keypair interface.
var _ sign.Keypair = (*SignerKeypair)(nil)

// NewSignerKeypair wraps signer in a sign.Keypair. When opts is nil the keypair
// defaults to ECDSA P-256 SHA-256 with a SHA-256 public-key hint. The logic
// mirrors sign.NewEphemeralKeypair, but signs with the provided key instead of a
// freshly generated one.
func NewSignerKeypair(signer crypto.Signer, opts *SignerKeypairOptions) (*SignerKeypair, error) {
	if signer == nil {
		return nil, errors.New("crypto.Signer must not be nil")
	}

	options := SignerKeypairOptions{}
	if opts != nil {
		options = *opts
	}

	// Default signing algorithm is ECDSA P-256 SHA-256.
	if options.Algorithm == protocommon.PublicKeyDetails_PUBLIC_KEY_DETAILS_UNSPECIFIED {
		options.Algorithm = protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
	}
	algDetails, err := signature.GetAlgorithmDetails(options.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("resolving algorithm details: %w", err)
	}

	if options.Hint == nil {
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
		if err != nil {
			return nil, fmt.Errorf("marshaling public key for hint: %w", err)
		}
		hashedBytes := sha256.Sum256(pubKeyBytes)
		options.Hint = []byte(base64.StdEncoding.EncodeToString(hashedBytes[:]))
	}

	return &SignerKeypair{
		options:    options,
		signer:     signer,
		algDetails: algDetails,
	}, nil
}

// GetHashAlgorithm returns the hash algorithm used to compute the digest to sign.
func (k *SignerKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.algDetails.GetProtoHashType()
}

// GetSigningAlgorithm returns the signing algorithm of the key.
func (k *SignerKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.algDetails.GetSignatureAlgorithm()
}

// GetHint returns the fingerprint of the public key.
func (k *SignerKeypair) GetHint() []byte {
	return k.options.Hint
}

// GetKeyAlgorithm returns the top-level key algorithm, used as part of requests
// to Fulcio.
func (k *SignerKeypair) GetKeyAlgorithm() string {
	switch k.algDetails.GetKeyType() {
	case signature.ECDSA:
		return "ECDSA"
	case signature.RSA:
		return "RSA"
	case signature.ED25519:
		return "ED25519"
	default:
		return ""
	}
}

// GetPublicKey returns the public key.
func (k *SignerKeypair) GetPublicKey() crypto.PublicKey {
	return k.signer.Public()
}

// GetPublicKeyPem returns the public key in PEM format.
func (k *SignerKeypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	if err != nil {
		return "", fmt.Errorf("marshaling public key to PEM: %w", err)
	}
	return string(pubKeyBytes), nil
}

// SignData returns the signature and the data that was signed (a digest, except
// for pure Ed25519). It mirrors sign.EphemeralKeypair.SignData over the provided
// key.
func (k *SignerKeypair) SignData(_ context.Context, data []byte) (sig, digest []byte, err error) {
	hf := k.algDetails.GetHashType()
	dataToSign := data
	// RSA, ECDSA, and Ed25519ph sign a digest, while pure Ed25519 hashes the
	// data itself during signing.
	if hf != crypto.Hash(0) {
		hasher := hf.New()
		hasher.Write(data)
		dataToSign = hasher.Sum(nil)
	}
	signed, err := k.signer.Sign(rand.Reader, dataToSign, hf)
	if err != nil {
		return nil, nil, fmt.Errorf("signing data: %w", err)
	}
	return signed, dataToSign, nil
}
