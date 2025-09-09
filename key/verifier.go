// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/pkg/errors"
)

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

type Public struct {
	Scheme Scheme
	Data   string
	Key    crypto.PublicKey
}

type Scheme string

const (
	RsaSsaPssSha256     Scheme = "rsassa-pss-sha256"
	RsaSsaPssSha384     Scheme = "rsassa-pss-sha384"
	RsaSsaPssSha512     Scheme = "rsassa-pss-sha512"
	EcdsaSha2nistP224   Scheme = "ecdsa-sha2-nistp224"
	EcdsaSha2nistP256   Scheme = "ecdsa-sha2-nistp256"
	EcdsaSha2nistP384   Scheme = "ecdsa-sha2-nistp384"
	EcdsaSha2nistP521   Scheme = "ecdsa-sha2-nistp521"
	EcdsaSha256nistP256 Scheme = "ecdsa-sha256-nistp256"
	EcdsaSha384nistP384 Scheme = "ecdsa-sha384-nistp384"
	Ed25519             Scheme = "ed2551956"
)

// VerifyMessage verifies the signature by getting the whole message
func (v *Verifier) VerifyMessage(pubKey crypto.PublicKey, message []byte, signature []byte) (bool, error) {
	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		var hashType crypto.Hash
		switch k.Curve.Params().Name {
		case elliptic.P256().Params().Name: // "P-256"
			hashType = crypto.SHA256
		case elliptic.P384().Params().Name: // "P-384"
			hashType = crypto.SHA384
		case elliptic.P521().Params().Name: // P-521
			hashType = crypto.SHA512
		}

		sum := hashType.New().Sum(message)
		return verifyECDSA(k, hashType, sum, signature)
	case *rsa.PublicKey:
		return verifyRSA(k, hashType, sum, signature)
	case ed25519.PublicKey:
		return verifyEd25519Message(k, message, signature)
	case *ecdh.PublicKey:
		return false, fmt.Errorf("key type not yet supported: %T", pubKey)
	default:
		// *dsa.PublicKey is deprectated, we don't support it. Also ecdh keys
		return false, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

func (v *Verifier) VerifyDigest(pubKey crypto.PublicKey, digestString string, signature []byte) (bool, error) {
	// Parse the digest string
	algo, digestValue, ok := strings.Cut(digestString, ":")
	if !ok {
		return false, errors.New("digest string not well formed")
	}
	sum, err := hex.DecodeString(digestValue)
	if err != nil {
		return false, fmt.Errorf("decoding digest: %w", err)
	}

	// TODO(puerco): This probably belongs in the hasher package
	var hashType crypto.Hash
	// Create the hasher from the label
	switch strings.ToLower(algo) {
	case "sha1", "gitCommit":
		hashType = crypto.SHA1
	case "sha256":
		hashType = crypto.SHA256
	case "sha512":
		hashType = crypto.SHA512
	default:
		return false, fmt.Errorf("unable to build hasher from %q", algo)
	}

	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(k, hashType, sum, signature)
	case *rsa.PublicKey:
		return verifyRSA(k, hashType, sum, signature)
	case ed25519.PublicKey:
		return false, errors.New("cannot verify ed25519 signatures from hash")
	case *ecdh.PublicKey:
		return false, fmt.Errorf("key type not yet supported: %T", pubKey)
	default:
		// *dsa.PublicKey is deprectated, we don't support it. Also ecdh keys
		return false, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}

type signatureValues struct {
	R, S *big.Int
}

// verifyRSA verifies RSA using PSS
func verifyRSA(pubKey *rsa.PublicKey, hashType crypto.Hash, digest []byte, signature []byte) (bool, error) {
	pssOptions := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hashType,
	}

	if err := rsa.VerifyPKCS1v15(pubKey, hashType, digest, signature); err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, err
	}

	if err := rsa.VerifyPSS(pubKey, hashType, digest, signature, pssOptions); err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// verifyECDSA
func verifyECDSA(pubKey *ecdsa.PublicKey, hashType crypto.Hash, digest []byte, signature []byte) (bool, error) {
	// Ensure the curves matche the algos as per FIPS 186-4
	curveName := pubKey.Curve.Params().Name
	var curveErr = errors.New("invalid curve in public key")
	switch hashType {
	case crypto.SHA256:
		if curveName != elliptic.P256().Params().Name { // "P-256"
			return false, curveErr
		}
	case crypto.SHA384:
		if curveName != elliptic.P384().Params().Name { // "P-384"
			return false, curveErr
		}
	case crypto.SHA512:
		if curveName != elliptic.P521().Params().Name { // "P-521"
			return false, curveErr
		}
	default:
		return false, fmt.Errorf("unsupported ECDSA configuration: curve %s with hash %v", curveName, hashType)
	}

	// Parse the DER encoded signature
	var sig signatureValues
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return false, fmt.Errorf("unmarshaling ECDSA signature: %w", err)
	}

	// Verify the signature
	return ecdsa.Verify(pubKey, digest, sig.R, sig.S), nil
}

// verifyEd25519 verifies an Ed25519 signature
func verifyEd25519Message(pubKey ed25519.PublicKey, message []byte, signature []byte) (bool, error) {
	// Signature must be 64 bytes long
	if len(signature) != ed25519.SignatureSize {
		return false, errors.New("invalid ed25519 signature length")
	}

	// Key must be 32 bytes, always
	if len(pubKey) != ed25519.PublicKeySize {
		return false, errors.New("invalid ed25519 key length")
	}

	// Verify the signature (Ed25519 doesn't require separate hashing)
	valid := ed25519.Verify(pubKey, message, signature)

	return valid, nil
}
