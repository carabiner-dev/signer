// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func NewParser() *Parser {
	return &Parser{}
}

type Parser struct{}

type KeyParseOptions struct {
	Scheme Scheme
}

type FnOpt func(*KeyParseOptions)

// WithScheme defines a scheme for a key.
func WithScheme(scheme Scheme) FnOpt {
	return func(kpo *KeyParseOptions) {
		kpo.Scheme = scheme
	}
}

// ParsePublicKey parses a public key that can be used to verify.
// It supports PEM-encoded keys (RSA, ECDSA, ED25519) and GPG keys
// (ASCII-armored or binary). For GPG keys the underlying crypto public
// key is extracted and returned as a *Public.
func (p *Parser) ParsePublicKey(pubKeyData []byte, funcs ...FnOpt) (*Public, error) {
	opts := KeyParseOptions{}
	for _, f := range funcs {
		f(&opts)
	}

	// Try PEM first
	k, pemErr := parseKeyBytes(pubKeyData)
	if pemErr != nil {
		// Try GPG (ASCII-armored or binary)
		gpgKeys, gpgErr := ParseGPGPublicKey(pubKeyData)
		if gpgErr != nil || len(gpgKeys) == 0 {
			return nil, fmt.Errorf("parsing public key: %w", pemErr)
		}
		var err error
		k, err = gpgKeys[0].PublicKey()
		if err != nil {
			return nil, fmt.Errorf("extracting public key from GPG data: %w", err)
		}
	}

	if opts.Scheme != "" {
		if err := k.SetScheme(opts.Scheme); err != nil {
			return nil, fmt.Errorf("setting key scheme: %w", err)
		}
	}
	return k, nil
}

// ParsePublicKeyProvider parses public key data and returns a PublicKeyProvider.
// It supports PEM-encoded keys (RSA, ECDSA, ED25519) and GPG keys (ASCII-armored
// or binary). For PEM keys the returned provider is a *Public; for GPG keys it
// is a *GPGPublic which preserves the full OpenPGP metadata.
func (p *Parser) ParsePublicKeyProvider(pubKeyData []byte, funcs ...FnOpt) (PublicKeyProvider, error) {
	opts := KeyParseOptions{}
	for _, f := range funcs {
		f(&opts)
	}

	// Try PEM first
	k, pemErr := parseKeyBytes(pubKeyData)
	if pemErr == nil {
		if opts.Scheme != "" {
			if err := k.SetScheme(opts.Scheme); err != nil {
				return nil, fmt.Errorf("setting key scheme: %w", err)
			}
		}
		return k, nil
	}

	// Try GPG (ASCII-armored or binary)
	gpgKeys, gpgErr := ParseGPGPublicKey(pubKeyData)
	if gpgErr == nil && len(gpgKeys) > 0 {
		return gpgKeys[0], nil
	}

	// Neither worked, return the PEM error as it's the most common format
	return nil, fmt.Errorf("parsing public key: %w", pemErr)
}

// parseKeyBytes is the parser function. It's a helper to expose it to tests.
func parseKeyBytes(pubKeyData []byte) (*Public, error) {
	blk, _ := pem.Decode(pubKeyData)
	if blk == nil || blk.Bytes == nil {
		return nil, errors.New("unable to decode key from data")
	}

	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key from PEM data: %w", err)
	}

	k := &Public{
		Data: string(pubKeyData),
		Key:  pub,
	}

	switch ik := pub.(type) {
	case *rsa.PublicKey:
		k.Type = RSA
		// Default to PKCS1v15 with SHA-256 for RSA keys. Without a HashType
		// the verifier panics when computing the message digest. We use
		// PKCS1v15 rather than PSS as the default because cosign and most
		// tooling sign with PKCS1v15. The verifier tries PKCS1v15 first
		// for non-PSS schemes, then falls back to PSS.
		k.HashType = crypto.SHA256
		k.Scheme = RsaPkcs1v15
	case *ecdsa.PublicKey:
		k.Type = ECDSA
		// We can infer the hash type from the elliptic curve in use. If it does
		// not match, verifications will not match but they would be insecure anyway
		switch ik.Curve.Params().Name {
		case elliptic.P224().Params().Name: // "P-256"
			k.HashType = crypto.SHA224
			k.Scheme = EcdsaSha2nistP224
		case elliptic.P256().Params().Name: // "P-256"
			k.HashType = crypto.SHA256
			k.Scheme = EcdsaSha2nistP256
		case elliptic.P384().Params().Name: // "P-384"
			k.HashType = crypto.SHA384
			k.Scheme = EcdsaSha2nistP384
		case elliptic.P521().Params().Name: // P-521
			k.HashType = crypto.SHA512
			k.Scheme = EcdsaSha2nistP521
		}
	case ed25519.PublicKey:
		k.Type = ED25519

	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}

	return k, nil
}
