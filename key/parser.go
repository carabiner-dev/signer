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
	"fmt"

	"github.com/pkg/errors"
)

func NewParser() *Parser {
	return &Parser{}
}

type Parser struct{}

// ParsePublicKey parses a public key that can be used to verify
func (p *Parser) ParsePublicKey(scheme Scheme, pubKeyData []byte) (*Public, error) {
	return parseKeyBytes(pubKeyData)
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
