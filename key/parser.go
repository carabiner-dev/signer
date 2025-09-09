// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
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
func (p *Parser) ParsePublicKey(pubKeyData []byte) (crypto.PublicKey, error) {
	return parseKeyBytes(pubKeyData)
}

// parseKeyBytes is the parser function. It's a helper to expose it to tests.
func parseKeyBytes(pubKeyData []byte) (crypto.PublicKey, error) {
	blk, _ := pem.Decode(pubKeyData)
	if blk == nil || blk.Bytes == nil {
		return nil, errors.New("unable to decode key from data")
	}

	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key from PEM data: %w", err)
	}

	switch pub.(type) {
	case *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey,
		ed25519.PublicKey, *ecdh.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}
}
