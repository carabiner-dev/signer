// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
)

// Private abstracts a private key use mainly to sign.
type Private struct {
	Type     Type
	Scheme   Scheme
	HashType crypto.Hash
	Data     string
	Key      crypto.PublicKey
}

// ID computes a key id by hashing the key data and triming it to the first 8 bytes
func (p *Private) ID() string {
	var hash [32]byte
	pub, err := p.PublicKey()
	if err != nil {
		return ""
	}
	switch pubKey := pub.Key.(type) {
	case *rsa.PublicKey:
		hash = sha256.Sum256(pubKey.N.Bytes())
	case *ecdsa.PublicKey:
		coords := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)
		hash = sha256.Sum256(coords)
		return hex.EncodeToString(hash[:8])
	case ed25519.PublicKey:
		hash = sha256.Sum256(pubKey)
	default:
		return ""
	}
	return hex.EncodeToString(hash[:8])
}

// PublicKey derives the public key from the provate one and returns a Public
// abstraction that can be used to verify signed things.
func (p *Private) PublicKey() (*Public, error) {
	if p.Key == nil {
		return nil, fmt.Errorf("private key undefined")
	}

	switch pk := p.Key.(type) {
	case *rsa.PrivateKey:
		public := pk.PublicKey

		// Encode public key to PEM format (PKCS#1)
		publicKeyBytes := x509.MarshalPKCS1PublicKey(&public)

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		return &Public{
			Type:     RSA,
			Scheme:   p.Scheme,
			HashType: p.HashType,
			Data:     string(publicKeyPEM),
			Key:      &public,
		}, nil
	case *ecdsa.PrivateKey:
		public := pk.PublicKey

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&public)
		if err != nil {
			return nil, err
		}

		pemEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		return &Public{
			Type:     ECDSA,
			Scheme:   p.Scheme,
			HashType: p.HashType,
			Data:     string(pemEncoded),
			Key:      &public,
		}, nil

	case ed25519.PrivateKey:
		derivedPublicKey, ok := pk.Public().(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("unable to cast public key")
		}

		marshaledKey, err := x509.MarshalPKIXPublicKey(derivedPublicKey)
		if err != nil {
			return nil, err
		}

		pemEncoded := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: marshaledKey,
		})

		return &Public{
			Type:   ED25519,
			Scheme: Ed25519,
			Data:   string(pemEncoded),
			Key:    derivedPublicKey,
		}, nil
	default:
		return nil, errors.New("unsupported private key type")
	}
}

// PrivateKey implements the PrivateKeyProvider interface
func (p *Private) PrivateKey() (*Private, error) {
	if p == nil {
		return nil, fmt.Errorf("private key not set")
	}
	return p, nil
}

type PrivateKeyProvider interface {
	PrivateKey() (*Private, error)
}

func marshalPrivateKey(k crypto.PrivateKey) ([]byte, error) {
	// Encode private key to PEM format (PKCS#8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}
