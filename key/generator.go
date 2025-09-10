// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

// Generator is a key generator that returns keys wrapped in our key wrappers.
// The key generator supports ECDSA, RSA and ED25519 and some basic options such
// as key length and defininig the elliptic curve to use.
type Generator struct{}

type GenerateOptions struct {
	Type         Type
	Curve        elliptic.Curve
	UseECMarshal bool
	KeyLength    int
}

// DefaultGenerateOptions default key generation options
var DefaultGenerateOptions = GenerateOptions{
	Type:      ECDSA,
	Curve:     elliptic.P256(),
	KeyLength: 4096,
}

type FnGenOpt func(*GenerateOptions) error

func WithKeyLength(l int) FnGenOpt {
	return func(o *GenerateOptions) error {
		if l < 1024 {
			return fmt.Errorf("invalid key length")
		}
		o.KeyLength = l
		return nil
	}
}

func WithEllipticCurve(cv elliptic.Curve) FnGenOpt {
	return func(o *GenerateOptions) error {
		o.Curve = cv
		return nil
	}
}

func WithKeyType(t Type) FnGenOpt {
	return func(o *GenerateOptions) error {
		o.Type = t
		return nil
	}
}

// GenerateKeyPair creates a new keypair
func (gen *Generator) GenerateKeyPair(funcs ...FnGenOpt) (*Private, error) {
	opts := DefaultGenerateOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	switch opts.Type {
	case ECDSA:
		privateKey, err := ecdsa.GenerateKey(opts.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ECDSA key: %w", err)
		}
		var data []byte
		if opts.UseECMarshal {
			privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
			if err != nil {
				log.Fatal(err)
			}

			data = pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: privateKeyBytes,
			})
		} else {
			data, err = marshalPrivateKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("marshaling provate key: %w ", err)
			}
		}

		return &Private{
			Type:     opts.Type,
			Scheme:   "",
			HashType: 0,
			Data:     string(data),
			Key:      privateKey,
		}, nil

	case RSA:
		privateKey, err := rsa.GenerateKey(rand.Reader, opts.KeyLength)
		if err != nil {
			return nil, fmt.Errorf("generating RSA key pair: %w", err)
		}

		privateKeyPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		data := pem.EncodeToMemory(privateKeyPEM)

		return &Private{
			Type:     opts.Type,
			Scheme:   "",
			HashType: 0,
			Data:     string(data),
			Key:      privateKey,
		}, nil

	case ED25519:
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating ed25519 key pair: %w", err)
		}

		data, err := marshalPrivateKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("marshaling ed25519 key: %w", err)
		}

		return &Private{
			Type:   ED25519,
			Scheme: Ed25519,
			Data:   string(data),
			Key:    privateKey,
		}, nil

	default:
		return nil, fmt.Errorf("key type not supported")
	}
}
