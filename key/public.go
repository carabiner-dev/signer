// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnknownScheme          = errors.New("unknown key scheme")
	ErrIncorrectKeySchema     = errors.New("unable to set key scheme, incorrect key type")
	ErrIncorrectEllipticCurve = errors.New("schema curve does not match key")
	ErrUnknownEllipticCurve   = errors.New("unsupported elliptic curve")
)

type (
	Scheme string
	Type   string
)

const (
	RSA     Type = "rsa"
	ECDSA   Type = "ecdsa"
	ED25519 Type = "ed25519"

	RsaSsaPssSha256     Scheme = "rsassa-pss-sha256"
	RsaSsaPssSha384     Scheme = "rsassa-pss-sha384"
	RsaSsaPssSha512     Scheme = "rsassa-pss-sha512"
	EcdsaSha2nistP224   Scheme = "ecdsa-sha2-nistp224"
	EcdsaSha2nistP256   Scheme = "ecdsa-sha2-nistp256"
	EcdsaSha2nistP384   Scheme = "ecdsa-sha2-nistp384"
	EcdsaSha2nistP521   Scheme = "ecdsa-sha2-nistp521"
	EcdsaSha256nistP256 Scheme = "ecdsa-sha256-nistp256"
	EcdsaSha384nistP384 Scheme = "ecdsa-sha384-nistp384"
	Ed25519             Scheme = "ed25519"
)

// Public key abstracts a public key data and all its features required to
// verify. After parsing, the original key data is preserved in the srtuct.
type Public struct {
	Type     Type
	Scheme   Scheme
	HashType crypto.Hash
	Data     string
	Key      crypto.PublicKey
}

// SetScheme sets the scheme string in the key, verifying consistency and defining
// some features of the key.
func (p *Public) SetScheme(scheme Scheme) error {
	if scheme == "" {
		return fmt.Errorf("scheme string is empty")
	}

	// Ed25519 has no hashes or curves
	if scheme == Ed25519 {
		return nil
	}

	switch {
	case strings.HasPrefix(string(scheme), "rsassa-pss"):
		if p.Type != RSA {
			return ErrIncorrectKeySchema
		}

		switch strings.TrimPrefix(string(scheme), "rsassa-pss-") {
		case "sha256":
			p.HashType = crypto.SHA256
		case "sha384":
			p.HashType = crypto.SHA384
		case "sha512":
			p.HashType = crypto.SHA512
		default:
			return ErrUnknownScheme
		}
	case strings.HasPrefix(string(scheme), "ecdsa-sha2-"):
		if p.Type != ECDSA {
			return ErrIncorrectKeySchema
		}

		switch p.Curve() {
		case elliptic.P224().Params().Name: // "P-224"
			if scheme != EcdsaSha2nistP224 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA224
		case elliptic.P256().Params().Name: // "P-256"
			if scheme != EcdsaSha2nistP256 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA256
		case elliptic.P384().Params().Name: // "P-384"
			if scheme != EcdsaSha2nistP384 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA384
		case elliptic.P521().Params().Name: // P-521
			if scheme != EcdsaSha2nistP521 {
				return ErrIncorrectEllipticCurve
			}
			p.HashType = crypto.SHA512
		default:
			return ErrUnknownEllipticCurve
		}
	default:
		return ErrUnknownScheme
	}

	p.Scheme = scheme
	return nil
}

// Curve returns the nist name of elliptic curve used in the key. If it cannot
// be read or the key is not an elliptic curve key then this function returns an
// empty string.
func (p *Public) Curve() string {
	if p.Type != ECDSA {
		return ""
	}

	if k, ok := p.Key.(*ecdsa.PublicKey); ok {
		return k.Curve.Params().Name
	}

	return ""
}
