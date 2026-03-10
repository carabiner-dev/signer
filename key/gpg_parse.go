// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"bytes"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// ParseGPGPublicKey reads OpenPGP public key data (auto-detects ASCII armor vs binary)
// and returns one GPGPublic per entity found.
func ParseGPGPublicKey(data []byte) ([]*GPGPublic, error) {
	entities, err := readEntities(data)
	if err != nil {
		return nil, fmt.Errorf("reading GPG public key data: %w", err)
	}

	result := make([]*GPGPublic, 0, len(entities))
	for _, e := range entities {
		result = append(result, newGPGPublic(e))
	}
	return result, nil
}

// ParseGPGPrivateKey reads OpenPGP private key data, decrypts with passphrase if provided,
// and returns one GPGPrivate per entity found.
func ParseGPGPrivateKey(data, passphrase []byte) ([]*GPGPrivate, error) {
	entities, err := readEntities(data)
	if err != nil {
		return nil, fmt.Errorf("reading GPG private key data: %w", err)
	}

	result := make([]*GPGPrivate, 0, len(entities))
	for _, e := range entities {
		if e.PrivateKey == nil {
			return nil, fmt.Errorf("key data does not contain private key material")
		}

		// Decrypt the private key if passphrase is provided
		if e.PrivateKey.Encrypted {
			if len(passphrase) == 0 {
				return nil, fmt.Errorf("private key is encrypted but no passphrase provided")
			}
			if err := e.PrivateKey.Decrypt(passphrase); err != nil {
				return nil, fmt.Errorf("decrypting private key: %w", err)
			}
		}

		// Also decrypt any encrypted subkeys
		for _, sk := range e.Subkeys {
			if sk.PrivateKey != nil && sk.PrivateKey.Encrypted {
				if len(passphrase) == 0 {
					return nil, fmt.Errorf("subkey is encrypted but no passphrase provided")
				}
				if err := sk.PrivateKey.Decrypt(passphrase); err != nil {
					return nil, fmt.Errorf("decrypting subkey: %w", err)
				}
			}
		}

		gpgPriv, err := newGPGPrivate(e)
		if err != nil {
			return nil, err
		}
		result = append(result, gpgPriv)
	}
	return result, nil
}

// readEntities reads OpenPGP entities from data, auto-detecting ASCII armor vs binary.
func readEntities(data []byte) (openpgp.EntityList, error) {
	if isOpenPGPArmored(data) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decoding ASCII armor: %w", err)
		}
		return openpgp.ReadKeyRing(block.Body)
	}
	return openpgp.ReadKeyRing(bytes.NewReader(data))
}

// isOpenPGPArmored checks whether the data starts with an ASCII armor header.
func isOpenPGPArmored(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PGP"))
}
