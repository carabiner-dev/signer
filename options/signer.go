// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/signer/sigstore"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

var DefaultSigner = Signer{
	SigstoreRootsData: sigstore.DefaultRoots, // Embedded data from the rootsfile
}

// Signer
type Signer struct {
	Sigstore
	Token             *oauthflow.OIDCIDToken
	SigstoreRootsData []byte
	parsedRoots       bool
}

// ParseRoots parses the root information and assigns the instance data in
// the sigstore options
func (so *Signer) ParseRoots() error {
	if so.parsedRoots {
		return nil
	}
	roots, err := sigstore.ParseRoots(so.SigstoreRootsData)
	if err != nil {
		return fmt.Errorf("invalid root data: %w", err)
	}

	if len(roots.Roots) == 0 {
		return fmt.Errorf("no root configuration found")
	}

	so.Sigstore.Instance = roots.Roots[0].Instance
	so.parsedRoots = true
	return nil
}

// Validate checks the signer options
func (so *Signer) Validate() error {
	if err := so.ParseRoots(); err != nil {
		return fmt.Errorf("parsing roots: %w", err)
	}

	errs := []error{
		so.ValidateSigner(),
	}
	return errors.Join(errs...)
}
