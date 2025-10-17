// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"

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
}

// Validate checks the signer options
func (so *Signer) Validate() error {
	errs := []error{
		so.ValidateSigner(),
	}
	return errors.Join(errs...)
}
