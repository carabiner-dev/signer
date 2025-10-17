// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"

	"github.com/sigstore/sigstore/pkg/oauthflow"
)

var DefaultSigner = Signer{
	SigstoreRootsData: defaultRoots, // Embedded data from the rootsfile
}

// Signer
type Signer struct {
	Sigstore
	Token             *oauthflow.OIDCIDToken
	SigstoreRootsData []byte
}

// Validate checks the signer options
func (so *Signer) Validate() error {
	errs := []error{}
	if so.OidcIssuer == "" {
		errs = append(errs, errors.New("OIDC issuer not set"))
	}

	if so.OidcClientID == "" {
		errs = append(errs, errors.New("OIDC client not set"))
	}

	if so.OidcRedirectURL == "" {
		errs = append(errs, errors.New("OIDC redirect URL not set"))
	}

	return errors.Join(errs...)
}
