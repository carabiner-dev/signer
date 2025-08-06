// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/carabiner-dev/signer/internal/tuf"
)

var DefaultSigner = Signer{
	TufOptions: tuf.TufOptions{
		TufRootURL:  tuf.SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     tuf.Defaultfetcher(),
	},
	Timestamp:     true,
	AppendToRekor: true,

	OidcRedirectURL: "http://localhost:0/auth/callback",
	OidcIssuer:      "https://oauth2.sigstore.dev/auth",
	OidcClientID:    "sigstore",
}

// Signer
type Signer struct {
	tuf.TufOptions
	Token         *oauthflow.OIDCIDToken
	Timestamp     bool
	AppendToRekor bool
	DisableSTS    bool

	// OidcRedirectURL defines the URL that the browser will redirect to.
	// if the port is set to 0, bind will randomize it to a high number
	// port before starting the OIDC flow.
	OidcRedirectURL  string
	OidcIssuer       string
	OidcClientID     string
	OidcClientSecret string
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
	// opts.OidcClientSecret

	return errors.Join(errs...)
}
