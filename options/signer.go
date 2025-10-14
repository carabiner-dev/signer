// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"

	"github.com/sigstore/sigstore/pkg/oauthflow"

	"github.com/carabiner-dev/signer/internal/tuf"
)

// DefaultSigstore is the default options set to configure the bundle
// verifier to use the sigstore public good instance.
var DefaultSigstore = Sigstore{
	Timestamp:     true,
	AppendToRekor: true,

	HideOIDCOptions: true,
	OidcRedirectURL: "http://localhost:0/auth/callback",
	OidcIssuer:      "https://oauth2.sigstore.dev/auth",
	OidcClientID:    "sigstore",

	// URLs default the public good instances
	FulcioURL: "https://fulcio.sigstore.dev",
	RekorURL:  "https://rekor.sigstore.dev",
}

var DefaultSigner = Signer{
	TufOptions: tuf.TufOptions{
		TufRootURL:  tuf.SigstorePublicGoodBaseURL,
		TufRootPath: "",
		Fetcher:     tuf.Defaultfetcher(),
	},
	Sigstore: DefaultSigstore,
}

// Signer
type Signer struct {
	tuf.TufOptions
	Sigstore
	Token *oauthflow.OIDCIDToken
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
