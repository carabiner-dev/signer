// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

// Sigstore options to control how signer handles signing with sigstore
type Sigstore struct {
	Timestamp bool

	// AppendToRekor controls if the signing operation is recorded into the
	// transparency log.
	AppendToRekor bool
	DisableSTS    bool

	// FulcioURL url of the Fulcio CA (defaults to the public good instance)
	FulcioURL string

	// RekorURL url of the Rekor transparency log (defaults to the public good instance)
	RekorURL string

	// Hide the OIDC options in the CLI --help
	HideOIDCOptions bool

	// OidcRedirectURL defines the URL that the browser will redirect to.
	// if the port is set to 0, bind will randomize it to a high number
	// port before starting the OIDC flow.
	OidcRedirectURL string

	// OIDC token issuer endpoint
	OidcIssuer string

	// Client ID to stamp on the tokens
	OidcClientID string

	// Client secret to pass in OIDC calls
	OidcClientSecret string
}

// Verify checks the integrity of the sigstore options
func (s *Sigstore) Verify() error {
	errs := []error{}
	if s.RekorURL == "" {
		errs = append(errs, errors.New("rekor url not set"))
	} else {
		if _, err := url.Parse(s.RekorURL); err != nil {
			return fmt.Errorf("invalid Rekor URL value")
		}
	}
	if s.FulcioURL == "" {
		errs = append(errs, errors.New("fulcio url not set"))
	} else {
		if _, err := url.Parse(s.RekorURL); err != nil {
			return fmt.Errorf("invalid Rekor URL value")
		}
	}

	if s.OidcIssuer == "" {
		errs = append(errs, errors.New("OIDC issuer URL not set"))
	} else {
		if _, err := url.Parse(s.RekorURL); err != nil {
			return fmt.Errorf("invalid OIDC issuer URL")
		}
	}

	if s.OidcClientID == "" {
		errs = append(errs, fmt.Errorf("no OIDC client id set"))
	}

	return errors.Join(errs...)
}

// AddFlags adds flags to a spf13/cobra command exposing the sigstore
// signing options. Not all options are yet exposed as CLI flags.
func (s *Sigstore) AddFlags(cmd *cobra.Command) {
	// URLs for the sigstore services
	cmd.PersistentFlags().StringVar(&s.RekorURL, "rekor-url", DefaultSigstore.RekorURL, "address of the rekor transparency log server")
	cmd.PersistentFlags().StringVar(&s.FulcioURL, "fulcio-url", DefaultSigstore.RekorURL, "address of the fulcio certificate authority server")

	// OIDC settings
	cmd.PersistentFlags().StringVar(&s.OidcClientID, "oidc-client-id", DefaultSigstore.OidcClientID, "OIDC client ID to use exchanging tokens")
	cmd.PersistentFlags().StringVar(&s.OidcIssuer, "oidc-issuer", DefaultSigstore.OidcIssuer, "OIDC issuer URL")
	cmd.PersistentFlags().StringVar(&s.OidcRedirectURL, "oidc-redirect-url", DefaultSigstore.OidcRedirectURL, "OIDC redirect URL")

	// Mark the OIDS options as hidden if needed.
	if s.HideOIDCOptions {
		cmd.PersistentFlags().MarkHidden("oidc-client-id")    //nolint:errcheck,gosec
		cmd.PersistentFlags().MarkHidden("oidc-issuer")       //nolint:errcheck,gosec
		cmd.PersistentFlags().MarkHidden("oidc-redirect-url") //nolint:errcheck,gosec
	}
}
