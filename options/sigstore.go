// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/signer/internal/tuf"
)

// Sigstore options to control how signer handles signing with sigstore
type Sigstore struct {
	// Embed the tuf options struct
	tuf.TufOptions

	Timestamp bool

	// AppendToRekor controls if the signing operation is recorded into the
	// transparency log.
	AppendToRekor bool `json:"rekor-append"`
	DisableSTS    bool

	// FulcioURL url of the Fulcio CA (defaults to the public good instance)
	FulcioURL string `json:"fulcio-url"`

	// RekorURL url of the Rekor transparency log (defaults to the public good instance)
	RekorURL string `json:"rekor-url"`

	// Hide the OIDC options in the CLI --help
	HideOIDCOptions bool

	// OidcRedirectURL defines the URL that the browser will redirect to.
	// if the port is set to 0, bind will randomize it to a high number
	// port before starting the OIDC flow.
	OidcRedirectURL string `json:"oidc-redirect-url"`

	// OIDC token issuer endpoint
	OidcIssuer string `json:"oidc-issuer"`

	// Client ID to stamp on the tokens
	OidcClientID string `json:"oidc-client-id"`

	// Client secret to pass in OIDC calls
	OidcClientSecret string `json:"oidc-client-secret"`

	// Time stamp verification options

	// Look for a signed timestamp in the cert and verify with the CTLog Auth
	RequireCTlog bool `json:"require-ct-log"`
	// Verify the cert validity in the transparency log
	RequireTlog bool `json:"require-tlog"`
	// Verify the certificate validity time with a signed timestamp
	RequireSignedTimestamps bool `json:"require-signed-timestamps"`
	// Allow no timestamp, for keys instead of certs
	RequireObserverTimestamp bool `json:"require-observer-timestamp"`
}

// Ensure the options have the required OIDC fields
func (s *Sigstore) ValidateOIDC() error {
	errs := []error{}
	if s.OidcClientID == "" {
		errs = append(errs, errors.New("OIDC client ID is missing"))
	}

	if s.OidcIssuer == "" {
		errs = append(errs, errors.New("OIDC issuer URL missing"))
	}

	if s.OidcRedirectURL == "" {
		errs = append(errs, errors.New("OIDC redirect URL missing"))
	}
	return errors.Join(errs...)
}

var DefaultSigstore = Sigstore{
	Timestamp:     true,
	AppendToRekor: true,

	TufOptions: tuf.TufOptions{
		TufRootURL: "https://tuf-repo-cdn.sigstore.dev",
	},

	HideOIDCOptions: true,
	OidcRedirectURL: "http://localhost:0/auth/callback",
	OidcIssuer:      "https://oauth2.sigstore.dev/auth",
	OidcClientID:    "sigstore",

	// URLs default the public good instances
	FulcioURL: "https://fulcio.sigstore.dev",
	RekorURL:  "https://rekor.sigstore.dev",

	RequireCTlog:             true,
	RequireTlog:              true,
	RequireObserverTimestamp: true,
}

// ValidateTimestamps
func (s *Sigstore) ValidateTimestamps() error {
	if !s.RequireCTlog && !s.RequireTlog && !s.RequireObserverTimestamp && !s.RequireSignedTimestamps {
		return errors.New("at least one method to check timestamps must be set")
	}
	return nil
}

// ValidateSigner check the options required to sign
func (s *Sigstore) ValidateSigner() error {
	errs := []error{
		s.ValidateOIDC(),
	}
	if s.RekorURL == "" {
		if s.AppendToRekor {
			errs = append(errs, errors.New("rekor url not set (and append to rekor is set)"))
		}
	} else {
		if _, err := url.Parse(s.RekorURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid Rekor URL"))
		}
	}
	if s.FulcioURL == "" {
		errs = append(errs, errors.New("fulcio url not set"))
	} else {
		if _, err := url.Parse(s.RekorURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid Rekor URL"))
		}
	}
	return errors.Join(errs...)
}

func (s *Sigstore) ValidateVerifier() error {
	errs := []error{
		s.ValidateTimestamps(),
	}
	if s.FulcioURL == "" {
		errs = append(errs, errors.New("fulcio url not set"))
	} else {
		if _, err := url.Parse(s.RekorURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid Rekor URL value"))
		}
	}
	return errors.Join(errs...)
}

// Validate checks the integrity of the sigstore options
func (s *Sigstore) Validate() error {
	return s.ValidateVerifier()
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
