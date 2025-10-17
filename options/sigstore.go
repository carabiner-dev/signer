// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/carabiner-dev/signer/internal/tuf"
	"github.com/carabiner-dev/signer/sigstore"
)

// Sigstore options to control how signer handles signing with sigstore
type Sigstore struct {
	sigstore.Instance
}

// Ensure the options have the required OIDC fields
func (s *Sigstore) ValidateOIDC() error {
	return s.Instance.ValidateOIDC()
}

var DefaultSigstore = Sigstore{
	Instance: sigstore.Instance{
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
	},
}

// ValidateTimestamps
func (s *Sigstore) ValidateTimestamps() error {
	return s.Instance.ValidateTimestamps()
}

// ValidateSigner check the options required to sign
func (s *Sigstore) ValidateSigner() error {
	return s.Instance.ValidateSigner()
}

func (s *Sigstore) ValidateVerifier() error {
	return s.Instance.ValidateVerifier()
}

// Validate checks the integrity of the sigstore options
func (s *Sigstore) Validate() error {
	return s.ValidateVerifier()
}

// AddFlags adds flags to a spf13/cobra command exposing the sigstore
// signing options. Not all options are yet exposed as CLI flags.
func (s *Sigstore) AddFlags(cmd *cobra.Command) {
	flagPrefix := ""
	if s.FlagPrefix != "" {
		flagPrefix = s.FlagPrefix + "-"
	}
	// URLs for the sigstore services
	cmd.PersistentFlags().StringVar(&s.RekorURL, fmt.Sprintf("%srekor-url", flagPrefix), DefaultSigstore.RekorURL, "address of the rekor transparency log server")
	cmd.PersistentFlags().StringVar(&s.FulcioURL, fmt.Sprintf("%sfulcio-url", flagPrefix), DefaultSigstore.FulcioURL, "address of the fulcio certificate authority server")

	// OIDC settings
	cmd.PersistentFlags().StringVar(&s.OidcClientID, fmt.Sprintf("%soidc-client-id", flagPrefix), DefaultSigstore.OidcClientID, "OIDC client ID to use exchanging tokens")
	cmd.PersistentFlags().StringVar(&s.OidcIssuer, fmt.Sprintf("%soidc-issuer", flagPrefix), DefaultSigstore.OidcIssuer, "OIDC issuer URL")
	cmd.PersistentFlags().StringVar(&s.OidcRedirectURL, fmt.Sprintf("%soidc-redirect-url", flagPrefix), DefaultSigstore.OidcRedirectURL, "OIDC redirect URL")

	// Mark the OIDC options as hidden if needed.
	if s.HideOIDCOptions {
		cmd.PersistentFlags().MarkHidden(fmt.Sprintf("%soidc-client-id", flagPrefix))    //nolint:errcheck,gosec
		cmd.PersistentFlags().MarkHidden(fmt.Sprintf("%soidc-issuer", flagPrefix))       //nolint:errcheck,gosec
		cmd.PersistentFlags().MarkHidden(fmt.Sprintf("%soidc-redirect-url", flagPrefix)) //nolint:errcheck,gosec
	}
}
