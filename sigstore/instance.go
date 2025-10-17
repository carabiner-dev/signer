// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/carabiner-dev/signer/internal/tuf"
)

// Instance captures the configuration required to talk to a sigstore instance.
type Instance struct {
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
	// FlagPrefix adds a prefix to the CLI strings, these help grouping them
	FlagPrefix string

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

// ValidateOIDC checks that the OIDC properties are correct
func (i *Instance) ValidateOIDC() error {
	errs := []error{}
	if i.OidcClientID == "" {
		errs = append(errs, errors.New("OIDC client ID is missing"))
	}

	if i.OidcIssuer == "" {
		errs = append(errs, errors.New("OIDC issuer URL missing"))
	}

	if i.OidcRedirectURL == "" {
		errs = append(errs, errors.New("OIDC redirect URL missing"))
	}
	return errors.Join(errs...)
}

// ValidateTimestamps
func (i *Instance) ValidateTimestamps() error {
	if !i.RequireCTlog && !i.RequireTlog && !i.RequireObserverTimestamp && !i.RequireSignedTimestamps {
		return errors.New("at least one method to check timestamps must be set")
	}
	return nil
}

func (i *Instance) ValidateVerifier() error {
	errs := []error{
		i.ValidateTimestamps(),
	}
	if i.FulcioURL == "" {
		errs = append(errs, errors.New("fulcio url not set"))
	} else {
		if _, err := url.Parse(i.RekorURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid Rekor URL value"))
		}
	}
	return errors.Join(errs...)
}

func (i *Instance) ValidateSigner() error {
	errs := []error{
		i.ValidateOIDC(),
	}
	if i.RekorURL == "" {
		if i.AppendToRekor {
			errs = append(errs, errors.New("rekor url not set (and append to rekor is set)"))
		}
	} else {
		if _, err := url.Parse(i.RekorURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid Rekor URL"))
		}
	}
	if i.FulcioURL == "" {
		errs = append(errs, errors.New("fulcio url not set"))
	} else {
		if _, err := url.Parse(i.RekorURL); err != nil {
			errs = append(errs, fmt.Errorf("invalid Rekor URL"))
		}
	}
	return errors.Join(errs...)
}
