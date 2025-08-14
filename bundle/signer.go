// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	trustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/internal/sts"
	"github.com/carabiner-dev/signer/internal/tuf"
	"github.com/carabiner-dev/signer/options"
)

// BundleSigner abstracts the signer implementation to make it easy to mock
type Signer interface {
	VerifyAttestationContent(*options.Signer, []byte) error
	WrapData(payloadType string, data []byte) *sign.DSSEData
	BuildMessage(data []byte) *sign.PlainData
	GetKeyPair(*options.Signer) (*sign.EphemeralKeypair, error)
	GetAmbientTokens(*options.Signer) error
	GetOidcToken(*options.Signer) error
	BuildSigstoreSignerOptions(*options.Signer) (*sign.BundleOptions, error)
	SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*v1.Bundle, error)
}

// DefaultSigner implements the BundleSigner interface for the signer
type DefaultSigner struct{}

func (bs *DefaultSigner) WrapData(payloadType string, data []byte) *sign.DSSEData {
	content := &sign.DSSEData{
		Data:        data,
		PayloadType: payloadType,
	}
	return content
}

// BuildMessage is the alternative to WrapData.
func (bs *DefaultSigner) BuildMessage(data []byte) *sign.PlainData {
	return &sign.PlainData{
		Data: data,
	}
}

// VerifyContent checka that the attestation is in good shape to sign
func (bs *DefaultSigner) VerifyAttestationContent(_ *options.Signer, data []byte) error {
	if data == nil {
		return errors.New("payload is empty")
	}
	st := &intoto.Statement{}
	if err := protojson.Unmarshal(data, st); err != nil {
		return errors.New("unable to unmarshal intoto statement from payload")
	}
	return nil
}

// GetKeyPair calls the configured key generator and returns
// a keypair which will be used to sign
func (bs *DefaultSigner) GetKeyPair(opts *options.Signer) (*sign.EphemeralKeypair, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keypair")
	}

	// Extract the PEM data to ensure it worked
	_, err = keypair.GetPublicKeyPem()
	// TODO(we clouidl log or store the public key)
	if err != nil {
		return nil, fmt.Errorf("extracting public key: %w", err)
	}

	return keypair, nil
}

func tempSigningConfigBuilder(opts *options.Signer) (*root.SigningConfig, error) {
	// These two are not yet exposed in the SignerOptions
	fulcioURL := "https://fulcio.sigstore.dev"
	rekorURL := "https://rekor.sigstore.dev"

	// This is:
	oidcIssuer := options.DefaultSigner.OidcIssuer
	if opts.OidcIssuer != "" {
		oidcIssuer = opts.OidcIssuer
	}

	return root.NewSigningConfig(
		root.SigningConfigMediaType02,
		// Fulcio URLs
		[]root.Service{
			{
				URL:                 fulcioURL,
				MajorAPIVersion:     1,
				ValidityPeriodStart: time.Now().Add(-time.Hour),
				ValidityPeriodEnd:   time.Now().Add(time.Hour),
			},
		},
		// OIDC Issuer
		[]root.Service{
			{
				URL:                 oidcIssuer,
				MajorAPIVersion:     1,
				ValidityPeriodStart: time.Now().Add(-time.Hour),
				ValidityPeriodEnd:   time.Now().Add(time.Hour),
			},
		},
		// Rekor API endpoint
		[]root.Service{
			{
				URL:                 rekorURL,
				MajorAPIVersion:     1,
				ValidityPeriodStart: time.Now().Add(-time.Hour),
				ValidityPeriodEnd:   time.Now().Add(time.Hour),
			},
		},
		root.ServiceConfiguration{
			Selector: trustroot.ServiceSelector_ANY,
		},
		// Timestamp services
		[]root.Service{
			{
				URL:                 "https://timestamp.githubapp.com/api/v1/timestamp",
				MajorAPIVersion:     1,
				ValidityPeriodStart: time.Now().Add(-time.Hour),
				ValidityPeriodEnd:   time.Now().Add(time.Hour),
			},
		},
		root.ServiceConfiguration{
			Selector: trustroot.ServiceSelector_ANY,
		},
	)
}

// BuildSigstoreSignerOptions builds the signer options by reading the TUF roots
// and configuration from the local system (or defaults).
func (bs *DefaultSigner) BuildSigstoreSignerOptions(opts *options.Signer) (*sign.BundleOptions, error) {
	if opts.Token == nil {
		return nil, fmt.Errorf("no OIDC token set")
	}

	// bundleOptions is the options set to configure the sigstore signer
	bundleOptions := sign.BundleOptions{}
	tufClient, err := tuf.GetClient(&opts.TufOptions)
	if err != nil {
		return nil, fmt.Errorf("creating TUF client: %w", err)
	}

	// Call the tuf client to ensure roots are on disk
	if _, err = root.GetTrustedRoot(tufClient); err != nil {
		return nil, fmt.Errorf("fetching TUF root: %w", err)
	}

	// The TUF roots are in the process to be updated, so for now we
	// use a temporary configuration to point to the sigstore public good
	// while it getsa updated:
	//
	// signingConfig, err := root.GetSigningConfig(tufClient)
	signingConfig, err := tempSigningConfigBuilder(opts)
	if err != nil {
		return nil, fmt.Errorf("getting signing config from TUF: %w", err)
	}

	if len(signingConfig.FulcioCertificateAuthorityURLs()) == 0 {
		return nil, fmt.Errorf("unable to read fulcio configuration from TUF client")
	}

	// Configure the Fulcio client
	fulcioOpts := &sign.FulcioOptions{
		BaseURL: signingConfig.FulcioCertificateAuthorityURLs()[0].URL,
		Timeout: 30 * time.Second,
		Retries: 1,
	}

	bundleOptions.CertificateProvider = sign.NewFulcio(fulcioOpts)
	bundleOptions.CertificateProviderOptions = &sign.CertificateProviderOptions{
		IDToken: opts.Token.RawString,
	}

	if opts.Timestamp {
		tsaURLs, err := root.SelectServices(
			signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("fetching time stamp authority URLs: %w", err)
		}

		if len(tsaURLs) == 0 {
			return nil, fmt.Errorf("no timestamp authority found in signing config")
		}

		for _, tsaURL := range tsaURLs {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL.URL,
				Timeout: 30 * time.Second,
				Retries: 1,
			}
			bundleOptions.TimestampAuthorities = append(
				bundleOptions.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts),
			)
		}
	}

	if opts.AppendToRekor {
		for _, rekorURL := range signingConfig.RekorLogURLs() {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL.URL,
				Timeout: 90 * time.Second,
				Retries: 1,
			}
			bundleOptions.TransparencyLogs = append(bundleOptions.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	return &bundleOptions, nil
}

// SignBundle signs the DSSE envelop and returns the new bundle
func (bs *DefaultSigner) SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*v1.Bundle, error) {
	bndl, err := sign.Bundle(content, keypair, *opts)
	if err != nil {
		return nil, fmt.Errorf("signing DSSE wrapper: %w", err)
	}

	return bndl, nil
}

func (bs *DefaultSigner) GetOidcToken(opts *options.Signer) error {
	//
	// Create the OIDC connector and choose the proper flow depending on the
	// environment.
	//
	// TODO(puerco): This needs to fetch the token from github actions
	connector := &oidcConnector{}
	switch {
	case opts.Token != nil:
		connector.flow = &oauthflow.StaticTokenGetter{RawToken: opts.Token.RawString}
	case !term.IsTerminal(0):
		connector.flow = oauthflow.NewDeviceFlowTokenGetterForIssuer(opts.OidcIssuer)
	default:
		connector.flow = oauthflow.DefaultIDTokenGetter
	}

	// Run the flow and get the access token:
	tok, err := connector.Connect(
		opts.OidcIssuer,
		opts.OidcClientID,
		opts.OidcClientSecret,
		randomizePort(opts.OidcRedirectURL),
	)
	if err != nil {
		return fmt.Errorf("running OIDC flow: %w", err)
	}

	opts.Token = tok
	return nil
}

func randomizePort(redirectURL string) string {
	p, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	rond, err := rand.Int(rand.Reader, big.NewInt(64511))
	if err != nil {
		// :(
		return ""
	}
	replace := strings.Replace(
		redirectURL, fmt.Sprintf("%s:0/", p.Hostname()), fmt.Sprintf("%s:%d/", p.Hostname(), rond.Int64()+1025), 1,
	)
	return replace
}

func (bs *DefaultSigner) GetAmbientTokens(opts *options.Signer) error {
	// If sts providers are disabled, we're done.
	if opts.DisableSTS {
		return nil
	}

	ctx := context.Background()

	for k, provider := range sts.DefaultProviders {
		token, err := provider.Provide(ctx, opts.OidcClientID)
		if err != nil {
			return fmt.Errorf("trying ambien credentials from %s: %w", k, err)
		}

		if token != nil {
			opts.Token = token
			return nil
		}
	}
	return nil
}

type oidcConnector struct {
	flow oauthflow.TokenGetter
}

func (rf *oidcConnector) Connect(urlString, clientID, secret, redirectURL string) (*oauthflow.OIDCIDToken, error) {
	return oauthflow.OIDConnect(urlString, clientID, secret, redirectURL, rf.flow)
}
