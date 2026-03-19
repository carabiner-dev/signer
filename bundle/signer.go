// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package bundle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/term"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/internal/tuf"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/sts"
)

// BundleSigner abstracts the signer implementation to make it easy to mock
//
//counterfeiter:generate . Signer
type Signer interface {
	VerifyAttestationContent(*options.Signer, []byte) error
	WrapData(payloadType string, data []byte) *sign.DSSEData
	BuildMessage(data []byte) *sign.PlainData
	GetKeyPair(*options.Signer) (*sign.EphemeralKeypair, error)
	GetAmbientTokens(*options.Signer) error
	GetOidcToken(*options.Signer) error
	BuildSigstoreSignerOptions(*options.Signer) (*sign.BundleOptions, error)
	SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*protobundle.Bundle, error)
}

func NewSigner() Signer {
	return &DefaultSigner{}
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

// BuildSigstoreSignerOptions builds the signer options by reading the TUF roots
// and configuration from the local system (or defaults).
func (bs *DefaultSigner) BuildSigstoreSignerOptions(opts *options.Signer) (*sign.BundleOptions, error) {
	if opts.Token == nil {
		return nil, fmt.Errorf("no OIDC token set")
	}

	if opts.SigningConfig == nil {
		return nil, fmt.Errorf("signing config not set")
	}

	signingConfig := opts.SigningConfig

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

	if len(signingConfig.FulcioCertificateAuthorityURLs()) == 0 {
		return nil, fmt.Errorf("no fulcio URL configured in signing config")
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
func (bs *DefaultSigner) SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*protobundle.Bundle, error) {
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
	oidcIssuer := opts.OidcIssuerURL()

	connector := &oidcConnector{}
	switch {
	case opts.Token != nil:
		connector.flow = &oauthflow.StaticTokenGetter{RawToken: opts.Token.RawString}
	case !term.IsTerminal(0):
		// If we're in a CI environment with no ambient credentials token,
		// fail fast instead of starting the device flow which will hang
		// forever waiting for interactive input.
		if os.Getenv("CI") != "" {
			return fmt.Errorf(
				"no OIDC ambient credentials found in CI environment, " +
					"ensure the workflow has 'id-token: write' permission",
			)
		}
		connector.flow = oauthflow.NewDeviceFlowTokenGetterForIssuer(oidcIssuer)
	default:
		connector.flow = oauthflow.DefaultIDTokenGetter
	}

	// Run the flow and get the access token:
	tok, err := connector.Connect(
		oidcIssuer,
		opts.OIDCConfig.ClientID,
		opts.OIDCConfig.ClientSecret,
		randomizePort(opts.OIDCConfig.RedirectURL),
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
		token, err := provider.Provide(ctx, opts.OIDCConfig.ClientID)
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
