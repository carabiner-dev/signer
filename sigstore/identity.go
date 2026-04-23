// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/term"

	"github.com/carabiner-dev/signer/internal/tuf"
	"github.com/carabiner-dev/signer/sts"
)

// Identity implements bundle.Identity and binds a sigstore instance
// (OIDC provider + Fulcio) to a signer.
type Identity struct {
	// Instance holds the sigstore configuration (TUF options, signing config,
	// OIDC client config, verifier config).
	Instance *Instance

	// DisableSTS skips the ambient credential providers.
	DisableSTS bool

	// Token is an optional pre-provided OIDC ID token. When set, Prepare skips
	// the ambient STS providers; the token still flows through OIDConnect so
	// that it is parsed/validated the same way as a freshly issued one.
	Token *oauthflow.OIDCIDToken

	keypair  *sign.EphemeralKeypair
	cp       sign.CertificateProvider
	prepared bool
}

// NewIdentity creates a sigstore Identity for the given Instance.
func NewIdentity(instance *Instance) *Identity {
	return &Identity{Instance: instance}
}

// Prepare runs the OIDC flow, ensures TUF roots are on disk, generates an
// ephemeral keypair, and builds the Fulcio certificate provider. Subsequent
// calls are no-ops.
func (i *Identity) Prepare(ctx context.Context) error {
	if i.prepared {
		return nil
	}
	if i.Instance == nil {
		return errors.New("sigstore instance not set")
	}

	// Ensure TUF roots are available on disk. sigstore-go's internals look
	// them up during verification; fetch once here so the first sign call
	// doesn't race with TUF bootstrap.
	tufClient, err := tuf.GetClient(&i.Instance.TufOptions)
	if err != nil {
		return fmt.Errorf("creating TUF client: %w", err)
	}
	if _, err := root.GetTrustedRoot(tufClient); err != nil {
		return fmt.Errorf("fetching TUF root: %w", err)
	}

	// Generate the ephemeral keypair that will be bound to the Fulcio cert.
	kp, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	if _, err := kp.GetPublicKeyPem(); err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}
	i.keypair = kp

	// Try ambient STS providers before falling back to an interactive flow.
	if !i.DisableSTS && i.Token == nil {
		if err := i.runAmbientSTS(ctx); err != nil {
			return fmt.Errorf("fetching ambient credentials: %w", err)
		}
	}

	tok, err := i.runOIDCFlow()
	if err != nil {
		return fmt.Errorf("getting ID token: %w", err)
	}
	i.Token = tok

	fulcioURL := i.Instance.FulcioURL()
	if fulcioURL == "" {
		return errors.New("no fulcio URL configured in signing config")
	}

	// Wrap Fulcio with a validity-window cache so repeated signs with the
	// same identity reuse the certificate until it expires.
	i.cp = &cachingCertProvider{
		inner: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioURL,
			Timeout: 30 * time.Second,
			Retries: 1,
		}),
	}

	i.prepared = true
	return nil
}

// Keypair returns the ephemeral keypair bound to the Fulcio certificate.
func (i *Identity) Keypair() sign.Keypair { return i.keypair }

// CertificateProvider returns the Fulcio provider and the OIDC ID token that
// authenticates the signing cert request.
func (i *Identity) CertificateProvider() (sign.CertificateProvider, *sign.CertificateProviderOptions) {
	var opts *sign.CertificateProviderOptions
	if i.Token != nil {
		opts = &sign.CertificateProviderOptions{IDToken: i.Token.RawString}
	}
	return i.cp, opts
}

// runAmbientSTS iterates over the configured STS providers until it gets a token
func (i *Identity) runAmbientSTS(ctx context.Context) error {
	for k, provider := range sts.DefaultProviders {
		token, err := provider.Provide(ctx, i.Instance.OIDCConfig.ClientID)
		if err != nil {
			return fmt.Errorf("trying ambien credentials from %s: %w", k, err)
		}
		if token != nil {
			i.Token = token
			return nil
		}
	}
	return nil
}

// runOIDCFlow does the OIDC exchange to get the token.
// If a token is already set it goes through the static flow which just
// parses and returns it unchanged. Otherwise the flow is chosen based on the
// environment (browser, device flow, or fail-fast in CI).
func (i *Identity) runOIDCFlow() (*oauthflow.OIDCIDToken, error) {
	issuer := i.Instance.OidcIssuerURL()

	var flow oauthflow.TokenGetter
	switch {
	case i.Token != nil:
		flow = &oauthflow.StaticTokenGetter{RawToken: i.Token.RawString}
	case !term.IsTerminal(0):
		if os.Getenv("CI") != "" {
			return nil, fmt.Errorf(
				"no OIDC ambient credentials found in CI environment, " +
					"ensure the workflow has 'id-token: write' permission",
			)
		}
		flow = oauthflow.NewDeviceFlowTokenGetterForIssuer(issuer)
	default:
		flow = oauthflow.DefaultIDTokenGetter
	}

	return oauthflow.OIDConnect(
		issuer,
		i.Instance.OIDCConfig.ClientID,
		i.Instance.OIDCConfig.ClientSecret,
		randomizePort(i.Instance.OIDCConfig.RedirectURL),
		flow,
	)
}

func randomizePort(redirectURL string) string {
	p, err := url.Parse(redirectURL)
	if err != nil {
		return ""
	}

	rond, err := rand.Int(rand.Reader, big.NewInt(64511))
	if err != nil {
		return ""
	}
	return strings.Replace(
		redirectURL,
		fmt.Sprintf("%s:0/", p.Hostname()),
		fmt.Sprintf("%s:%d/", p.Hostname(), rond.Int64()+1025),
		1,
	)
}

// cachingCertProvider wraps a CertificateProvider and caches the certificate
// within its validity window. This avoids issuing multiple Fulcio certificate
// requests when the same keypair is used to sign several artifacts.
type cachingCertProvider struct {
	inner     sign.CertificateProvider
	cert      []byte
	notBefore time.Time
	notAfter  time.Time
}

func (c *cachingCertProvider) GetCertificate(ctx context.Context, kp sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	now := time.Now()
	if c.cert != nil && now.After(c.notBefore) && now.Before(c.notAfter) {
		return c.cert, nil
	}

	cert, err := c.inner.GetCertificate(ctx, kp, opts)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("parsing cached certificate: %w", err)
	}

	c.cert = cert
	c.notBefore = x509Cert.NotBefore
	c.notAfter = x509Cert.NotAfter
	return cert, nil
}
