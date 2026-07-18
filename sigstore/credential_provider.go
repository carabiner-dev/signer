// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// CredentialProvider implements bundle.CredentialProvider and binds a sigstore
// instance (OIDC provider + Fulcio) to a signer.
type CredentialProvider struct {
	// Instance holds the sigstore configuration (TUF options, signing config,
	// OIDC client config, verifier config).
	Instance *Instance

	// DisableSTS skips the ambient credential providers.
	DisableSTS bool

	// Token is an optional pre-provided OIDC ID token. When set, Prepare skips
	// the ambient STS providers; the token still flows through OIDConnect so
	// that it is parsed/validated the same way as a freshly issued one.
	Token *oauthflow.OIDCIDToken

	keypair     *sign.EphemeralKeypair
	cp          sign.CertificateProvider
	trustedRoot *root.TrustedRoot
	prepared    bool
}

// NewCredentialProvider creates a sigstore CredentialProvider for the given Instance.
func NewCredentialProvider(instance *Instance) *CredentialProvider {
	return &CredentialProvider{Instance: instance}
}

// Prepare runs the OIDC flow, ensures TUF roots are on disk, generates an
// ephemeral keypair, and builds the Fulcio certificate provider. Subsequent
// calls are no-ops.
func (p *CredentialProvider) Prepare(ctx context.Context) error {
	if p.prepared {
		return nil
	}
	if p.Instance == nil {
		return errors.New("sigstore instance not set")
	}

	// Ensure TUF roots are available on disk. sigstore-go's internals look
	// them up during verification; fetch once here so the first sign call
	// doesn't race with TUF bootstrap.
	tufClient, err := tuf.GetClient(&p.Instance.TufOptions)
	if err != nil {
		return fmt.Errorf("creating TUF client: %w", err)
	}
	trustedRoot, err := root.GetTrustedRoot(tufClient)
	if err != nil {
		return fmt.Errorf("fetching TUF root: %w", err)
	}
	// Keep the trusted root so CertifiedKey can reconstruct the Fulcio
	// intermediate chain (sigstore-go's Fulcio provider returns only the leaf).
	p.trustedRoot = trustedRoot

	// Generate the ephemeral keypair that will be bound to the Fulcio cert.
	kp, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return fmt.Errorf("generating ephemeral keypair: %w", err)
	}
	if _, err := kp.GetPublicKeyPem(); err != nil {
		return fmt.Errorf("extracting public key: %w", err)
	}
	p.keypair = kp

	// Try ambient STS providers before falling back to an interactive flow.
	if !p.DisableSTS && p.Token == nil {
		if err := p.runAmbientSTS(ctx); err != nil {
			return fmt.Errorf("fetching ambient credentials: %w", err)
		}
	}

	tok, err := p.runOIDCFlow()
	if err != nil {
		return fmt.Errorf("getting ID token: %w", err)
	}
	p.Token = tok

	fulcioURL := p.Instance.FulcioURL()
	if fulcioURL == "" {
		return errors.New("no fulcio URL configured in signing config")
	}

	// Wrap Fulcio with a validity-window cache so repeated signs with the
	// same identity reuse the certificate until it expires.
	p.cp = &cachingCertProvider{
		inner: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioURL,
			Timeout: 30 * time.Second,
			Retries: 1,
		}),
	}

	p.prepared = true
	return nil
}

// Keypair returns the ephemeral keypair bound to the Fulcio certificate.
func (p *CredentialProvider) Keypair() sign.Keypair { return p.keypair }

// CertificateProvider returns the Fulcio provider and the OIDC ID token that
// authenticates the signing cert request.
func (p *CredentialProvider) CertificateProvider() (sign.CertificateProvider, *sign.CertificateProviderOptions) {
	var opts *sign.CertificateProviderOptions
	if p.Token != nil {
		opts = &sign.CertificateProviderOptions{IDToken: p.Token.RawString}
	}
	return p.cp, opts
}

// Intermediates returns nil. The Fulcio chain is reconstructed at verify
// time from the sigstore TUF root, so no intermediates are embedded in the
// bundle's VerificationMaterial.
func (p *CredentialProvider) Intermediates() []*x509.Certificate { return nil }

// CertifiedKey runs the keyless (Fulcio) flow with a freshly generated key and
// returns the leaf certificate with its intermediate chain (leaf-adjacent first,
// root excluded), and the private key. The material is suitable for building a
// detached CMS/PKCS7 signature. We built this to emulate the gitsign signer but
// it can be used to sign anything with the same ambient identity the sigstore
// bundle backend signs with.
//
// Unlike the bundle path, the returned key is available to the caller as a
// crypto.Signer,. this function generates its own key and drives the Fulcio
// certificate request with it but ( as opposed to sigstore-go's that hides its
// its key in EphemeralKeypair), the issued certificate binds to a key the caller
// gets to keep.
//
// The ambient OIDC token and Fulcio provider are obtained through Prepare, so an
// injected Token / DisableSTS is honored exactly like the signing path.
func (p *CredentialProvider) CertifiedKey(ctx context.Context) (
	leaf *x509.Certificate, chain []*x509.Certificate, key crypto.Signer, err error,
) {
	if err := p.Prepare(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("preparing credentials: %w", err)
	}

	// Generate our own key so we can hand the crypto.Signer back to the caller.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating signing key: %w", err)
	}
	kp, err := NewSignerKeypair(priv, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building keypair: %w", err)
	}

	cp, opts := p.CertificateProvider()
	if cp == nil {
		return nil, nil, nil, errors.New("no certificate provider available after Prepare")
	}
	// Bypass the validity-window cache: it is keyed only by time, not by
	// keypair, so it may hold a certificate bound to the bundle path's ephemeral
	// key. We need one freshly bound to the key we just generated.
	if cc, ok := cp.(*cachingCertProvider); ok {
		cp = cc.inner
	}

	// When the provider can return a full chain (leaf + intermediates), use it.
	// The real Fulcio provider only returns the leaf, so fall back to
	// reconstructing the intermediates from the sigstore trusted root.
	if ccp, ok := cp.(sign.CertificateChainProvider); ok {
		chainDER, cerr := ccp.GetCertificateChain(ctx, kp, opts)
		if cerr != nil {
			return nil, nil, nil, fmt.Errorf("requesting certificate chain: %w", cerr)
		}
		leaf, chain, err = parseLeafAndChain(chainDER)
		if err != nil {
			return nil, nil, nil, err
		}
		return leaf, chain, priv, nil
	}

	leafDER, cerr := cp.GetCertificate(ctx, kp, opts)
	if cerr != nil {
		return nil, nil, nil, fmt.Errorf("requesting certificate: %w", cerr)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	return leaf, p.fulcioIntermediates(leaf), priv, nil
}

// fulcioIntermediates reconstructs the intermediate chain for a Fulcio-issued
// leaf from the sigstore trusted root. sigstore-go's Fulcio provider returns
// only the leaf, so the intermediates — which a detached CMS signature needs to
// chain to the Fulcio root — come from the trust root fetched during Prepare.
// Returns nil when no matching authority is found: the leaf alone is still
// usable and the caller can supply intermediates from its own trust root.
func (p *CredentialProvider) fulcioIntermediates(leaf *x509.Certificate) []*x509.Certificate {
	if p.trustedRoot == nil || leaf == nil {
		return nil
	}
	for _, ca := range p.trustedRoot.FulcioCertificateAuthorities() {
		chains, err := ca.Verify(leaf, leaf.NotBefore)
		if err != nil || len(chains) == 0 {
			continue
		}
		// Each chain is [leaf, intermediate(s)..., root]; drop leaf and root.
		chain := chains[0]
		if len(chain) <= 2 {
			return nil
		}
		intermediates := chain[1 : len(chain)-1]
		out := make([]*x509.Certificate, len(intermediates))
		copy(out, intermediates)
		return out
	}
	return nil
}

// parseLeafAndChain parses a DER chain (leaf first) into the leaf certificate
// and its intermediates, dropping a trailing self-signed root if the provider
// included one (CMS callers supply the trust anchor out of band).
func parseLeafAndChain(chainDER [][]byte) (leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	if len(chainDER) == 0 {
		return nil, nil, errors.New("certificate provider returned an empty chain")
	}
	certs := make([]*x509.Certificate, 0, len(chainDER))
	for i, der := range chainDER {
		c, perr := x509.ParseCertificate(der)
		if perr != nil {
			return nil, nil, fmt.Errorf("parsing certificate %d in chain: %w", i, perr)
		}
		certs = append(certs, c)
	}

	leaf = certs[0]
	intermediates := certs[1:]
	if n := len(intermediates); n > 0 && isSelfSigned(intermediates[n-1]) {
		intermediates = intermediates[:n-1]
	}
	if len(intermediates) == 0 {
		return leaf, nil, nil
	}
	out := make([]*x509.Certificate, len(intermediates))
	copy(out, intermediates)
	return leaf, out, nil
}

// isSelfSigned reports whether a certificate's issuer equals its subject, the
// hallmark of a trust-anchor root.
func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

// runAmbientSTS iterates over the configured STS providers until it gets a token
func (p *CredentialProvider) runAmbientSTS(ctx context.Context) error {
	for k, provider := range sts.DefaultProviders {
		token, err := provider.Provide(ctx, p.Instance.OIDCConfig.ClientID)
		if err != nil {
			return fmt.Errorf("trying ambien credentials from %s: %w", k, err)
		}
		if token != nil {
			p.Token = token
			return nil
		}
	}
	return nil
}

// runOIDCFlow does the OIDC exchange to get the token.
// If a token is already set it goes through the static flow which just
// parses and returns it unchanged. Otherwise the flow is chosen based on the
// environment (browser, device flow, or fail-fast in CI).
func (p *CredentialProvider) runOIDCFlow() (*oauthflow.OIDCIDToken, error) {
	issuer := p.Instance.OidcIssuerURL()

	var flow oauthflow.TokenGetter
	switch {
	case p.Token != nil:
		flow = &oauthflow.StaticTokenGetter{RawToken: p.Token.RawString}
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
		p.Instance.OIDCConfig.ClientID,
		p.Instance.OIDCConfig.ClientSecret,
		randomizePort(p.Instance.OIDCConfig.RedirectURL),
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
