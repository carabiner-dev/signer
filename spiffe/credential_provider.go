// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Options configures a SPIFFE CredentialProvider.
type Options struct {
	// SocketPath is the Workload API endpoint (typically "unix:///...").
	// When empty, go-spiffe reads SPIFFE_ENDPOINT_SOCKET from the environment.
	SocketPath string

	// ExpectedTrustDomain, when non-zero, asserts that the issued SVID
	// belongs to this trust domain. Mismatch causes Prepare to fail.
	ExpectedTrustDomain spiffeid.TrustDomain
}

// CredentialProvider implements bundle.CredentialProvider using X.509-SVIDs
// from the SPIFFE Workload API. The Workload API stream is opened at Prepare
// time and rotates automatically; callers should invoke Close when done.
type CredentialProvider struct {
	Options Options

	// Source is the SVID source used by the keypair and cert provider. When
	// nil, Prepare opens a workloadapi.X509Source against Options.SocketPath.
	// Tests inject a fake source to exercise the provider without a running
	// Workload API.
	Source x509svid.Source

	// closer, when set, is invoked by Close to release resources owned by
	// the provider (e.g. the workloadapi.X509Source started in Prepare).
	closer   func() error
	keypair  sign.Keypair
	certProv sign.CertificateProvider
	prepared bool
}

// NewCredentialProvider creates a SPIFFE CredentialProvider with the given
// options.
func NewCredentialProvider(opts Options) *CredentialProvider {
	return &CredentialProvider{Options: opts}
}

// Prepare connects to the Workload API (if no Source was injected) and
// verifies that an SVID is available. Subsequent calls are no-ops.
func (p *CredentialProvider) Prepare(ctx context.Context) error {
	if p.prepared {
		return nil
	}

	if p.Source == nil {
		var clientOpts []workloadapi.ClientOption
		if p.Options.SocketPath != "" {
			clientOpts = append(clientOpts, workloadapi.WithAddr(p.Options.SocketPath))
		}
		src, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(clientOpts...))
		if err != nil {
			return fmt.Errorf("connecting to spiffe workload api: %w", err)
		}
		p.Source = src
		p.closer = src.Close
	}

	// Fetch once so Prepare fails fast if the agent isn't handing out an SVID.
	svid, err := p.Source.GetX509SVID()
	if err != nil {
		p.Close() //nolint:errcheck,gosec // best-effort cleanup; the original error is the one that matters
		return fmt.Errorf("fetching initial svid: %w", err)
	}

	if !p.Options.ExpectedTrustDomain.IsZero() && svid.ID.TrustDomain() != p.Options.ExpectedTrustDomain {
		p.Close() //nolint:errcheck,gosec // best-effort cleanup; the original error is the one that matters
		return fmt.Errorf(
			"svid trust domain %q does not match expected %q",
			svid.ID.TrustDomain(), p.Options.ExpectedTrustDomain,
		)
	}

	p.keypair = &svidKeypair{source: p.Source}
	p.certProv = &svidCertProvider{source: p.Source}
	p.prepared = true
	return nil
}

// Keypair returns the sign.Keypair backed by the SVID private key.
func (p *CredentialProvider) Keypair() sign.Keypair { return p.keypair }

// CertificateProvider returns the provider that yields the current SVID leaf.
// No provider options are required for the SPIFFE path.
func (p *CredentialProvider) CertificateProvider() (sign.CertificateProvider, *sign.CertificateProviderOptions) {
	return p.certProv, nil
}

// Intermediates returns the certs between the SVID leaf and the trust domain
// root, taken from the current SVID. The trust anchor itself is NOT
// included — verifiers pin it out-of-band.
func (p *CredentialProvider) Intermediates() []*x509.Certificate {
	if p.Source == nil {
		return nil
	}
	svid, err := p.Source.GetX509SVID()
	if err != nil || len(svid.Certificates) <= 1 {
		return nil
	}
	// Copy so callers can't mutate the SVID's slice.
	out := make([]*x509.Certificate, len(svid.Certificates)-1)
	copy(out, svid.Certificates[1:])
	return out
}

// Close releases any workloadapi.X509Source opened by Prepare. Sources
// injected by callers are not closed here — the caller owns their lifecycle.
func (p *CredentialProvider) Close() error {
	if p.closer == nil {
		return nil
	}
	err := p.closer()
	p.closer = nil
	return err
}
