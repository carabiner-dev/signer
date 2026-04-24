// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package spiffe

import (
	"context"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

var _ sign.CertificateProvider = (*svidCertProvider)(nil)

// svidCertProvider returns the current SVID leaf certificate as DER on each
// call. Intermediates are intentionally omitted in this phase — they will be
// embedded via VerificationMaterial.X509CertificateChain in a follow-up once
// the outer Signer post-processes the bundle.
type svidCertProvider struct {
	source x509svid.Source
}

func (p *svidCertProvider) GetCertificate(_ context.Context, _ sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	svid, err := p.source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("fetching svid: %w", err)
	}
	if len(svid.Certificates) == 0 {
		return nil, errors.New("svid has no certificates")
	}
	return svid.Certificates[0].Raw, nil
}
