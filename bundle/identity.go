// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package bundle

import (
	"context"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

// Identity abstracts the credentials and certificate material used to sign a
// bundle. Implementations own both the signing keypair and the certificate
// provider that populates VerificationMaterial.
//
//counterfeiter:generate . Identity
type Identity interface {
	// Prepare acquires credentials, keys, and certificates. Called once before
	// the first sign. Implementations are expected to be idempotent.
	Prepare(ctx context.Context) error

	// Keypair returns the signing keypair used by sign.Bundle.
	Keypair() sign.Keypair

	// CertificateProvider returns the provider sign.Bundle will call to
	// populate VerificationMaterial, together with any provider-specific
	// options (e.g. an OIDC ID token for Fulcio).
	CertificateProvider() (sign.CertificateProvider, *sign.CertificateProviderOptions)
}
