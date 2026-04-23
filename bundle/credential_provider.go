// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package bundle

import (
	"context"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

// CredentialProvider produces the signing material used to populate a bundle.
// Implementations own the lifecycle of the keypair and the certificate
// provider that sign.Bundle calls to build VerificationMaterial.
//
//counterfeiter:generate . CredentialProvider
type CredentialProvider interface {
	// Prepare acquires credentials, keys, and certificates. Called once
	// before the first sign; implementations are expected to be idempotent.
	Prepare(ctx context.Context) error

	// Keypair returns the signing keypair used by sign.Bundle.
	Keypair() sign.Keypair

	// CertificateProvider returns the provider sign.Bundle will call to
	// populate VerificationMaterial, together with any provider-specific
	// options (e.g. an OIDC ID token for Fulcio).
	CertificateProvider() (sign.CertificateProvider, *sign.CertificateProviderOptions)
}
