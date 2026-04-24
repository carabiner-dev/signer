// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package bundle

import (
	"context"
	"crypto/x509"

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

	// Intermediates returns the certificates between the leaf and the trust
	// anchor, in order from leaf-adjacent to root-adjacent. The root itself
	// must NOT be included — verifiers supply it out-of-band.
	//
	// Returns nil when there are no intermediates to embed (the sigstore
	// case, where the chain is reconstructed from TUF at verify time). When
	// the return value is non-empty, the outer Signer rewrites the bundle's
	// VerificationMaterial to carry [leaf, ...intermediates] so the verifier
	// can build a path to its pinned trust anchor.
	Intermediates() []*x509.Certificate
}
