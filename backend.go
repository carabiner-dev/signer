// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package signer

import (
	"github.com/carabiner-dev/signer/options"
)

// Backend is one of the three signing implementations the Signer
// dispatches to. Real implementations are constructed by
// Signer.resolveBackend based on Signer.Options.Backend (or per-call
// options.WithKey overrides). A counterfeiter-generated fake lives at
// signerfakes.FakeBackend.
//
// Backends are self-contained: they hold the state they need
// (credentials, bundle/dsse signers, configured keys) and the
// per-instance caches that make repeated Sign calls cheap (one OIDC
// flow + one Fulcio cert request shared across calls).
//
//counterfeiter:generate . Backend
type Backend interface {
	// Name reports which backend this is.
	Name() options.Backend

	// SignStatement signs an in-toto attestation. Bundle backends
	// produce *BundleArtifact; the key backend produces
	// *EnvelopeArtifact.
	SignStatement(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error)

	// SignMessage signs a raw payload. Bundle backends wrap it in a
	// sigstore bundle; the key backend wraps it in a DSSE envelope
	// (caller must supply options.WithPayloadType).
	SignMessage(data []byte, funcs ...options.SignOptFn) (SignedArtifact, error)
}
