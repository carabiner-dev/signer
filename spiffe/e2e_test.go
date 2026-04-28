// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package spiffe_test

import (
	"context"
	"os"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"

	signerlib "github.com/carabiner-dev/signer"
	api "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
	"github.com/carabiner-dev/signer/spiffe"
)

// TestE2ESPIFFESignAndVerify exercises the full SPIFFE pipeline against a
// real SPIRE fixture:
//
//   - talk to spire-agent over the Workload API socket
//   - sign an in-toto statement with the issued SVID
//   - assert the resulting bundle carries a leaf + intermediate (the
//     fixture's UpstreamAuthority produces a non-trivial chain)
//   - verify the bundle against the exported upstream CA
//   - translate the verification result into api/v1.SignatureVerification
//     and match the SPIFFE identity
//
// Requires `make spire-up` to have run first; skipped otherwise.
func TestE2ESPIFFESignAndVerify(t *testing.T) {
	socketAddr := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	bundlePath := os.Getenv("SPIFFE_TRUST_BUNDLE")
	if socketAddr == "" || bundlePath == "" {
		t.Skip("SPIFFE_ENDPOINT_SOCKET / SPIFFE_TRUST_BUNDLE unset — run `make spire-up` first")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	source, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socketAddr)))
	require.NoError(t, err, "connecting to the Workload API")
	t.Cleanup(func() {
		if cerr := source.Close(); cerr != nil {
			t.Logf("closing workload API source: %v", cerr)
		}
	})

	// Sanity check before signing: the agent actually gave us an SVID.
	svid, err := source.GetX509SVID()
	require.NoError(t, err, "fetching initial SVID")
	require.NotNil(t, svid)
	require.Equal(t, "test.local", svid.ID.TrustDomain().Name())
	require.Equal(t, "/workload", svid.ID.Path())

	// Sign
	signer := signerlib.NewSigner()
	signer.Credentials = &spiffe.CredentialProvider{Source: source}
	statement := []byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"e2e","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}],` +
		`"predicateType":"https://example.com/p/v1",` +
		`"predicate":{}` +
		`}`)
	bndl, err := signer.SignStatementBundle(statement)
	require.NoError(t, err, "signing statement")
	require.NotNil(t, bndl)

	// The UpstreamAuthority chain means the SVID has at least [leaf,
	// intermediate] — assert the bundle carried that through.
	chain, ok := bndl.Bundle.GetVerificationMaterial().GetContent().(*protobundle.VerificationMaterial_X509CertificateChain)
	require.True(t, ok, "expected X509CertificateChain content (UpstreamAuthority produces intermediates), got %T",
		bndl.Bundle.GetVerificationMaterial().GetContent())
	require.GreaterOrEqual(t, len(chain.X509CertificateChain.GetCertificates()), 2,
		"expected at least leaf + intermediate in chain")

	// Verify against the pinned upstream root.
	verifier := signerlib.NewVerifier(func(v *options.Verifier) {
		v.TrustRootsPath = bundlePath
	})
	result, err := verifier.VerifyParsedBundle(bndl)
	require.NoError(t, err, "verifying bundle")
	require.NotNil(t, result)
	require.NotNil(t, result.VerifiedIdentity)
	require.Equal(t, "spiffe://test.local/workload",
		result.VerifiedIdentity.SubjectAlternativeName.SubjectAlternativeName)

	// Identity matching via the api/v1 layer.
	sv := api.SignatureVerificationFromResult(result)
	require.True(t, sv.GetVerified())

	require.True(t, sv.MatchesIdentity(&api.Identity{
		Spiffe: &api.IdentitySpiffe{
			Svid: "spiffe://test.local/workload",
		},
	}), "exact SVID pin should match the issued SVID")

	require.True(t, sv.MatchesIdentity(&api.Identity{
		Spiffe: &api.IdentitySpiffe{
			TrustDomainMatch: &api.StringMatcher{
				Kind: &api.StringMatcher_Exact{Exact: "test.local"},
			},
			PathMatch: &api.StringMatcher{
				Kind: &api.StringMatcher_Exact{Exact: "/workload"},
			},
		},
	}), "trust-domain + path component match should succeed")

	require.False(t, sv.MatchesIdentity(&api.Identity{
		Spiffe: &api.IdentitySpiffe{
			TrustDomainMatch: &api.StringMatcher{
				Kind: &api.StringMatcher_Exact{Exact: "other.example"},
			},
		},
	}), "wrong trust domain should not match")

	require.True(t, sv.MatchesIdentity(&api.Identity{
		Spiffe: &api.IdentitySpiffe{
			TrustDomainMatch: &api.StringMatcher{
				Kind: &api.StringMatcher_Exact{Exact: "test.local"},
			},
			PathMatch: &api.StringMatcher{
				// matchString anchors regex to the full input.
				Kind: &api.StringMatcher_Regex{Regex: `/work.*`},
			},
		},
	}), "regex path match should succeed")
}

// TestE2ESPIFFESignAndVerifyWithTimestamp exercises the TSA-stamped
// SPIFFE pipeline: sign with --signing-timestamp on, then verify
// against the SPIRE upstream root *and* sigstore's TSA. Verifies both
// that the bundle carries an RFC 3161 TimeStampToken and that the
// SPIFFE verifier reports verified timestamps in the result.
//
// Requires `make spire-up` AND outbound network reachability to
// timestamp.sigstore.dev. Skipped without env vars; the t.Logf branch
// records when network failure means we couldn't validate the path.
func TestE2ESPIFFESignAndVerifyWithTimestamp(t *testing.T) {
	socketAddr := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	bundlePath := os.Getenv("SPIFFE_TRUST_BUNDLE")
	if socketAddr == "" || bundlePath == "" {
		t.Skip("SPIFFE_ENDPOINT_SOCKET / SPIFFE_TRUST_BUNDLE unset — run `make spire-up` first")
	}

	// Build the signer through the bundled SignerSet path with TSA on
	// (default for SPIFFE in DefaultSignerSet).
	set := options.DefaultSignerSet()
	set.Backend = string(options.BackendSpiffe)
	set.Spiffe.Sign.SocketPath = socketAddr
	require.True(t, set.Timestamp, "DefaultSignerSet should default Timestamp=true")

	s, err := signerlib.NewSignerFromSet(set)
	require.NoError(t, err, "building signer from set")
	t.Cleanup(func() {
		if cerr := s.Close(); cerr != nil {
			t.Logf("closing signer: %v", cerr)
		}
	})

	statement := []byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"e2e-tsa","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}],` +
		`"predicateType":"https://example.com/p/v1",` +
		`"predicate":{}` +
		`}`)
	bndl, err := s.SignStatementBundle(statement)
	if err != nil {
		// TSA POST may have failed (network / sigstore.dev availability).
		// Skip rather than fail to keep the test useful in offline CI.
		t.Skipf("signing with TSA failed (may be a network issue): %v", err)
	}

	// Bundle should carry the RFC 3161 TimeStampToken.
	require.NotNil(t, bndl.GetVerificationMaterial())
	require.NotNil(t, bndl.GetVerificationMaterial().GetTimestampVerificationData(),
		"TSA-stamped bundle must carry timestamp verification data")
	require.NotEmpty(t, bndl.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps(),
		"TSA-stamped bundle must carry at least one RFC 3161 token")

	// Verify — the SPIFFE verifier should validate the TSA token
	// against the embedded sigstore TSA root, populate
	// VerifiedTimestamps, and use the verified time for SVID chain
	// validation (proven indirectly: verification succeeds).
	verifier := signerlib.NewVerifier(func(v *options.Verifier) {
		v.TrustRootsPath = bundlePath
	})
	result, err := verifier.VerifyParsedBundle(bndl)
	require.NoError(t, err, "verifying TSA-stamped bundle")
	require.NotNil(t, result)
	require.NotEmpty(t, result.VerifiedTimestamps,
		"SPIFFE verifier must report at least one verified TSA timestamp")
	require.Equal(t, "TimestampAuthority", result.VerifiedTimestamps[0].Type)
}
