// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/carabiner-dev/signer/api/v1"
	"github.com/carabiner-dev/signer/options"
)

const (
	keylessFixture = "testdata/keyless/generator.intoto.jsonl"
	noCertFixture  = "testdata/keyless/no-cert.intoto.jsonl"
	goBuilderSAN   = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml@refs/heads/main"
	githubIssuer   = "https://token.actions.githubusercontent.com"
)

// rekorTestServer serves the frozen SearchLogQuery response for the
// generator fixture, so its real log entry verifies offline.
func rekorTestServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries/retrieve" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(payload)
		assert.NoError(t, err)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func frozenRekorResponse(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/keyless/rekor-response.json")
	require.NoError(t, err)
	return data
}

// The cert signature extension is captured next to the proto envelope,
// which keeps only spec fields.
func TestParseArtifactKeylessCerts(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	art, err := ParseArtifact(data)
	require.NoError(t, err)
	env, ok := art.(*EnvelopeArtifact)
	require.True(t, ok)
	assert.Equal(t, data, env.Raw)
	require.Len(t, env.SignatureCerts, len(env.Envelope.GetSignatures()))
	assert.Contains(t, string(env.SignatureCerts[0]), "BEGIN CERTIFICATE")

	data, err = os.ReadFile(noCertFixture)
	require.NoError(t, err)
	art, err = ParseArtifact(data)
	require.NoError(t, err)
	env, ok = art.(*EnvelopeArtifact)
	require.True(t, ok)
	assert.Nil(t, env.SignatureCerts)
}

// With Rekor verification off (the default), a keyless envelope is
// UNVERIFIABLE and the reason names the certificate identity and the
// option that would verify it.
func TestVerifyStatementKeylessDisabled(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	res, err := NewVerifier().VerifyStatementBytes(data)
	require.NoError(t, err)
	assert.Equal(t, api.VerificationStatus_UNVERIFIABLE, res.GetSignature().GetStatus())
	assert.Contains(t, res.GetSignature().GetError(), "builder_go_slsa3.yml")
	assert.Contains(t, res.GetSignature().GetError(), "WithRekorVerification")
}

// With Rekor verification on, the frozen log entry vouches for the
// signature: the envelope verifies and the certificate identity is
// recorded.
func TestVerifyStatementKeylessRekor(t *testing.T) {
	t.Parallel()
	ts := rekorTestServer(t, frozenRekorResponse(t))
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	res, err := NewVerifier().VerifyStatementBytes(data,
		options.WithRekorVerification(true), options.WithRekorURL(ts.URL))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, api.VerificationStatus_VERIFIED, res.GetSignature().GetStatus(), res.GetSignature().GetError())
	assert.True(t, res.GetVerified())
	ids := res.GetSignature().GetIdentities()
	require.Len(t, ids, 1)
	assert.Equal(t, goBuilderSAN, ids[0].GetSigstore().GetIdentity())
	assert.Equal(t, githubIssuer, ids[0].GetSigstore().GetIssuer())
}

// A log with no matching entry refutes the envelope: nothing vouches
// for the signature having been made while the certificate lived.
func TestVerifyStatementKeylessNoEntry(t *testing.T) {
	t.Parallel()
	ts := rekorTestServer(t, []byte("[]"))
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	res, err := NewVerifier().VerifyStatementBytes(data,
		options.WithRekorVerification(true), options.WithRekorURL(ts.URL))
	require.NoError(t, err)
	assert.Equal(t, api.VerificationStatus_FAILED, res.GetSignature().GetStatus())
	assert.Contains(t, res.GetSignature().GetError(), "no entry matching")
}

// An unreachable log is not a refutation: the verification could not
// run.
func TestVerifyStatementKeylessLogUnreachable(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	res, err := NewVerifier().VerifyStatementBytes(data,
		options.WithRekorVerification(true), options.WithRekorURL("http://127.0.0.1:1"))
	require.NoError(t, err)
	assert.Equal(t, api.VerificationStatus_UNVERIFIABLE, res.GetSignature().GetStatus())
	assert.Contains(t, res.GetSignature().GetError(), "querying the transparency log")
}

// A keyless envelope with no certificate cannot be looked up.
func TestVerifyStatementKeylessNoCert(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(noCertFixture)
	require.NoError(t, err)
	res, err := NewVerifier().VerifyStatementBytes(data,
		options.WithRekorVerification(true))
	require.NoError(t, err)
	assert.Equal(t, api.VerificationStatus_UNVERIFIABLE, res.GetSignature().GetStatus())
	assert.Contains(t, res.GetSignature().GetError(), "carries no")
}

// A tampered payload still finds the entry (the test log answers
// regardless) but the signature no longer verifies against the
// certificate key.
func TestVerifyStatementKeylessTampered(t *testing.T) {
	t.Parallel()
	ts := rekorTestServer(t, frozenRekorResponse(t))
	data, err := os.ReadFile(keylessFixture)
	require.NoError(t, err)
	tampered := strings.Replace(string(data), `"payload":"`, `"payload":"aaaa`, 1)
	require.NotEqual(t, string(data), tampered)
	res, err := NewVerifier().VerifyStatementBytes([]byte(tampered),
		options.WithRekorVerification(true), options.WithRekorURL(ts.URL))
	require.NoError(t, err)
	assert.Equal(t, api.VerificationStatus_FAILED, res.GetSignature().GetStatus())
	assert.Contains(t, res.GetSignature().GetError(), "does not verify against the certificate")
}
