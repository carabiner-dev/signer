// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sigstore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// unreachableTUF is a mirror URL that fails fast on any platform, so tests can
// assert offline behavior deterministically: if a code path reaches TUF it
// errors, which lets NoError prove the embed was used instead.
const unreachableTUF = "http://127.0.0.1:1"

// TestTrustedRootEmbeddedFresh proves the fast path: a fresh embed is returned
// with no network. The bogus TUF URL guarantees that if the code consulted TUF
// it would error, so NoError means the embedded copy was used.
func TestTrustedRootEmbeddedFresh(t *testing.T) {
	t.Parallel()
	roots, err := ParseRoots(DefaultRoots)
	require.NoError(t, err)
	ic := roots.Roots[0]
	require.Equal(t, "sigstore", ic.ID)
	ic.TrustedRootSnapshot = time.Now() // force fresh regardless of run date
	ic.TufRootURL = unreachableTUF      // would fail if TUF were consulted

	tr, err := ic.TrustedRoot()
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
}

// TestTrustedRootStaleFallsBackToEmbed exercises the resilient fallback: with a
// zero MaxAge the embed is considered stale, so TUF is attempted; TUF is
// unreachable, so the stale embed must still be returned.
func TestTrustedRootStaleFallsBackToEmbed(t *testing.T) {
	t.Parallel()
	roots, err := ParseRoots(DefaultRoots)
	require.NoError(t, err)
	ic := roots.Roots[0]
	ic.TufRootURL = unreachableTUF

	tr, err := ic.TrustedRoot(WithMaxAge(0))
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
}

// TestTrustedRootOverrideJSON checks WithTrustedRootJSON wins and parses.
func TestTrustedRootOverrideJSON(t *testing.T) {
	t.Parallel()
	data, err := readEmbeddedTrustedRoot("sigstore")
	require.NoError(t, err)

	tr, err := TrustedRoot(WithTrustedRootJSON(data))
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
}

// TestTrustedRootOverrideJSONInvalid checks a bad override surfaces an error.
func TestTrustedRootOverrideJSONInvalid(t *testing.T) {
	t.Parallel()
	_, err := TrustedRoot(WithTrustedRootJSON([]byte("{not-json")))
	require.Error(t, err)
}

// TestTrustedRootOverridePath checks WithTrustedRootPath wins and parses.
func TestTrustedRootOverridePath(t *testing.T) {
	t.Parallel()
	data, err := readEmbeddedTrustedRoot("sigstore")
	require.NoError(t, err)
	p := filepath.Join(t.TempDir(), "trusted_root.json")
	require.NoError(t, os.WriteFile(p, data, 0o600))

	tr, err := TrustedRoot(WithTrustedRootPath(p))
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
}

// TestTrustedRootWithInstanceGithub checks WithInstance selects the github
// instance and resolves its embedded root. Snapshots are forced fresh and the
// TUF URL made unreachable so the assertion holds offline.
func TestTrustedRootWithInstanceGithub(t *testing.T) {
	t.Parallel()
	roots, err := ParseRoots(DefaultRoots)
	require.NoError(t, err)
	for i := range roots.Roots {
		roots.Roots[i].TrustedRootSnapshot = time.Now()
		roots.Roots[i].TufRootURL = unreachableTUF
	}

	tr, err := TrustedRoot(WithRoots(roots), WithInstance("github"))
	require.NoError(t, err)
	require.NotNil(t, tr)
	// The github trusted root ships several Fulcio authorities.
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
}

// TestTrustedRootUnknownInstance checks an unknown id errors before any
// network work.
func TestTrustedRootUnknownInstance(t *testing.T) {
	t.Parallel()
	_, err := TrustedRoot(WithInstance("does-not-exist"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "does-not-exist")
}

// TestTrustedRootDefaultInstance checks the package-level accessor defaults to
// Roots[0] (public-good) and resolves it via the fresh embed offline.
func TestTrustedRootDefaultInstance(t *testing.T) {
	t.Parallel()
	roots, err := ParseRoots(DefaultRoots)
	require.NoError(t, err)
	for i := range roots.Roots {
		roots.Roots[i].TrustedRootSnapshot = time.Now()
		roots.Roots[i].TufRootURL = unreachableTUF
	}

	tr, err := TrustedRoot(WithRoots(roots))
	require.NoError(t, err)
	require.NotNil(t, tr)
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
}
