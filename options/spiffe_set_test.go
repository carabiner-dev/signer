// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const testWorkloadPath = "/workload"

func TestSpiffeCommonValidate(t *testing.T) {
	t.Parallel()

	t.Run("empty-passes", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, DefaultSpiffeCommon().Validate())
	})

	t.Run("valid-trust-domain", func(t *testing.T) {
		t.Parallel()
		c := &SpiffeCommon{TrustDomain: "prod.example.org"}
		require.NoError(t, c.Validate())
	})

	t.Run("malformed-trust-domain", func(t *testing.T) {
		t.Parallel()
		c := &SpiffeCommon{TrustDomain: "not a trust domain!"}
		err := c.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing trust domain")
	})
}

func TestSpiffeCommonParseTrustDomain(t *testing.T) {
	t.Parallel()

	t.Run("empty-returns-zero-no-error", func(t *testing.T) {
		t.Parallel()
		c := DefaultSpiffeCommon()
		td, err := c.ParseTrustDomain()
		require.NoError(t, err)
		require.True(t, td.IsZero(), "empty TrustDomain → zero value")
	})

	t.Run("set-returns-parsed", func(t *testing.T) {
		t.Parallel()
		c := &SpiffeCommon{TrustDomain: "example.org"}
		td, err := c.ParseTrustDomain()
		require.NoError(t, err)
		require.Equal(t, "example.org", td.Name())
	})
}

func TestSpiffeSignAddFlags(t *testing.T) {
	t.Parallel()

	t.Run("registers-bare-socket-flag", func(t *testing.T) {
		t.Parallel()
		s := DefaultSpiffeSign(nil)
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)
		require.NotNil(t, cmd.PersistentFlags().Lookup("socket"))
	})

	t.Run("flag-prefix-applies", func(t *testing.T) {
		t.Parallel()
		s := DefaultSpiffeSign(nil)
		s.Config().FlagPrefix = "spiffe"
		cmd := &cobra.Command{Use: "test"}
		s.AddFlags(cmd)
		require.NotNil(t, cmd.PersistentFlags().Lookup("spiffe-socket"))
	})
}

func TestSpiffeSignEffectiveSocketPath(t *testing.T) {
	// No t.Parallel: t.Setenv conflicts with parallel chains.

	t.Run("explicit-flag-wins", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "/from/env")
		s := DefaultSpiffeSign(nil)
		s.SocketPath = "/from/flag"
		require.Equal(t, "/from/flag", s.EffectiveSocketPath())
	})

	t.Run("env-fallback", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "/from/env")
		s := DefaultSpiffeSign(nil)
		require.Equal(t, "/from/env", s.EffectiveSocketPath())
	})

	t.Run("neither-empty", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		s := DefaultSpiffeSign(nil)
		require.Empty(t, s.EffectiveSocketPath())
	})
}

func TestSpiffeSignValidate(t *testing.T) {
	// No t.Parallel: t.Setenv conflicts with parallel chains.

	t.Run("missing-socket-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		s := DefaultSpiffeSign(nil)
		err := s.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SPIFFE_ENDPOINT_SOCKET")
	})

	t.Run("env-satisfies-validation", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/sock")
		s := DefaultSpiffeSign(nil)
		require.NoError(t, s.Validate())
	})

	t.Run("flag-satisfies-validation", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
		s := DefaultSpiffeSign(nil)
		s.SocketPath = "unix:///tmp/sock"
		require.NoError(t, s.Validate())
	})

	t.Run("nil-common-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/sock")
		s := &SpiffeSign{}
		err := s.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SpiffeCommon is nil")
	})

	t.Run("invalid-trust-domain-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/sock")
		s := DefaultSpiffeSign(nil)
		s.TrustDomain = "not a trust domain!"
		err := s.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "trust domain")
	})
}

func TestSpiffeVerifyValidate(t *testing.T) {
	// No t.Parallel: t.Setenv conflicts with parallel chains.

	t.Run("missing-bundle-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		v := DefaultSpiffeVerify(nil)
		err := v.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SPIFFE_TRUST_BUNDLE")
	})

	t.Run("trust-bundle-flag-satisfies", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		v := DefaultSpiffeVerify(nil)
		v.TrustBundlePath = "/tmp/bundle.pem"
		require.NoError(t, v.Validate())
	})

	t.Run("trust-bundle-env-satisfies", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "/tmp/bundle.pem")
		v := DefaultSpiffeVerify(nil)
		require.NoError(t, v.Validate())
	})

	t.Run("trust-bundle-pem-satisfies", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		v := DefaultSpiffeVerify(nil)
		v.TrustBundlePEM = []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
		require.NoError(t, v.Validate())
	})

	t.Run("path-and-regex-mutually-exclusive", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "/tmp/bundle.pem")
		v := DefaultSpiffeVerify(nil)
		v.Path = testWorkloadPath
		v.PathRegex = "^/work.*$"
		err := v.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("malformed-path-regex", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "/tmp/bundle.pem")
		v := DefaultSpiffeVerify(nil)
		v.PathRegex = "[unclosed"
		err := v.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "compiling --spiffe-path-regex")
	})

	t.Run("nil-common-fails", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "/tmp/bundle.pem")
		v := &SpiffeVerify{}
		err := v.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "SpiffeCommon is nil")
	})
}

func TestSpiffeVerifyApplyTo(t *testing.T) {
	// No t.Parallel: t.Setenv conflicts with parallel chains.

	t.Run("populates-all-fields", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "")
		v := DefaultSpiffeVerify(nil)
		v.TrustDomain = "prod.example.org"
		v.TrustBundlePath = "/path/to/bundle.pem"
		v.Path = testWorkloadPath
		target := &Verification{}
		require.NoError(t, v.ApplyTo(target))
		require.Equal(t, "/path/to/bundle.pem", target.TrustRootsPath)
		require.Equal(t, "prod.example.org", target.ExpectedTrustDomain)
		require.Equal(t, testWorkloadPath, target.ExpectedPath)
	})

	t.Run("env-fallback-flows-into-target", func(t *testing.T) {
		t.Setenv("SPIFFE_TRUST_BUNDLE", "/from/env")
		v := DefaultSpiffeVerify(nil)
		target := &Verification{}
		require.NoError(t, v.ApplyTo(target))
		require.Equal(t, "/from/env", target.TrustRootsPath)
	})

	t.Run("nil-target-errors", func(t *testing.T) {
		v := DefaultSpiffeVerify(nil)
		require.Error(t, v.ApplyTo(nil))
	})

	t.Run("nil-common-errors", func(t *testing.T) {
		v := &SpiffeVerify{}
		require.Error(t, v.ApplyTo(&Verification{}))
	})
}

func TestSpiffeSignSet(t *testing.T) {
	t.Parallel()

	t.Run("registers-prefixed-flags", func(t *testing.T) {
		t.Parallel()
		set := DefaultSpiffeSignSet("spiffe")
		cmd := &cobra.Command{Use: "test"}
		set.AddFlags(cmd)
		for _, name := range []string{"spiffe-trust-domain", "spiffe-socket"} {
			require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %s must be registered", name)
		}
	})

	t.Run("validate-zero-value-fails", func(t *testing.T) {
		t.Parallel()
		require.Error(t, (&SpiffeSignSet{}).Validate())
	})
}

// TestSpiffeSignSetValidateNoSocket lives at the top level because
// t.Setenv is incompatible with parallel-aware test chains.
func TestSpiffeSignSetValidateNoSocket(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	require.Error(t, DefaultSpiffeSignSet("spiffe").Validate())
}

func TestSpiffeVerifySet(t *testing.T) {
	t.Parallel()

	t.Run("registers-prefixed-flags", func(t *testing.T) {
		t.Parallel()
		set := DefaultSpiffeVerifySet("spiffe")
		cmd := &cobra.Command{Use: "test"}
		set.AddFlags(cmd)
		for _, name := range []string{
			"spiffe-trust-domain",
			"spiffe-trust-bundle",
			"spiffe-path",
			"spiffe-path-regex",
		} {
			require.NotNil(t, cmd.PersistentFlags().Lookup(name), "flag %s must be registered", name)
		}
	})

	t.Run("validate-zero-value-fails", func(t *testing.T) {
		t.Parallel()
		require.Error(t, (&SpiffeVerifySet{}).Validate())
	})
}

// TestSpiffeVerifySetApplyTo lives at the top level because t.Setenv
// is incompatible with parallel-aware test chains.
func TestSpiffeVerifySetApplyTo(t *testing.T) {
	t.Setenv("SPIFFE_TRUST_BUNDLE", "/from/env")
	set := DefaultSpiffeVerifySet("spiffe")
	set.Verify.Path = testWorkloadPath
	target := &Verification{}
	require.NoError(t, set.ApplyTo(target))
	require.Equal(t, "/from/env", target.TrustRootsPath)
	require.Equal(t, testWorkloadPath, target.ExpectedPath)
}

// TestSpiffeCommonSharedBetweenSignAndVerify documents the
// recommended pattern: one *SpiffeCommon shared by pointer between
// the sign and verify sets, so --<prefix>-trust-domain is registered
// once and seen by both.
func TestSpiffeCommonSharedBetweenSignAndVerify(t *testing.T) {
	t.Parallel()
	common := DefaultSpiffeCommon()
	sign := DefaultSpiffeSign(common)
	verify := DefaultSpiffeVerify(common)

	require.Same(t, common, sign.SpiffeCommon)
	require.Same(t, common, verify.SpiffeCommon)

	common.TrustDomain = "shared.example.org"
	require.Equal(t, "shared.example.org", sign.TrustDomain)
	require.Equal(t, "shared.example.org", verify.TrustDomain)
}

// helper used to assert a synthesized trust-bundle file works for
// EffectiveTrustBundlePath path-precedence semantics; not currently
// needed but kept here as documentation of how to extend coverage if
// we add a "file vs env precedence" test later.
func writeStubTrustBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), 0o600))
	return path
}

// reference the helper to avoid unused-symbol lint when no test
// currently needs it. It's intentionally kept as a one-line
// scaffolding hook.
var _ = writeStubTrustBundle
