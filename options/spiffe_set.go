// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/carabiner-dev/signer/spiffe"
)

// Standard SPIFFE-related env vars used as fallbacks when the
// corresponding flag is not supplied. SPIFFE_ENDPOINT_SOCKET is the
// canonical Workload API discovery variable defined by the SPIFFE
// spec; SPIFFE_TRUST_BUNDLE is signer-specific (we picked it for the
// trust-bundle path).
const (
	spiffeSocketEnv      = "SPIFFE_ENDPOINT_SOCKET"
	spiffeTrustBundleEnv = "SPIFFE_TRUST_BUNDLE"
)

// SpiffeCommon holds the SPIFFE configuration shared between
// SpiffeSign and SpiffeVerify. Tools that expose both operations
// construct one *SpiffeCommon, share it via pointer in their
// SpiffeSign and SpiffeVerify, and call SpiffeCommon.AddFlags(cmd)
// once so --spiffe-trust-domain is registered exactly once.
type SpiffeCommon struct {
	// TrustDomain is the expected SPIFFE trust domain (e.g.
	// "prod.example.org"). Used at sign time to assert the issued
	// SVID belongs to this trust domain, and at verify time to
	// require the SVID's trust domain matches.
	TrustDomain string

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SpiffeCommon)(nil)

// DefaultSpiffeCommon returns an empty SpiffeCommon ready to bind
// flags.
func DefaultSpiffeCommon() *SpiffeCommon { return &SpiffeCommon{} }

// Config returns the flag configuration for SpiffeCommon.
func (c *SpiffeCommon) Config() *command.OptionsSetConfig {
	if c.config == nil {
		c.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"trust-domain": {
					Long: "trust-domain",
					Help: "expected SPIFFE trust domain (e.g. prod.example.org)",
				},
			},
		}
	}
	return c.config
}

// AddFlags registers the SpiffeCommon flags on cmd.
func (c *SpiffeCommon) AddFlags(cmd *cobra.Command) {
	cfg := c.Config()
	cmd.PersistentFlags().StringVar(
		&c.TrustDomain,
		cfg.LongFlag("trust-domain"),
		c.TrustDomain,
		cfg.HelpText("trust-domain"),
	)
}

// Validate checks that the trust-domain string parses (when set).
// Empty TrustDomain is valid — it just means "don't constrain".
func (c *SpiffeCommon) Validate() error {
	_, err := c.ParseTrustDomain()
	return err
}

// ParseTrustDomain returns the configured TrustDomain parsed as a
// spiffeid.TrustDomain. Returns the zero value (and a nil error)
// when TrustDomain is empty — empty means "no constraint".
func (c *SpiffeCommon) ParseTrustDomain() (spiffeid.TrustDomain, error) {
	if c.TrustDomain == "" {
		return spiffeid.TrustDomain{}, nil
	}
	td, err := spiffeid.TrustDomainFromString(c.TrustDomain)
	if err != nil {
		return spiffeid.TrustDomain{}, fmt.Errorf("parsing trust domain %q: %w", c.TrustDomain, err)
	}
	return td, nil
}

// SpiffeSign is the OptionsSet for the signing side of a SPIFFE
// workflow. It carries the Workload API socket path (with env
// fallback) used to fetch the X.509-SVID.
type SpiffeSign struct {
	*SpiffeCommon

	// SocketPath is the SPIFFE Workload API endpoint
	// (typically "unix:///run/spire/sockets/api.sock"). Empty falls
	// back to the SPIFFE_ENDPOINT_SOCKET env var; if both are empty,
	// Validate fails.
	SocketPath string

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SpiffeSign)(nil)

// DefaultSpiffeSign builds a SpiffeSign sharing the supplied common.
// Pass nil to allocate a fresh one.
func DefaultSpiffeSign(common *SpiffeCommon) *SpiffeSign {
	if common == nil {
		common = DefaultSpiffeCommon()
	}
	return &SpiffeSign{SpiffeCommon: common}
}

// Config returns the flag configuration for SpiffeSign.
func (s *SpiffeSign) Config() *command.OptionsSetConfig {
	if s.config == nil {
		s.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"socket": {
					Long: "socket",
					Help: "SPIFFE Workload API socket (e.g. unix:///run/spire/sockets/api.sock; env fallback: " + spiffeSocketEnv + ")",
				},
			},
		}
	}
	return s.config
}

// AddFlags registers SpiffeSign flags. Assumes the caller registers
// SpiffeCommon's flags separately so --<prefix>-trust-domain is not
// registered twice.
func (s *SpiffeSign) AddFlags(cmd *cobra.Command) {
	cfg := s.Config()
	cmd.PersistentFlags().StringVar(
		&s.SocketPath,
		cfg.LongFlag("socket"),
		s.SocketPath,
		cfg.HelpText("socket"),
	)
}

// EffectiveSocketPath returns the explicit SocketPath when set, or
// the SPIFFE_ENDPOINT_SOCKET env var otherwise. Empty when neither
// is set.
func (s *SpiffeSign) EffectiveSocketPath() string {
	if s.SocketPath != "" {
		return s.SocketPath
	}
	return os.Getenv(spiffeSocketEnv)
}

// Validate ensures the trust-domain parses (when set) and that a
// Workload API socket is available either via flag or env var.
func (s *SpiffeSign) Validate() error {
	if s.SpiffeCommon == nil {
		return errors.New("SpiffeSign: SpiffeCommon is nil")
	}
	if err := s.SpiffeCommon.Validate(); err != nil {
		return err
	}
	if s.EffectiveSocketPath() == "" {
		return fmt.Errorf("no SPIFFE socket configured (pass --spiffe-socket or set %s)", spiffeSocketEnv)
	}
	return nil
}

// BuildCredentialProvider constructs a *spiffe.CredentialProvider
// from the resolved options (effective socket path + parsed trust
// domain). The Sign side of signer/spiffe is decoupled from
// signer/options (the Verifier lives in signer/spiffe/verifier so
// importing the sign package back here is cycle-free).
func (s *SpiffeSign) BuildCredentialProvider() (*spiffe.CredentialProvider, error) {
	socket := s.EffectiveSocketPath()
	if socket == "" {
		return nil, fmt.Errorf("no SPIFFE socket configured (pass --spiffe-socket or set %s)", spiffeSocketEnv)
	}
	td, err := s.ParseTrustDomain()
	if err != nil {
		return nil, err
	}
	return spiffe.NewCredentialProvider(spiffe.Options{
		SocketPath:          socket,
		ExpectedTrustDomain: td,
	}), nil
}

// SpiffeVerify is the OptionsSet for the verification side of a
// SPIFFE workflow. It carries the trust bundle (file path with env
// fallback, or programmatic PEM) plus the optional path constraints.
type SpiffeVerify struct {
	*SpiffeCommon

	// TrustBundlePath is a filesystem path to a PEM-encoded SPIRE
	// upstream CA bundle. Empty falls back to SPIFFE_TRUST_BUNDLE.
	TrustBundlePath string

	// TrustBundlePEM is inline PEM-encoded trust roots set
	// programmatically. Not bound to a CLI flag — callers building
	// the verifier in code use this to skip the file step.
	TrustBundlePEM []byte

	// Path constrains the SVID's path component to this exact value.
	// Mutually exclusive with PathRegex.
	Path string

	// PathRegex constrains the SVID's path to match this regex.
	// Anchored at match time by the verifier. Mutually exclusive
	// with Path.
	PathRegex string

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SpiffeVerify)(nil)

// DefaultSpiffeVerify builds a SpiffeVerify sharing the supplied
// common. Pass nil to allocate a fresh one.
func DefaultSpiffeVerify(common *SpiffeCommon) *SpiffeVerify {
	if common == nil {
		common = DefaultSpiffeCommon()
	}
	return &SpiffeVerify{SpiffeCommon: common}
}

// Config returns the flag configuration for SpiffeVerify.
func (v *SpiffeVerify) Config() *command.OptionsSetConfig {
	if v.config == nil {
		v.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"trust-bundle": {
					Long: "trust-bundle",
					Help: "path to a PEM-encoded SPIFFE/SPIRE trust bundle (env fallback: " + spiffeTrustBundleEnv + ")",
				},
				"path": {
					Long: "path",
					Help: "exact SVID path the leaf must carry (mutually exclusive with --spiffe-path-regex)",
				},
				"path-regex": {
					Long: "path-regex",
					Help: "regex the SVID path must match (anchored; mutually exclusive with --spiffe-path)",
				},
			},
		}
	}
	return v.config
}

// AddFlags registers SpiffeVerify flags. Assumes the caller registers
// SpiffeCommon's flags separately.
func (v *SpiffeVerify) AddFlags(cmd *cobra.Command) {
	cfg := v.Config()
	pf := cmd.PersistentFlags()
	pf.StringVar(&v.TrustBundlePath, cfg.LongFlag("trust-bundle"), v.TrustBundlePath, cfg.HelpText("trust-bundle"))
	pf.StringVar(&v.Path, cfg.LongFlag("path"), v.Path, cfg.HelpText("path"))
	pf.StringVar(&v.PathRegex, cfg.LongFlag("path-regex"), v.PathRegex, cfg.HelpText("path-regex"))
}

// EffectiveTrustBundlePath returns the explicit TrustBundlePath when
// set, or the SPIFFE_TRUST_BUNDLE env var otherwise. Empty when
// neither is set.
func (v *SpiffeVerify) EffectiveTrustBundlePath() string {
	if v.TrustBundlePath != "" {
		return v.TrustBundlePath
	}
	return os.Getenv(spiffeTrustBundleEnv)
}

// Validate ensures the trust-domain parses (when set), the path
// constraints aren't both set, the path regex compiles (when set),
// and a trust bundle source is configured (file/env/PEM).
func (v *SpiffeVerify) Validate() error {
	if v.SpiffeCommon == nil {
		return errors.New("SpiffeVerify: SpiffeCommon is nil")
	}
	if err := v.SpiffeCommon.Validate(); err != nil {
		return err
	}
	if v.Path != "" && v.PathRegex != "" {
		return errors.New("--spiffe-path and --spiffe-path-regex are mutually exclusive")
	}
	if v.PathRegex != "" {
		if _, err := regexp.Compile(v.PathRegex); err != nil {
			return fmt.Errorf("compiling --spiffe-path-regex %q: %w", v.PathRegex, err)
		}
	}
	if v.EffectiveTrustBundlePath() == "" && len(v.TrustBundlePEM) == 0 {
		return fmt.Errorf("no SPIFFE trust bundle configured (pass --spiffe-trust-bundle or set %s)", spiffeTrustBundleEnv)
	}
	return nil
}

// ApplyTo populates the SpiffeVerification fields on a Verification
// options struct so the verifier sees the resolved SPIFFE config.
// Reads the env-var fallback for the trust-bundle path so downstream
// code doesn't need to know about it.
func (v *SpiffeVerify) ApplyTo(target *Verification) error {
	if v.SpiffeCommon == nil {
		return errors.New("SpiffeVerify: SpiffeCommon is nil")
	}
	if target == nil {
		return errors.New("ApplyTo: target is nil")
	}
	target.TrustRootsPath = v.EffectiveTrustBundlePath()
	target.TrustRootsPEM = v.TrustBundlePEM
	target.ExpectedTrustDomain = v.TrustDomain
	target.ExpectedPath = v.Path
	target.ExpectedPathRegex = v.PathRegex
	return nil
}

// SpiffeSignSet bundles a SpiffeCommon and a SpiffeSign sharing the
// same flag prefix — the typical shape needed by a CLI signing tool.
type SpiffeSignSet struct {
	Common *SpiffeCommon
	Sign   *SpiffeSign
}

// DefaultSpiffeSignSet builds a SpiffeSignSet with the supplied flag
// prefix applied to both Common and Sign Config(). Empty prefix
// produces bare flag names (--trust-domain, --socket).
func DefaultSpiffeSignSet(flagPrefix string) *SpiffeSignSet {
	common := DefaultSpiffeCommon()
	common.Config().FlagPrefix = flagPrefix
	sign := DefaultSpiffeSign(common)
	sign.Config().FlagPrefix = flagPrefix
	return &SpiffeSignSet{Common: common, Sign: sign}
}

var _ command.OptionsSet = (*SpiffeSignSet)(nil)

// Config returns the SpiffeSign Config — the bundle's primary
// flag-namespace identity.
func (s *SpiffeSignSet) Config() *command.OptionsSetConfig { return s.Sign.Config() }

// AddFlags registers Common and Sign flags in order so the shared
// trust-domain flag is registered exactly once.
func (s *SpiffeSignSet) AddFlags(cmd *cobra.Command) {
	s.Common.AddFlags(cmd)
	s.Sign.AddFlags(cmd)
}

// Validate runs the sign-side validation. Nil-safe.
func (s *SpiffeSignSet) Validate() error {
	if s == nil || s.Sign == nil {
		return errors.New("SpiffeSignSet: nil; construct via DefaultSpiffeSignSet")
	}
	return s.Sign.Validate()
}

// BuildCredentialProvider returns a *spiffe.CredentialProvider built
// from the resolved options. Nil-safe.
func (s *SpiffeSignSet) BuildCredentialProvider() (*spiffe.CredentialProvider, error) {
	if s == nil || s.Sign == nil {
		return nil, errors.New("SpiffeSignSet: nil; construct via DefaultSpiffeSignSet")
	}
	return s.Sign.BuildCredentialProvider()
}

// BuildSigner returns a *Signer wired for the SPIFFE backend: Backend
// set to BackendSpiffe. Callers must additionally call
// BuildCredentialProvider and assign the result to
// signer.Signer.Credentials before signing — the SPIFFE backend
// cannot construct credentials from Options alone. Validates the set
// before returning.
func (s *SpiffeSignSet) BuildSigner() (*Signer, error) {
	if s == nil || s.Sign == nil {
		return nil, errors.New("SpiffeSignSet: nil; construct via DefaultSpiffeSignSet")
	}
	if err := s.Sign.Validate(); err != nil {
		return nil, err
	}
	target := DefaultSigner
	target.Backend = BackendSpiffe
	return &target, nil
}

// SpiffeVerifySet bundles a SpiffeCommon and a SpiffeVerify sharing
// the same flag prefix.
type SpiffeVerifySet struct {
	Common *SpiffeCommon
	Verify *SpiffeVerify
}

// DefaultSpiffeVerifySet builds a SpiffeVerifySet with the supplied
// flag prefix applied to both Common and Verify Config().
func DefaultSpiffeVerifySet(flagPrefix string) *SpiffeVerifySet {
	common := DefaultSpiffeCommon()
	common.Config().FlagPrefix = flagPrefix
	verify := DefaultSpiffeVerify(common)
	verify.Config().FlagPrefix = flagPrefix
	return &SpiffeVerifySet{Common: common, Verify: verify}
}

var _ command.OptionsSet = (*SpiffeVerifySet)(nil)

// Config returns the SpiffeVerify Config.
func (s *SpiffeVerifySet) Config() *command.OptionsSetConfig { return s.Verify.Config() }

// AddFlags registers Common and Verify flags in order.
func (s *SpiffeVerifySet) AddFlags(cmd *cobra.Command) {
	s.Common.AddFlags(cmd)
	s.Verify.AddFlags(cmd)
}

// Validate runs the verify-side validation. Nil-safe.
func (s *SpiffeVerifySet) Validate() error {
	if s == nil || s.Verify == nil {
		return errors.New("SpiffeVerifySet: nil; construct via DefaultSpiffeVerifySet")
	}
	return s.Verify.Validate()
}

// ApplyTo populates target.SpiffeVerification with the resolved
// SPIFFE verifier config. Nil-safe.
func (s *SpiffeVerifySet) ApplyTo(target *Verification) error {
	if s == nil || s.Verify == nil {
		return errors.New("SpiffeVerifySet: nil; construct via DefaultSpiffeVerifySet")
	}
	return s.Verify.ApplyTo(target)
}
