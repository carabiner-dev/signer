// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/signer/spiffe"
)

// SignerSet is the top-level sign-side OptionsSet that bundles every
// backend-specific child set behind a single --backend discriminator
// flag. AddFlags registers --backend plus every child's flags so the
// CLI's --help shows the full surface; Validate and BuildSigner act
// only on the child selected by --backend, so non-selected children
// are inert.
//
// Typical use:
//
//	set := DefaultSignerSet()
//	set.AddFlags(cmd)
//	// ... after cobra parses ...
//	if err := set.Validate(); err != nil { ... }
//	opts, err := set.BuildSigner()
//	creds, err := set.BuildCredentialProvider()
//	runtime := signer.NewSigner()
//	runtime.Options = *opts
//	if creds != nil {
//	    runtime.Credentials = creds
//	}
//
// SPIFFE is the only backend that needs a separate credential
// provider; for sigstore and key BuildCredentialProvider returns
// (nil, nil) and the runtime signer's auto-build / unused-credentials
// behavior takes over.
type SignerSet struct {
	// Backend selects which child set Validate/BuildSigner consult.
	// Bound to --backend. Empty resolves to BackendSigstore, matching
	// the runtime signer's default.
	Backend string

	Keys     *KeysSign
	Sigstore *SigstoreSignSet
	Spiffe   *SpiffeSignSet

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*SignerSet)(nil)

// DefaultSignerSet builds a SignerSet with every child constructed
// under its conventional flag prefix ("sigstore", "spiffe"; KeysSign
// uses its own --signing-key namespace). The default Backend is
// BackendSigstore — empty resolves the same way the runtime signer
// does, but the explicit value is what shows up in --help.
func DefaultSignerSet() *SignerSet {
	return &SignerSet{
		Backend:  string(BackendSigstore),
		Keys:     DefaultKeysSign(),
		Sigstore: DefaultSigstoreSignSet("sigstore"),
		Spiffe:   DefaultSpiffeSignSet("spiffe"),
	}
}

// Config returns the flag config for the --backend flag itself.
// Children expose their own Config() and remain the authoritative
// source for their flag namespaces.
func (s *SignerSet) Config() *command.OptionsSetConfig {
	if s.config == nil {
		s.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"backend": {
					Long: "backend",
					Help: fmt.Sprintf("signing backend (%s | %s | %s)", BackendKey, BackendSigstore, BackendSpiffe),
				},
			},
		}
	}
	return s.config
}

// AddFlags registers --backend and every non-nil child's flags. Order
// is fixed (backend → keys → sigstore → spiffe) so --help output is
// stable across runs.
func (s *SignerSet) AddFlags(cmd *cobra.Command) {
	cfg := s.Config()
	cmd.PersistentFlags().StringVar(
		&s.Backend,
		cfg.LongFlag("backend"),
		s.Backend,
		cfg.HelpText("backend"),
	)
	if s.Keys != nil {
		s.Keys.AddFlags(cmd)
	}
	if s.Sigstore != nil {
		s.Sigstore.AddFlags(cmd)
	}
	if s.Spiffe != nil {
		s.Spiffe.AddFlags(cmd)
	}
}

// resolveBackend returns the Backend value to dispatch on, defaulting
// empty to BackendSigstore (matching signer.Signer's own resolution).
func (s *SignerSet) resolveBackend() (Backend, error) {
	if s.Backend == "" {
		return BackendSigstore, nil
	}
	switch Backend(s.Backend) {
	case BackendKey, BackendSigstore, BackendSpiffe:
		return Backend(s.Backend), nil
	default:
		return "", fmt.Errorf("SignerSet: unknown --backend %q (valid: %s, %s, %s)",
			s.Backend, BackendKey, BackendSigstore, BackendSpiffe)
	}
}

// Validate checks --backend is recognized and validates the selected
// child only. Non-selected children are not consulted, so their flags
// can be left unset without failing validation.
func (s *SignerSet) Validate() error {
	backend, err := s.resolveBackend()
	if err != nil {
		return err
	}
	switch backend {
	case BackendKey:
		if s.Keys == nil {
			return errors.New("SignerSet: --backend=key but Keys is nil")
		}
		return s.Keys.Validate()
	case BackendSigstore:
		if s.Sigstore == nil {
			return errors.New("SignerSet: --backend=sigstore but Sigstore is nil")
		}
		return s.Sigstore.Validate()
	case BackendSpiffe:
		if s.Spiffe == nil {
			return errors.New("SignerSet: --backend=spiffe but Spiffe is nil")
		}
		return s.Spiffe.Validate()
	default:
		return fmt.Errorf("SignerSet: unhandled backend %q", backend)
	}
}

// BuildSigner dispatches on --backend and returns the populated
// *Signer for that backend. SPIFFE callers must additionally call
// BuildCredentialProvider and assign the result to
// signer.Signer.Credentials before any Sign* call.
func (s *SignerSet) BuildSigner() (*Signer, error) {
	backend, err := s.resolveBackend()
	if err != nil {
		return nil, err
	}
	switch backend {
	case BackendKey:
		if s.Keys == nil {
			return nil, errors.New("SignerSet: --backend=key but Keys is nil")
		}
		return s.Keys.BuildSigner()
	case BackendSigstore:
		if s.Sigstore == nil {
			return nil, errors.New("SignerSet: --backend=sigstore but Sigstore is nil")
		}
		return s.Sigstore.BuildSigner()
	case BackendSpiffe:
		if s.Spiffe == nil {
			return nil, errors.New("SignerSet: --backend=spiffe but Spiffe is nil")
		}
		return s.Spiffe.BuildSigner()
	default:
		return nil, fmt.Errorf("SignerSet: unhandled backend %q", backend)
	}
}

// BuildCredentialProvider returns the *spiffe.CredentialProvider
// needed to arm signer.Signer.Credentials for the SPIFFE backend.
// Returns (nil, nil) for backends that don't need an externally-
// supplied provider — sigstore lazy-builds from Options on first
// signing call; key has no credentials concept.
func (s *SignerSet) BuildCredentialProvider() (*spiffe.CredentialProvider, error) {
	backend, err := s.resolveBackend()
	if err != nil {
		return nil, err
	}
	if backend != BackendSpiffe {
		return nil, nil
	}
	if s.Spiffe == nil {
		return nil, errors.New("SignerSet: --backend=spiffe but Spiffe is nil")
	}
	return s.Spiffe.BuildCredentialProvider()
}
