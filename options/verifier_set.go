// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"
)

// VerifierSet is the top-level verify-side OptionsSet that bundles
// every backend-specific child set behind one AddFlags call. Verify
// composes (unlike sign, which selects): a single bundle may be
// signed via sigstore, SPIFFE, or a raw key, so the verifier needs
// trust material for each path the caller is willing to accept.
//
// AddFlags registers every child's flags so the CLI's --help shows
// the full surface. Validate and ApplyToVerifier consult only the
// children that are Active — i.e., where the user has supplied
// enough configuration to use them. A user verifying a sigstore-only
// bundle leaves --key and --spiffe-trust-bundle unset and gets no
// "missing trust material" error from the inactive children.
//
// Sigstore is always Active when present: the embedded
// sigstore.DefaultRoots make it the baseline verifier even with no
// user flags. Keys is Active when --key is provided. SPIFFE is
// Active when --spiffe-trust-bundle is provided (or
// SPIFFE_TRUST_BUNDLE env var, or programmatic TrustBundlePEM).
//
// Typical use:
//
//	set := DefaultVerifierSet()
//	set.AddFlags(cmd)
//	// ... after cobra parses ...
//	if err := set.Validate(); err != nil { ... }
//	opts, err := set.BuildVerifier()
//	runtime := signer.NewVerifier(func(v *options.Verifier) { *v = *opts })
type VerifierSet struct {
	Keys     *KeysVerify
	Sigstore *SigstoreVerifySet
	Spiffe   *SpiffeVerifySet

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*VerifierSet)(nil)

// DefaultVerifierSet builds a VerifierSet with every child constructed
// under its conventional flag prefix ("sigstore", "spiffe"; KeysVerify
// uses bare --key).
func DefaultVerifierSet() *VerifierSet {
	return &VerifierSet{
		Keys:     DefaultKeysVerify(),
		Sigstore: DefaultSigstoreVerifySet("sigstore"),
		Spiffe:   DefaultSpiffeVerifySet("spiffe"),
	}
}

// Config returns the (empty) flag config for the VerifierSet itself.
// The set has no own flags; every flag belongs to a child whose
// Config() remains the authoritative source for its namespace.
func (v *VerifierSet) Config() *command.OptionsSetConfig {
	if v.config == nil {
		v.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{},
		}
	}
	return v.config
}

// AddFlags registers every non-nil child's flags. Order is fixed
// (keys → sigstore → spiffe) so --help output is stable across runs.
func (v *VerifierSet) AddFlags(cmd *cobra.Command) {
	if v.Keys != nil {
		v.Keys.AddFlags(cmd)
	}
	if v.Sigstore != nil {
		v.Sigstore.AddFlags(cmd)
	}
	if v.Spiffe != nil {
		v.Spiffe.AddFlags(cmd)
	}
}

// Validate runs each Active child's validation, joining any errors so
// callers see every problem at once. Inactive children are skipped —
// their flags can be left unset without failing validation.
func (v *VerifierSet) Validate() error {
	var errs []error
	if v.Keys != nil && v.Keys.Active() {
		if err := v.Keys.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if v.Sigstore != nil && v.Sigstore.Active() {
		if err := v.Sigstore.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	if v.Spiffe != nil && v.Spiffe.Active() {
		if err := v.Spiffe.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ApplyToVerifier composes every Active child's contribution onto
// target. Children write disjoint fields (KeysVerify →
// Verification.PubKeys; SigstoreVerifySet → SigstoreRoots*;
// SpiffeVerifySet → Verification.TrustRoots* + ExpectedTrustDomain
// + ExpectedPath*) so the order they're applied in does not matter.
// Inactive children are skipped.
func (v *VerifierSet) ApplyToVerifier(target *Verifier) error {
	if target == nil {
		return errors.New("VerifierSet.ApplyToVerifier: target is nil")
	}
	if v.Keys != nil && v.Keys.Active() {
		if err := v.Keys.ApplyToVerifier(target); err != nil {
			return err
		}
	}
	if v.Sigstore != nil && v.Sigstore.Active() {
		if err := v.Sigstore.ApplyToVerifier(target); err != nil {
			return err
		}
	}
	if v.Spiffe != nil && v.Spiffe.Active() {
		if err := v.Spiffe.ApplyToVerifier(target); err != nil {
			return err
		}
	}
	return nil
}

// BuildVerifier returns a *Verifier populated by every Active child,
// starting from DefaultVerifier (which carries the embedded sigstore
// DefaultRoots). Mirror of SignerSet.BuildSigner on the verify side.
func (v *VerifierSet) BuildVerifier() (*Verifier, error) {
	target := DefaultVerifier
	if err := v.ApplyToVerifier(&target); err != nil {
		return nil, err
	}
	return &target, nil
}
