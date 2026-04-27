// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/command"
	"github.com/carabiner-dev/command/keys"
)

// KeysVerify is a command.OptionsSet for verify-side public-key
// configuration. It composes the upstream
// github.com/carabiner-dev/command/keys.Options (which supplies the
// --key flag, repeatable, plus AddKeys and ParseKeys) with this
// package's verifier-side ApplyToVerifier / BuildVerifier so the set
// fits the same shape as SigstoreVerifySet and SpiffeVerifySet.
//
// Composition over duplication: the upstream package owns --key, we
// own the wiring into options.Verifier so the keys flow into
// Verification.PubKeys and VerifyParsedDSSE picks them up via the
// fallback added when the per-call keys argument is empty.
type KeysVerify struct {
	*keys.Options
}

var _ command.OptionsSet = (*KeysVerify)(nil)

// DefaultKeysVerify constructs a KeysVerify wrapping a fresh upstream
// keys.Options ready to bind flags.
func DefaultKeysVerify() *KeysVerify {
	return &KeysVerify{Options: &keys.Options{}}
}

// ApplyToVerifier parses every configured public-key file (and any
// programmatic providers added via AddKeys on the embedded Options)
// and stores them on target.Verification.PubKeys. VerifyParsedDSSE
// reads PubKeys as a fallback when its keys argument is empty, so a
// CLI can wire --key once and call VerifyDSSE without re-passing.
func (k *KeysVerify) ApplyToVerifier(target *Verifier) error {
	if target == nil {
		return errors.New("KeysVerify.ApplyToVerifier: target is nil")
	}
	if k == nil || k.Options == nil {
		return errors.New("KeysVerify: nil; construct via DefaultKeysVerify")
	}
	parsed, err := k.Options.ParseKeys()
	if err != nil {
		return fmt.Errorf("KeysVerify.ApplyToVerifier: %w", err)
	}
	target.Verification.PubKeys = parsed
	return nil
}

// BuildVerifier returns a *Verifier populated from the resolved
// public-key configuration. Empty key configuration is allowed and
// yields a Verifier whose PubKeys slice is empty — callers that
// require keys must check before calling VerifyDSSE.
func (k *KeysVerify) BuildVerifier() (*Verifier, error) {
	target := DefaultVerifier
	if err := k.ApplyToVerifier(&target); err != nil {
		return nil, err
	}
	return &target, nil
}
