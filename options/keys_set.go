// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"errors"
	"fmt"
	"os"

	"github.com/carabiner-dev/command"
	"github.com/spf13/cobra"

	"github.com/carabiner-dev/signer/key"
)

// KeysSign is a command.OptionsSet for sign-side private-key configuration.
// It is the sister of upstream carabiner-dev/command/keys.Options
// (which handles verify-side public keys): both let CLI tools wire
// flag-driven key-file paths into their command surface.
//
// When the resolved Signer.Options.Backend is BackendKey, the keys
// produced by KeysSign.ParseSigningKeys feed into Signer.Options.Keys,
// at which point Signer.SignStatement / SignMessage produce DSSE
// envelopes via the key backend.
type KeysSign struct {
	// PrivateKeyPaths are filesystem paths to private signing keys.
	// Bound to --signing-key (repeatable).
	PrivateKeyPaths []string

	// PassphraseEnvVar names an environment variable whose value (when
	// set and non-empty) is used to decrypt encrypted signing keys
	// (currently only encrypted GPG private keys). Bound to
	// --signing-key-passphrase-env.
	PassphraseEnvVar string

	// extraKeys are programmatically supplied providers (via AddKeys).
	// Returned by ParseSigningKeys ahead of any file-loaded keys.
	extraKeys []key.PrivateKeyProvider

	config *command.OptionsSetConfig
}

var _ command.OptionsSet = (*KeysSign)(nil)

// defaultPassphraseEnvVar is the env-var name a CLI looks at by
// default when an encrypted signing key needs decryption. Callers can
// override on the resulting KeysSign or via the
// --signing-key-passphrase-env flag.
const defaultPassphraseEnvVar = "SIGNING_KEY_PASSPHRASE"

// DefaultKeysSign returns a KeysSign ready to bind flags. The
// passphrase env-var name defaults to SIGNING_KEY_PASSPHRASE; users
// who export that variable get encrypted-key support out of the box,
// users who don't see no behavior change.
func DefaultKeysSign() *KeysSign {
	return &KeysSign{
		PassphraseEnvVar: defaultPassphraseEnvVar,
	}
}

// Config returns the flag configuration for KeysSign.
func (k *KeysSign) Config() *command.OptionsSetConfig {
	if k.config == nil {
		k.config = &command.OptionsSetConfig{
			Flags: map[string]command.FlagConfig{
				"signing-key": {
					Short: "K",
					Long:  "signing-key",
					Help:  "path to a private signing key file (PEM PKCS#8/PKCS#1/SEC1 or OpenPGP)",
				},
				"signing-key-passphrase-env": {
					Long: "signing-key-passphrase-env",
					Help: "envvar to read the signing key passphrase from",
				},
			},
		}
	}
	return k.config
}

// AddFlags registers the KeysSign flags on cmd.
func (k *KeysSign) AddFlags(cmd *cobra.Command) {
	cfg := k.Config()
	pf := cmd.PersistentFlags()
	pf.StringSliceVarP(
		&k.PrivateKeyPaths,
		cfg.LongFlag("signing-key"),
		cfg.ShortFlag("signing-key"),
		k.PrivateKeyPaths,
		cfg.HelpText("signing-key"),
	)
	pf.StringVar(
		&k.PassphraseEnvVar,
		cfg.LongFlag("signing-key-passphrase-env"),
		k.PassphraseEnvVar,
		cfg.HelpText("signing-key-passphrase-env"),
	)
}

// Validate checks that every configured signing-key path exists. It
// does not parse the key material — that happens lazily in
// ParseSigningKeys so flag-time errors stay cheap and parsing errors
// surface with file context at use time.
func (k *KeysSign) Validate() error {
	var errs []error
	for _, p := range k.PrivateKeyPaths {
		if _, err := os.Stat(p); err != nil {
			errs = append(errs, fmt.Errorf("checking signing key %q: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// AddKeys appends pre-parsed providers. They are returned by
// ParseSigningKeys ahead of any keys loaded from PrivateKeyPaths.
// Useful for tests and for callers that already hold the key material
// and want to feed it to the same plumbing as the file-based keys.
func (k *KeysSign) AddKeys(providers ...key.PrivateKeyProvider) {
	k.extraKeys = append(k.extraKeys, providers...)
}

// ParseSigningKeys reads and parses every entry in PrivateKeyPaths
// and returns the resulting providers prepended with AddKeys-supplied
// extras. Encrypted GPG keys are decrypted using the passphrase read
// from PassphraseEnvVar when set.
func (k *KeysSign) ParseSigningKeys() ([]key.PrivateKeyProvider, error) {
	parser := key.NewParser()

	var fnOpts []key.FnOpt
	if k.PassphraseEnvVar != "" {
		if passphrase := os.Getenv(k.PassphraseEnvVar); passphrase != "" {
			fnOpts = append(fnOpts, key.WithPassphrase(passphrase))
		}
	}

	out := append([]key.PrivateKeyProvider{}, k.extraKeys...)
	for _, p := range k.PrivateKeyPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading signing key file %q: %w", p, err)
		}
		provider, err := parser.ParsePrivateKeyProvider(data, fnOpts...)
		if err != nil {
			return nil, fmt.Errorf("parsing signing key %q: %w", p, err)
		}
		out = append(out, provider)
	}
	return out, nil
}
