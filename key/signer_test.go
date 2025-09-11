// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		keyType Type
	}{
		{"rsa", RSA}, {"ecdsa", ECDSA}, {"ed25519", ED25519},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gen := &Generator{}
			k, err := gen.GenerateKeyPair(WithKeyType(tt.keyType))
			require.NoError(t, err)

			// Test signing
			signer := NewSigner()
			sig, err := signer.SignMessage(k, []byte("test"))
			require.NoError(t, err)
			require.NotNil(t, sig)

			// Now, verify the message to ensure things are ok
			verifier := NewVerifier()
			res, err := verifier.VerifyMessage(k, []byte("test"), sig)
			require.NoError(t, err)
			require.True(t, res)
		})
	}
}
