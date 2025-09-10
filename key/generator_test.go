// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		funcs        []FnGenOpt
		mustErr      bool
		expectedType Type
	}{
		{"default", []FnGenOpt{}, false, ECDSA},
		{"rsa", []FnGenOpt{WithKeyType(RSA)}, false, RSA},
		{"rsa-small-key", []FnGenOpt{WithKeyType(RSA), WithKeyLength(5)}, true, RSA},
		{"ecdsa", []FnGenOpt{WithKeyType(ECDSA)}, false, ECDSA},
		{"ed25519", []FnGenOpt{WithKeyType(ED25519)}, false, ED25519},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gen := Generator{}
			res, err := gen.GenerateKeyPair(tt.funcs...)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, tt.expectedType, res.Type)
			require.NotEmpty(t, res.Data)
			require.True(t, strings.HasPrefix(res.Data, "-----BEGIN "))
			require.True(t, strings.HasSuffix(res.Data, "PRIVATE KEY-----\n"))
			t.Log("\n" + res.Data)
			public, err := res.PublicKey()
			require.NoError(t, err)
			require.NotNil(t, public)
		})
	}
}
