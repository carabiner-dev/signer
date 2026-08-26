// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/carabiner-dev/signer/key"
)

func TestWithPublicKeys(t *testing.T) {
	t.Parallel()

	k1, k2, k3 := &key.Public{}, &key.Public{}, &key.Public{}

	t.Run("replaces configured keys", func(t *testing.T) {
		t.Parallel()
		v := Verification{}
		v.PubKeys = []key.PublicKeyProvider{k1}
		require.NoError(t, WithPublicKeys(k2, k3)(&v))
		assert.Equal(t, []key.PublicKeyProvider{k2, k3}, v.PubKeys)
	})

	t.Run("copies the slice", func(t *testing.T) {
		t.Parallel()
		v := Verification{}
		in := []key.PublicKeyProvider{k1, k2}
		require.NoError(t, WithPublicKeys(in...)(&v))
		in[0] = k3
		assert.Same(t, k1, v.PubKeys[0], "option must not alias the caller's slice")
	})

	t.Run("no keys clears the set", func(t *testing.T) {
		t.Parallel()
		v := Verification{}
		v.PubKeys = []key.PublicKeyProvider{k1}
		require.NoError(t, WithPublicKeys()(&v))
		assert.Empty(t, v.PubKeys)
	})
}
