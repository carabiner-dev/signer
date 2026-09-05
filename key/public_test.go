// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// The key ID of an ECDSA key is a public identifier pinned in policies.
// It must not change.
func TestPublicIDStable(t *testing.T) {
	t.Parallel()
	const pemKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n"
	pub, err := NewParser().ParsePublicKey([]byte(pemKey))
	require.NoError(t, err)
	require.Equal(t, "5be34774cae03891", pub.ID())
}

// ecdsaKeyIDBytes must reproduce the historical encoding of the coordinates:
// X.Bytes() || Y.Bytes(), where big.Int.Bytes() strips leading zero bytes.
func TestECDSAKeyIDBytes(t *testing.T) {
	t.Parallel()
	for _, curve := range []elliptic.Curve{
		elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521(),
	} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			t.Parallel()
			byteLen := (curve.Params().BitSize + 7) / 8

			// Keep generating keys until a coordinate with a leading zero byte
			// shows up, so the stripping path is exercised. Each coordinate has
			// a 1/256 chance, so this finishes almost immediately.
			shortSeen := false
			for i := 0; i < 4096 && !shortSeen; i++ {
				priv, err := ecdsa.GenerateKey(curve, rand.Reader)
				require.NoError(t, err)

				point, err := priv.PublicKey.Bytes()
				require.NoError(t, err)
				require.Len(t, point, 1+2*byteLen)
				fixedX := point[1 : 1+byteLen]
				fixedY := point[1+byteLen:]

				expected := append(
					new(big.Int).SetBytes(fixedX).Bytes(),
					new(big.Int).SetBytes(fixedY).Bytes()...,
				)

				got, err := ecdsaKeyIDBytes(&priv.PublicKey)
				require.NoError(t, err)
				require.Equal(t, expected, got)

				if len(got) < 2*byteLen {
					shortSeen = true
				}
			}
			require.True(t, shortSeen, "no coordinate with a leading zero byte was generated")
		})
	}
}

// A key on a curve the standard library cannot encode has no ID.
func TestPublicIDUnsupportedCurve(t *testing.T) {
	t.Parallel()
	pub := &Public{Key: &ecdsa.PublicKey{Curve: &elliptic.CurveParams{Name: "bogus", BitSize: 256}}}
	require.Empty(t, pub.ID())
}
