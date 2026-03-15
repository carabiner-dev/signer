// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"crypto"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePublicKeyBytes(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		mustErr  bool
		Type     Type
		HashType crypto.Hash
		keyData  string
	}{
		{"256-p256", false, ECDSA, crypto.SHA256, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n"},
		{"rsa", false, RSA, crypto.SHA256, "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0Zfzonp3/FScaIP+KKuz\nB+OZNFpjbVGWjm3leqnFqHYLqrLcCw5KhlXpycJqoSvZBpO+PFCksUx8U/ryklHG\nVoDiB84pRkvZtBoVaA4b4IHDIhz1K5NqkJgieya4fwReTxmCW0a9gH7AnDicHBCX\nlzMxqEdt6OKMV5g4yjKaxf8lW72O1gSI46GSIToo+Z7UUgs3ofaM5UFIcczgCpUa\n5kEKocB6cSZ9U8PKRLSs0xO0ROjrcOTsfxMs8eV4bsRCWY5mAq1WM9EHDSV9WO8g\nqrRmanC4enNqa8jU4O3zhgJVegP9A01r9AwNt6AqgPSikwhXN/P4v1FMYV+R6N3b\nS1lsVWRAnwBq5RFz5zVvcY88JEkHbrcBqP/A4909NXae1VMXmnoJb4EzGAkyUySB\na+fHXAVJgzwyv3I48d/OIjH8NWcVmM/DQL7FtcJk3tp0YUjY5wNpcbQTnLzURtlU\nsd+MtGuvdlDxUUvtUYCIVKRdS8UzYnTPjI2xzeoSHZ2ZAgMBAAE=\n-----END PUBLIC KEY-----\n"},
		{"rsa2", false, RSA, crypto.SHA256, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2u+1EN9NMIAtqYZ2pqF\n3ov4omRpdgEorv1L4sBMaFN+2EPyqeMTF838/W4V/1fHLr5jaqIVY0VjcpAmCRJ6\noRhxw/6o7dgiIPsrTCWQHFAkXcElgb+2JUXWZO3azX90fxFliucPPj0IrLgK3u5O\nD+XgaT773Za2JJSe7A0Iacjb23Elm2T05ydtrWHy5zVMmg+Yj64iaXRxoLUhFpdp\nNOw/rVIUSiFItip+SAZjIsjqQDILzy4RcNUJqBFHG2N/cEwnO+ozb1G9sCtGSya6\nBkCQGhmX64xgehpSUomDod2q3ZmNlS2+9aUMpNq4TksLL08mhQkZi7atNoG4rq4p\nnwIDAQAB\n-----END PUBLIC KEY-----\n"},
		{"ed25519", false, ED25519, 0, "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----\n"},
		{"invalid-data", true, "", 0, "kjlskjlsdkjl  lksd skjl  lksdkl lkslkd jlk lk lskj dlkj lkj"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			k, err := parseKeyBytes([]byte(tt.keyData))
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, k)
			require.Equal(t, tt.Type, k.Type)
			require.Equal(t, tt.HashType, k.HashType, "HashType must be set for %s keys", tt.Type)
		})
	}
}

func TestParsePublicKey_GPG(t *testing.T) {
	t.Parallel()
	gpgData, err := os.ReadFile("testdata/gpg-ecdsa-public.asc")
	require.NoError(t, err)

	parser := NewParser()
	pub, err := parser.ParsePublicKey(gpgData)
	require.NoError(t, err)
	require.Equal(t, ECDSA, pub.Type)
	require.Equal(t, EcdsaSha2nistP256, pub.Scheme)
	require.NotNil(t, pub.Key)
	require.NotEmpty(t, pub.Data)
}

func TestParsePublicKeyProvider(t *testing.T) {
	t.Parallel()

	ecdsaPEM := "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n"

	gpgData, err := os.ReadFile("testdata/gpg-ecdsa-public.asc")
	require.NoError(t, err)

	parser := NewParser()

	t.Run("pem-ecdsa", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePublicKeyProvider([]byte(ecdsaPEM))
		require.NoError(t, err)
		pub, err := prov.PublicKey()
		require.NoError(t, err)
		require.Equal(t, ECDSA, pub.Type)
	})

	t.Run("pem-with-scheme", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePublicKeyProvider([]byte(ecdsaPEM), WithScheme(EcdsaSha2nistP256))
		require.NoError(t, err)
		pub, err := prov.PublicKey()
		require.NoError(t, err)
		require.Equal(t, EcdsaSha2nistP256, pub.Scheme)
	})

	t.Run("gpg-armored", func(t *testing.T) {
		t.Parallel()
		prov, err := parser.ParsePublicKeyProvider(gpgData)
		require.NoError(t, err)

		// Should be a *GPGPublic
		gpgPub, ok := prov.(*GPGPublic)
		require.True(t, ok, "expected *GPGPublic, got %T", prov)
		require.NotEmpty(t, gpgPub.Fingerprint())

		// PublicKey extraction should still work
		pub, err := prov.PublicKey()
		require.NoError(t, err)
		require.Equal(t, ECDSA, pub.Type)
	})

	t.Run("invalid-data", func(t *testing.T) {
		t.Parallel()
		_, err := parser.ParsePublicKeyProvider([]byte("not a key at all"))
		require.Error(t, err)
	})
}
