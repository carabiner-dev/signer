// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyHash(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name      string
		mustErr   bool
		keyData   string
		digest    string
		signature string
		scheme    string
		result    bool
	}{
		{
			"ecdsa", false, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			"53d4a0d736cfbc3aee21a2b02e3294e0b75c820400ce03bc184bca6c914ece03", "MEQCIEeMmq2z7+0yMyt8tL85S9pydxFCaxsGEArbPXXsgYFrAiBob+778d4PwHXQJ/WOVaCp4e/1i/P2i66hSxqPXT0Ykw==",
			"ecdsa-sha2-nistp256", true,
		},
		{
			"rsa", false, "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0Zfzonp3/FScaIP+KKuz\nB+OZNFpjbVGWjm3leqnFqHYLqrLcCw5KhlXpycJqoSvZBpO+PFCksUx8U/ryklHG\nVoDiB84pRkvZtBoVaA4b4IHDIhz1K5NqkJgieya4fwReTxmCW0a9gH7AnDicHBCX\nlzMxqEdt6OKMV5g4yjKaxf8lW72O1gSI46GSIToo+Z7UUgs3ofaM5UFIcczgCpUa\n5kEKocB6cSZ9U8PKRLSs0xO0ROjrcOTsfxMs8eV4bsRCWY5mAq1WM9EHDSV9WO8g\nqrRmanC4enNqa8jU4O3zhgJVegP9A01r9AwNt6AqgPSikwhXN/P4v1FMYV+R6N3b\nS1lsVWRAnwBq5RFz5zVvcY88JEkHbrcBqP/A4909NXae1VMXmnoJb4EzGAkyUySB\na+fHXAVJgzwyv3I48d/OIjH8NWcVmM/DQL7FtcJk3tp0YUjY5wNpcbQTnLzURtlU\nsd+MtGuvdlDxUUvtUYCIVKRdS8UzYnTPjI2xzeoSHZ2ZAgMBAAE=\n-----END PUBLIC KEY-----\n",
			"53d4a0d736cfbc3aee21a2b02e3294e0b75c820400ce03bc184bca6c914ece03", "MEQCIEeMmq2z7+0yMyt8tL85S9pydxFCaxsGEArbPXXsgYFrAiBob+778d4PwHXQJ/WOVaCp4e/1i/P2i66hSxqPXT0Ykw==",
			"rsassa-pss-sha256", true,
		},
		{
			"invalid-digest", true, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			"avs", "MEQCIEeMmq2z7+0yMyt8tL85S9pydxFCaxsGEArbPXXsgYFrAiBob+778d4PwHXQJ/WOVaCp4e/1i/P2i66hSxqPXT0Ykw==",
			"", false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := []FnOpt{}
			if tt.scheme != "" {
				opts = append(opts, WithScheme(Scheme(tt.scheme)))
			}
			k, err := NewParser().ParsePublicKey([]byte(tt.keyData), opts...)
			require.NoError(t, err)

			// Deocde the signature
			derData, err := base64.StdEncoding.DecodeString(tt.signature)
			require.NoError(t, err)
			require.NotNil(t, derData)

			res, err := NewVerifier().VerifyDigestString(k, tt.digest, derData)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Equal(t, tt.result, res)
		})
	}
}
