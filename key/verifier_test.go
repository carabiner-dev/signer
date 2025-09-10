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
		name            string
		mustErr         bool
		keyData         string
		digest          string
		signature       string
		scheme          string
		result          bool
		parseKeyMustErr bool
	}{
		{
			"ecdsa", false, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			"6b9e695a3f7bc780cdeba0e5c82e4a06f8eae3bc90752eeaa36cdc6af9a39e8a", "MEQCIDfyAVIjdRISLAAsE2aOjDGFvBac02Gc9z80VklJSPLfAiBDwINgrGs4KgJLgM+lw2yoZt12a48jTAd2hdrKxQO+2A==",
			"ecdsa-sha2-nistp256", true, false,
		},
		{
			"rsa", false, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJGe2Y0QXgOnS60CQcSNjGD21FLt+\nLzeUGhiyzu0iIz72NgbdcPyz6KQjkQEJoru6Y2NsAq9ZpjQLChl5jPm4zg==\n-----END PUBLIC KEY-----\n",
			"3aa489a09d7c7fac5f2cac100c28baab237b06644fa14233307b5b20214d4a12", "MEUCIQCOgpXO0V4xNCGslEpGnj9nGkEYTOqefQ/VIAVAYXUUJQIgMFiwpsELF+076kyK+8wiSD9Mcl1o78cbBdMRZd+thHk=",
			"ecdsa-sha2-nistp256", true, false,
		},
		{
			"incorrect-curve", true, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJGe2Y0QXgOnS60CQcSNjGD21FLt+\nLzeUGhiyzu0iIz72NgbdcPyz6KQjkQEJoru6Y2NsAq9ZpjQLChl5jPm4zg==\n-----END PUBLIC KEY-----\n",
			"3aa489a09d7c7fac5f2cac100c28baab237b06644fa14233307b5b20214d4a12", "MEUCIQCOgpXO0V4xNCGslEpGnj9nGkEYTOqefQ/VIAVAYXUUJQIgMFiwpsELF+076kyK+8wiSD9Mcl1o78cbBdMRZd+thHk=",
			"ecdsa-sha2-nistp384", true, true,
		},
		{
			"incorrect-schema", true, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJGe2Y0QXgOnS60CQcSNjGD21FLt+\nLzeUGhiyzu0iIz72NgbdcPyz6KQjkQEJoru6Y2NsAq9ZpjQLChl5jPm4zg==\n-----END PUBLIC KEY-----\n",
			"3aa489a09d7c7fac5f2cac100c28baab237b06644fa14233307b5b20214d4a12", "MEUCIQCOgpXO0V4xNCGslEpGnj9nGkEYTOqefQ/VIAVAYXUUJQIgMFiwpsELF+076kyK+8wiSD9Mcl1o78cbBdMRZd+thHk=",
			"rsassa-pss-sha256", true, true,
		},
		{
			"swap-keys", false, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n",
			"3aa489a09d7c7fac5f2cac100c28baab237b06644fa14233307b5b20214d4a12", "MEUCIQCOgpXO0V4xNCGslEpGnj9nGkEYTOqefQ/VIAVAYXUUJQIgMFiwpsELF+076kyK+8wiSD9Mcl1o78cbBdMRZd+thHk=",
			"", false, false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := []FnOpt{}
			if tt.scheme != "" {
				opts = append(opts, WithScheme(Scheme(tt.scheme)))
			}
			k, err := NewParser().ParsePublicKey([]byte(tt.keyData), opts...)
			if tt.parseKeyMustErr {
				require.Error(t, err)
				return
			}
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
