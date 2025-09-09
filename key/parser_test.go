// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package key

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePublicKeyBytes(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mustErr bool
		keyData string
	}{
		{"256-p256", false, "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXkyL5IFxz/Hg6DwUy0HBumXcMxt9\nnQSECAK6r262hPwIzjd6LpE7IPlUbwgheE87vU8EUE9tsS02MShFZGo1gg==\n-----END PUBLIC KEY-----\n"},
		{"rsa", false, "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0Zfzonp3/FScaIP+KKuz\nB+OZNFpjbVGWjm3leqnFqHYLqrLcCw5KhlXpycJqoSvZBpO+PFCksUx8U/ryklHG\nVoDiB84pRkvZtBoVaA4b4IHDIhz1K5NqkJgieya4fwReTxmCW0a9gH7AnDicHBCX\nlzMxqEdt6OKMV5g4yjKaxf8lW72O1gSI46GSIToo+Z7UUgs3ofaM5UFIcczgCpUa\n5kEKocB6cSZ9U8PKRLSs0xO0ROjrcOTsfxMs8eV4bsRCWY5mAq1WM9EHDSV9WO8g\nqrRmanC4enNqa8jU4O3zhgJVegP9A01r9AwNt6AqgPSikwhXN/P4v1FMYV+R6N3b\nS1lsVWRAnwBq5RFz5zVvcY88JEkHbrcBqP/A4909NXae1VMXmnoJb4EzGAkyUySB\na+fHXAVJgzwyv3I48d/OIjH8NWcVmM/DQL7FtcJk3tp0YUjY5wNpcbQTnLzURtlU\nsd+MtGuvdlDxUUvtUYCIVKRdS8UzYnTPjI2xzeoSHZ2ZAgMBAAE=\n-----END PUBLIC KEY-----\n"},
		{"", false, "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAOT5nGyAPlkxJCD00qGf12YnsHGnfe2Z1j+RxyFkbE5w=\n-----END PUBLIC KEY-----\n"},
		{"", false, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2u+1EN9NMIAtqYZ2pqF\n3ov4omRpdgEorv1L4sBMaFN+2EPyqeMTF838/W4V/1fHLr5jaqIVY0VjcpAmCRJ6\noRhxw/6o7dgiIPsrTCWQHFAkXcElgb+2JUXWZO3azX90fxFliucPPj0IrLgK3u5O\nD+XgaT773Za2JJSe7A0Iacjb23Elm2T05ydtrWHy5zVMmg+Yj64iaXRxoLUhFpdp\nNOw/rVIUSiFItip+SAZjIsjqQDILzy4RcNUJqBFHG2N/cEwnO+ozb1G9sCtGSya6\nBkCQGhmX64xgehpSUomDod2q3ZmNlS2+9aUMpNq4TksLL08mhQkZi7atNoG4rq4p\nnwIDAQAB\n-----END PUBLIC KEY-----\n"},
		{"invalid-data", true, "kjlskjlsdkjl  lksd skjl  lksdkl lkslkd jlk lk lskj dlkj lkj"},
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

			// fmt.Printf("%+v", k)
		})
	}
	//t.Fail()
}
