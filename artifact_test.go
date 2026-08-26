// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArtifact(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		path     string
		wantKind ArtifactKind
	}{
		{"sigstore bundle", "bundle/testdata/public-good.sigstore.json", ArtifactKindBundle},
		{"dsse envelope", "dsse/testdata/rebuild.dsse.json", ArtifactKindEnvelope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(tc.path)
			require.NoError(t, err)

			art, err := ParseArtifact(data)
			require.NoError(t, err)
			assert.Equal(t, tc.wantKind, art.Kind())

			switch tc.wantKind {
			case ArtifactKindBundle:
				b, ok := art.(*BundleArtifact)
				require.True(t, ok)
				assert.NotNil(t, b.Bundle.GetDsseEnvelope())
			case ArtifactKindEnvelope:
				e, ok := art.(*EnvelopeArtifact)
				require.True(t, ok)
				assert.NotEmpty(t, e.Envelope.GetSignatures())
			}
		})
	}
}

// ParseArtifact must round-trip whatever WriteTo produces, for both kinds.
func TestParseArtifactRoundTrip(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"bundle/testdata/public-good.sigstore.json",
		"dsse/testdata/rebuild.dsse.json",
	} {
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		art, err := ParseArtifact(data)
		require.NoError(t, err)

		var buf bytes.Buffer
		_, err = art.WriteTo(&buf)
		require.NoError(t, err)

		again, err := ParseArtifact(buf.Bytes())
		require.NoError(t, err, path)
		assert.Equal(t, art.Kind(), again.Kind())
		assert.Equal(t, art.MediaType(), again.MediaType())
	}
}

func TestParseArtifactErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		data    string
		wantErr error // nil means "any error"
	}{
		{"not json", "nope", nil},
		{"json but neither kind", `{"foo": "bar"}`, ErrUnknownArtifact},
		{"empty object", `{}`, ErrUnknownArtifact},
		{"bundle mediaType with no content", `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}`, nil},
		{"dsse with unknown field", `{"payloadType": "x", "payload": "eA==", "signatures": [], "extra": 1}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			art, err := ParseArtifact([]byte(tc.data))
			require.Error(t, err)
			assert.Nil(t, art)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			}
		})
	}
}
