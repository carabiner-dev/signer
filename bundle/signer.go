// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package bundle

import (
	"errors"
	"fmt"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer/options"
)

// BundleSigner abstracts the signer implementation to make it easy to mock
//
//counterfeiter:generate . Signer
type Signer interface {
	VerifyAttestationContent(*options.Signer, []byte) error
	WrapData(payloadType string, data []byte) *sign.DSSEData
	BuildMessage(data []byte) *sign.PlainData
	BuildBundleOptions(*options.Signer, CredentialProvider) (*sign.BundleOptions, error)
	SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*protobundle.Bundle, error)
}

func NewSigner() Signer {
	return &DefaultSigner{}
}

// DefaultSigner implements the BundleSigner interface for the signer
type DefaultSigner struct{}

func (bs *DefaultSigner) WrapData(payloadType string, data []byte) *sign.DSSEData {
	content := &sign.DSSEData{
		Data:        data,
		PayloadType: payloadType,
	}
	return content
}

// BuildMessage is the alternative to WrapData.
func (bs *DefaultSigner) BuildMessage(data []byte) *sign.PlainData {
	return &sign.PlainData{
		Data: data,
	}
}

// VerifyContent checka that the attestation is in good shape to sign
func (bs *DefaultSigner) VerifyAttestationContent(_ *options.Signer, data []byte) error {
	if data == nil {
		return errors.New("payload is empty")
	}
	st := &intoto.Statement{}
	if err := protojson.Unmarshal(data, st); err != nil {
		return errors.New("unable to unmarshal intoto statement from payload")
	}
	return nil
}

// BuildBundleOptions assembles the sign.BundleOptions used by SignBundle. The
// certificate provider is supplied by the given CredentialProvider; TSA and
// Rekor endpoints come from the sigstore signing config carried in the options.
func (bs *DefaultSigner) BuildBundleOptions(opts *options.Signer, cp CredentialProvider) (*sign.BundleOptions, error) {
	if cp == nil {
		return nil, errors.New("credential provider not set")
	}

	if opts.SigningConfig == nil {
		return nil, fmt.Errorf("signing config not set")
	}

	signingConfig := opts.SigningConfig

	bundleOptions := sign.BundleOptions{}
	certProvider, cpOpts := cp.CertificateProvider()
	bundleOptions.CertificateProvider = certProvider
	bundleOptions.CertificateProviderOptions = cpOpts

	if opts.Timestamp {
		tsaURLs, err := root.SelectServices(
			signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("fetching time stamp authority URLs: %w", err)
		}

		if len(tsaURLs) == 0 {
			return nil, fmt.Errorf("no timestamp authority found in signing config")
		}

		for _, tsaURL := range tsaURLs {
			tsaOpts := &sign.TimestampAuthorityOptions{
				URL:     tsaURL.URL,
				Timeout: 30 * time.Second,
				Retries: 1,
			}
			bundleOptions.TimestampAuthorities = append(
				bundleOptions.TimestampAuthorities, sign.NewTimestampAuthority(tsaOpts),
			)
		}
	}

	if opts.AppendToRekor {
		for _, rekorURL := range signingConfig.RekorLogURLs() {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorURL.URL,
				Timeout: 90 * time.Second,
				Retries: 1,
			}
			bundleOptions.TransparencyLogs = append(bundleOptions.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	return &bundleOptions, nil
}

// SignBundle signs the DSSE envelop and returns the new bundle
func (bs *DefaultSigner) SignBundle(content sign.Content, keypair sign.Keypair, opts *sign.BundleOptions) (*protobundle.Bundle, error) {
	bndl, err := sign.Bundle(content, keypair, *opts)
	if err != nil {
		return nil, fmt.Errorf("signing DSSE wrapper: %w", err)
	}

	return bndl, nil
}
