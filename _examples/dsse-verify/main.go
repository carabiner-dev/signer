package main

import (
	"fmt"
	"os"

	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
)

var publicKeyData = ` 
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq0F7Qy812rYgbwi5c1wSnevN8FEC
hDjayw2lL6wkyR9k1vWICQYbe4FqOZeulBbfWBU7/BKdtlwKRStEVEffvg==
-----END PUBLIC KEY-----
`

var dsseData = `{
  "payload": "SGVsbG8gd29ybGQ=",
  "payloadType": "text/plain",
  "signatures": [
    {
      "sig": "MEUCIDKpSIt1MVAGv+flwES53S3FRx4EcRwQvgn/VdFO0OEVAiEA7kUkfouThUc/bXwmcrcidZwejlgGA6eH49Bvn7rIywc="
    }
  ]
}`

func main() {
	publicKey, err := key.NewParser().ParsePublicKey([]byte(publicKeyData))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	envelope := &sdsse.Envelope{}
	if err := protojson.Unmarshal([]byte(dsseData), envelope); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	verifier := signer.NewVerifier()
	result, err := verifier.VerifyParsedDSSE(envelope, []key.PublicKeyProvider{publicKey})
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if result.Verified {
		fmt.Println("DSSE Envelope verified !")
	} else {
		fmt.Println("DSSE Envelope verification failed")
	}
}
