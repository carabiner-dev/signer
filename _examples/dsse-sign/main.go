package main

import (
	"fmt"
	"os"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
)

func main() {
	// Start with a message
	myMessage := []byte("Hello world")

	// Generate a Key Pair to sign
	privateKey, err := key.NewGenerator().GenerateKeyPair()

	// Create a new signer
	s := signer.NewSigner()

	// Wrap the message in a new envelope and sign it with the key
	envelope, err := s.SignMessageToDSSE(
		myMessage,
		options.WithKey(privateKey),
		options.WithPayloadType("text/plain"),
	)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Print the public key
	// pub, _ := privateKey.PublicKey()
	// fmt.Println(pub.Data + "\n")

	s.WriteDSSEEnvelope(envelope, os.Stdout)
}
