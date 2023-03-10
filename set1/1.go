package main

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func main() {

	h := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	bytes, err := hex.DecodeString(h)

	if err != nil {
		panic("failed to decode hex")
	}

	b64 := base64.StdEncoding.EncodeToString(bytes)

	if b64 != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		panic("do not match")
	}

	log.Print("matches")
}
