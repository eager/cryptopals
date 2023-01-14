package main

import (
	"encoding/hex"
	"log"
)

func main() {

	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	actual := encrypt(input, key)

	expectedHex := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	log.Printf("expected == actual: %v", expectedHex == hex.EncodeToString(actual))
}

func encrypt(plaintext, key []byte) []byte {

	ciphertext := make([]byte, 0)

	for i, b := range plaintext {
		keyIndex := i % len(key)

		ciphertext = append(ciphertext, b^key[keyIndex])
	}

	return ciphertext
}
