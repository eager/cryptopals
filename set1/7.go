package main

import (
	"crypto/aes"
	"encoding/base64"
	"log"
	"os"
)

func main() {

	key := []byte("YELLOW SUBMARINE")

	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic("failed to create cipher")
	}

	ciphertext, err := os.ReadFile("./7.txt")
	if err != nil {
		panic("failed to read input")
	}
	ciphertext, err = base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		panic("failed to decode input")
	}

	plaintext := make([]byte, 0)
	buffer := make([]byte, len(key))

	for len(ciphertext) > 0 {
		cipher.Decrypt(buffer, ciphertext)
		plaintext = append(plaintext, buffer...)
		ciphertext = ciphertext[len(key):]
	}

	log.Print(string(plaintext))
}
