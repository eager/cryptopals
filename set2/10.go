package main

import (
	"crypto/aes"
	"encoding/base64"
	"log"
	"os"
	"strings"
)

func main10() {
	input, err := os.ReadFile("./10.txt")
	if err != nil {
		panic("could not read input")
	}
	input, err = base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		panic("failed to decode input")
	}

	key := []byte("YELLOW SUBMARINE")
	plaintext := decrypt(input, key, make([]byte, 16))

	log.Print(string(plaintext))

	plaintext = []byte(strings.Repeat("A", 16*100))
	ciphertext := encrypt(plaintext, key, make([]byte, 16))
	plaintext = decrypt(ciphertext, key, make([]byte, 16))

	log.Print(string(plaintext))
}

func decrypt(c, k, iv []byte) []byte {

	if len(k) != len(iv) {
		panic("key and iv must match length")
	}

	cipher, err := aes.NewCipher(k)
	if err != nil {
		panic("failed to create cipher")
	}

	p := make([]byte, 0)
	buffer := make([]byte, len(k))

	for len(c) > 0 {
		b := c[0:len(k)]
		cipher.Decrypt(buffer, b)
		p = append(p, xor(iv, buffer)...)
		iv = b
		c = c[len(k):]
	}

	return p
}

func encrypt(p, k, iv []byte) []byte {

	cipher, err := aes.NewCipher(k)
	if err != nil {
		panic("failed to create cipher")
	}

	c := make([]byte, 0)
	buffer := iv

	for len(p) > 0 {
		b := p[0:len(k)]
		cipher.Encrypt(buffer, xor(b, buffer))
		c = append(c, buffer...)
		p = p[len(k):]
	}

	return c
}
