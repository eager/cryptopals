package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"log"
	"os"
)

func main12() {

	unknownStringBase64, err := os.ReadFile("./12.txt")
	if err != nil {
		panic("failed to read input")
	}
	unknownBytes, err := base64.StdEncoding.DecodeString(string(unknownStringBase64))
	if err != nil {
		panic("failed to decode input")
	}

	key, err := RandomAesKey()
	if err != nil {
		panic("failed to generate key")
	}

	blockSize := DetectBlockSize12(key)
	log.Printf("block size: %d", blockSize)

	testInput := bytes.Repeat([]byte{byte('A')}, blockSize*3)

	testResult := EncryptionOracle12(testInput, key)

	if !IsECB(testResult, blockSize) {
		panic("failed to detect ECB")
	}

	byteMap := MakeMap(blockSize, key)

	knownUnknown := make([]byte, 0)
	shortInput := bytes.Repeat([]byte{byte('A')}, blockSize-1)
	for len(unknownBytes) > 0 {
		b := unknownBytes[0]
		unknownBytes = unknownBytes[1:]

		result := EncryptionOracle12(append(shortInput, b), key)
		b = byteMap[hex.EncodeToString(result[0:blockSize])]
		knownUnknown = append(knownUnknown, b)
	}

	log.Printf("unknown string:\n%s", string(knownUnknown))

}

// It’s not possible to use []byte as a map key, so the block is converted to a hex string
func MakeMap(blockSize int, key []byte) map[string]byte {

	p := bytes.Repeat([]byte{byte('A')}, blockSize-1)
	m := make(map[string]byte)
	for b := 0; b < 256; b += 1 {
		bb := byte(b)
		input := append(p, bb)
		e := EncryptionOracle12(input, key)
		eb := e[0:blockSize]
		m[hex.EncodeToString(eb)] = bb
	}

	return m
}

func DetectBlockSize12(key []byte) int {

	input := bytes.Repeat([]byte{byte('A')}, 2048)
	c := EncryptionOracle12(input, key)

	return findKeySize(c)
}

func EncryptionOracle12(input, key []byte) []byte {
	// TODO can we do this with the random padding from 11? I don’t think so
	// input = RandomPadding(input)

	iv, err := RandomAesKey()
	if err != nil {
		panic("failed to generate iv")
	}

	crypter := ECBCrypter{}

	result, err := crypter.encrypt(input, key, iv)
	if err != nil {
		panic("failed to encrypt")
	}

	return result
}
