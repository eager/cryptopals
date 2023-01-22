package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
)

func main() {

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

	blockSize := DetectBlockSize(key)
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

func DetectBlockSize(key []byte) int {

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

// from set2/11.go

func IsECB(cipher []byte, blockSize int) bool {
	repeatedBlocks := 0

	for len(cipher)-blockSize >= 0 {
		block := cipher[0:blockSize]
		cipher = cipher[blockSize:]
		for c := cipher; len(c) >= blockSize; c = c[blockSize:] {

			if bytes.Compare(block, c[0:blockSize]) == 0 {
				repeatedBlocks = repeatedBlocks + 1
			}

		}
	}

	log.Printf("repeated blocks: %d", repeatedBlocks)
	// TODO this is probably not sufficient
	return repeatedBlocks > 0
}

func RandomAesKey() ([]byte, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func RandomPadding(b []byte) []byte {
	frontPad, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		panic("failed to generate padding")
	}
	backPad, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		panic("failed to generate padding")
	}
	frontPadBytes := make([]byte, int(frontPad.Int64()+5))
	backPadBytes := make([]byte, int(backPad.Int64()+5))

	_, err = rand.Read(frontPadBytes)
	if err != nil {
		panic("failed to generate padding")
	}

	_, err = rand.Read(backPadBytes)
	if err != nil {
		panic("failed to generate padding")
	}

	result := append(frontPadBytes, b...)
	result = append(result, backPadBytes...)

	return result
}

func PKCS7Pad(b []byte, block int) []byte {
	var p int
	if len(b) > block {
		p = block - len(b)%block
	} else {
		p = block - len(b)
	}
	if p == 0 {
		p = block
	}
	pb := make([]byte, 0)
	pb = append(pb, byte(p))
	padding := bytes.Repeat(pb, p)

	return append(b, padding...)
}

func PKCS7Unpad(b []byte, block int) ([]byte, error) {

	if len(b)%block != 0 {
		return nil, fmt.Errorf("input is invalid lengh: %d (%d)", len(b), block)
	}
	if len(b) == 0 {
		return b, nil
	}
	last := int(b[len(b)-1])
	maybePad := b[len(b)-last:]
	if bytes.Count(maybePad, []byte{byte(last)}) != len(maybePad) {
		return nil, fmt.Errorf("incorrect padding")
	}
	return b[0 : len(b)-last], nil

}

type Crypter interface {
	decrypt([]byte, []byte, []byte) ([]byte, error)
	encrypt([]byte, []byte, []byte) ([]byte, error)
}

type ECBCrypter struct {
}

func (ECBCrypter) decrypt(c, k, _ []byte) ([]byte, error) {

	cipher, err := aes.NewCipher(k)
	if err != nil {
		panic("failed to create cipher")
	}

	p := make([]byte, 0)
	buffer := make([]byte, len(k))

	for len(c) > 0 {
		cipher.Decrypt(buffer, c)
		p = append(p, buffer...)
		c = c[len(k):]
	}

	return PKCS7Unpad(p, len(k))
}

func (ECBCrypter) encrypt(p, k, _ []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 0)
	buffer := make([]byte, len(k))

	p = PKCS7Pad(p, len(k))

	for len(p) > 0 {
		cipher.Encrypt(buffer, p)
		c = append(c, buffer...)
		p = p[len(k):]
	}

	return c, nil
}

// from set1/6.go

func findKeySize(bytes []byte) int {
	keySize := 0
	bestNormalized := math.MaxFloat64
	for k := 2; k <= 40; k++ {
		blocks := 16 // the instructions recommended averaging 4, but why not go big
		distance := 0
		for i := 0; i < blocks; i++ {
			// lazily skipping bounds checks
			b1 := bytes[i*k : (i+1)*k]
			b2 := bytes[(i+1)*k : (i+2)*k]
			distance = distance + hamming(b1, b2)
		}
		normalized := float64(distance) / float64(blocks) / float64(k)
		if normalized < bestNormalized {
			bestNormalized = normalized
			keySize = k
		}
	}

	return keySize
}

func hamming(s1, s2 []byte) int {

	distance := 0
	for i, _ := range s1 {
		if i >= len(s2) {
			distance = distance + 8*(len(s1)-len(s2))
			break
		}
		for shift := 0; shift < 8; shift++ {
			mask := byte(1 << shift)
			s1Bit := s1[i] & mask
			s2Bit := s2[i] & mask
			if s1Bit^s2Bit > 0 {
				distance = distance + 1
			}
		}
	}

	if len(s1) < len(s2) {
		distance = distance + 8*(len(s2)-len(s1))
	}

	return distance

}

func crypt(plaintext, key []byte) []byte {

	ciphertext := make([]byte, 0)

	for i, b := range plaintext {
		keyIndex := i % len(key)

		ciphertext = append(ciphertext, b^key[keyIndex])
	}

	return ciphertext
}
