package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
)

func main() {

	blockSize := 16
	// it’s not clearly stated in the challenge, but use a well-chosen input,
	// so that we know that there will be repeated blocks
	input := bytes.Repeat([]byte{byte('A')}, blockSize*3)

	rounds := 100
	correctEcbGuesses := 0
	correctCbcGuesses := 0
	confusedEcbFoCbc := 0
	confusedCbcForEcb := 0
	for i := 0; i < rounds; i += 1 {

		result, actualCbc := EncryptionOracle(input)

		guessCbc := !IsECB(result, blockSize)

		if actualCbc {
			if guessCbc {
				correctCbcGuesses += 1
			} else {
				confusedCbcForEcb += 1
			}
		} else {
			if guessCbc {
				confusedEcbFoCbc += 1
			} else {
				correctEcbGuesses += 1
			}
		}

	}
	log.Printf("correct ECB: %d", correctEcbGuesses)
	log.Printf("correct CBC: %d", correctCbcGuesses)
	log.Printf("false positive ECB: %d", confusedCbcForEcb)
	log.Printf("false positive CBC: %d", confusedEcbFoCbc)

}

func EncryptionOracle(input []byte) ([]byte, bool) {

	input = RandomPadding(input)
	key, err := RandomAesKey()
	if err != nil {
		panic("failed to generate key")
	}
	iv, err := RandomAesKey()
	if err != nil {
		panic("failed to generate iv")
	}
	randomInt, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		panic("failed to toss CBC coin")
	}
	cbc := randomInt.Cmp(big.NewInt(1)) == 0

	var crypter Crypter
	if cbc {
		crypter = CBCCrypter{}
	} else {
		crypter = ECBCrypter{}
	}

	result, err := crypter.encrypt(input, key, iv)
	if err != nil {
		panic("failed to encrypt")
	}

	return result, cbc
}

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

type CBCCrypter struct {
}

func (CBCCrypter) decrypt(c, k, iv []byte) ([]byte, error) {

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

	return PKCS7Unpad(p, len(k))
}

func (CBCCrypter) encrypt(p, k, iv []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	c := make([]byte, 0)
	buffer := iv

	p = PKCS7Pad(p, len(k))

	for len(p) > 0 {
		b := p[0:len(k)]
		cipher.Encrypt(buffer, xor(b, buffer))
		c = append(c, buffer...)
		p = p[len(k):]
	}

	return c, nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("slice length differ")
	}
	r := make([]byte, len(a))
	for i, v := range a {
		r[i] = v ^ b[i]
	}
	return r
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
