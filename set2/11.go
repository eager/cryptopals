package main

import (
	"bytes"
	"crypto/rand"
	"log"
	"math/big"
)

func main11() {

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
