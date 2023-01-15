package main

import (
	"encoding/base64"
	"log"
	"math"
	"os"
)

func main() {

	input, err := os.ReadFile("6.txt")
	if err != nil {
		panic("could not read input")
	}

	bytes, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		panic("could not decode input")
	}

	k := findKeySize(bytes)
	log.Printf("key size: %d", k)
	key := findKey(k, bytes)

	plaintext := crypt(bytes, key)

	log.Print(string(plaintext))
	log.Printf("key: %s", string(key))
}

func findKey(k int, bytes []byte) []byte {

	blocks := make([][]byte, 0)

	for i, b := range bytes {
		idx := i % k
		if idx == len(blocks) {
			blocks = append(blocks, make([]byte, 0))
		}
		blocks[idx] = append(blocks[idx], b)
	}

	key := make([]byte, 0)

	for _, b := range blocks {
		_, _, c := decipherBytes(b)
		key = append(key, c)
	}

	return key
}

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
