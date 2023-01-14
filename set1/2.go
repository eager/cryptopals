package main

import (
	"encoding/hex"
	"errors"
	"log"
)

func main() {

	h1, e1 := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	h2, e2 := hex.DecodeString("686974207468652062756c6c277320657965")

	if e1 != nil || e2 != nil {
		panic("failed to decode")
	}

	actual, err := xor(h1, h2)

	if err != nil {
		panic("failed to xor")
	}

	expected := "746865206b696420646f6e277420706c6179"

	log.Printf("actual == expected: %v", hex.EncodeToString(actual) == expected)

}

func xor(b1, b2 []byte) ([]byte, error) {

	if len(b1) != len(b2) {
		return nil, errors.New("slices of different lengths")
	}

	result := make([]byte, 0)

	for i, _ := range b1 {
		result = append(result, b1[i]^b2[i])
	}

	return result, nil

}
