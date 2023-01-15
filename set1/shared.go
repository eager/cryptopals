package main

import (
	"encoding/hex"
	"math"
	"strings"
)

// adapted from 1.3
func decipher(s string) (string, float64, byte) {

	input, err := hex.DecodeString(s)

	if err != nil {
		panic("invalid input")
	}

	return decipherBytes(input)
}

func decipherBytes(input []byte) (string, float64, byte) {

	c := 1
	bestScore := math.MaxFloat64
	bestResult := make([]byte, 0)
	bestCipher := c

	for c < 256 {

		result := xor(input, byte(c))
		currentScore := score(string(result))
		if currentScore < bestScore {
			bestScore = currentScore
			bestResult = result
			bestCipher = c
		}

		c += 1
	}

	return string(bestResult), bestScore, byte(bestCipher)
}

func score(s string) float64 {
	counts := countLetterFrequencies(s)
	sScore := float64(0)
	length := len(s)

	for c, count := range counts {
		freq := float64(count) / float64(length)
		if c == "other" {
			sScore = sScore + 100*freq
			continue
		}
		sScore = sScore + math.Abs(freq-englishTextLetterFrequencies()[c])
	}

	return sScore
}

func xor(data []byte, b byte) []byte {
	result := make([]byte, 0)
	for _, v := range data {
		result = append(result, v^b)
	}

	return result
}

func countLetterFrequencies(s string) map[string]int {
	counts := make(map[string]int)
	for _, c := range s {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == ' ' {
			lowerC := strings.ToLower(string(c))
			counts[lowerC] = counts[lowerC] + 1
		} else {
			counts["other"] = counts["other"] + 1
		}
	}
	return counts
}

func englishTextLetterFrequencies() map[string]float64 {
	// https://en.wikipedia.org/wiki/Letter_frequency
	// https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
	return map[string]float64{
		"a": 0.00651738,
		"b": 0.0124248,
		"c": 0.0217339,
		"d": 0.0349835,
		"e": 0.1041442,
		"f": 0.0197881,
		"g": 0.0158610,
		"h": 0.0492888,
		"i": 0.0558094,
		"j": 0.0009033,
		"k": 0.0050529,
		"l": 0.0331490,
		"m": 0.0202124,
		"n": 0.0564513,
		"o": 0.0596302,
		"p": 0.0137645,
		"q": 0.0008606,
		"r": 0.0497563,
		"s": 0.0515760,
		"t": 0.0729357,
		"u": 0.0225134,
		"v": 0.0082903,
		"w": 0.0171272,
		"x": 0.0013692,
		"y": 0.0145984,
		"z": 0.0007836,
		" ": 0.1918182,
	}
}
