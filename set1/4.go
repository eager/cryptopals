package main

import (
	"log"
	"math"
	"os"
	"strings"
)

func main() {

	input, err := os.ReadFile("4.txt")
	if err != nil {
		panic("could not read input")
	}

	bestScore := math.MaxFloat64
	result := ""

	for _, line := range strings.Split(strings.TrimSpace(string(input)), "\n") {

		s, score, _ := decipher(line)
		if score < bestScore {
			bestScore = score
			result = s
		}

	}

	log.Print(result)
}
