package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"strings"
)

func main() {

	input, err := os.ReadFile("./8.txt")
	if err != nil {
		panic("failed to read input")
	}

	bestRepeatedBlocks := 0
	blockSize := 16
	aesCipher := ""

	for _, line := range strings.Split(string(input), "\n") {
		cipher, err := hex.DecodeString(line)
		if err != nil {
			panic("could not decode line")
		}

		repeatedBlocks := 0

		for len(cipher)-blockSize > 0 {
			block := cipher[0:blockSize]
			cipher = cipher[blockSize:]
			for c := cipher; len(c) > blockSize; c = c[blockSize:] {

				if bytes.Compare(block, c[0:blockSize]) == 0 {
					repeatedBlocks = repeatedBlocks + 1
				}

			}
		}
		if repeatedBlocks > bestRepeatedBlocks {
			bestRepeatedBlocks = repeatedBlocks
			aesCipher = line
		}
	}

	log.Printf("repeated blocks: %d", bestRepeatedBlocks)
	log.Print(aesCipher)
}
