package main

import (
	"bytes"
	"fmt"
	"log"
)

func main9() {
	s := "YELLOW SUBMARINE"
	p := pad([]byte(s), 20)

	PrintEscaped(string(p))

	for i := 1; i < 32; i = i + 1 {
		padded := pad([]byte(s), i)
		PrintEscaped(string(padded))
		unpadded, err := unpad(padded, i)
		if err != nil {
			panic("failed to unpad")
		}
		PrintEscaped(string(unpadded))
	}
}

func pad(b []byte, block int) []byte {

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

func unpad(b []byte, block int) ([]byte, error) {

	if len(b)%block != 0 {
		return nil, fmt.Errorf("input is invalid length: %d (%d)", len(b), block)
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

func PrintEscaped(s string) {

	escaped := make([]byte, 0)

	for _, r := range s {
		if r >= 32 && r < 127 {
			escaped = append(escaped, byte(r))
		} else {
			escaped = append(escaped, fmt.Sprintf("\\x%03d", r)...)
		}
	}

	log.Print(string(escaped))

}
