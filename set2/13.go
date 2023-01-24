package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
)

func main13() {

	key, err := RandomAesKey()
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	_ = key

	blockSize := DetectBlockSize(key, Oracle13)
	log.Printf("detected blocksize: %d", blockSize)

	adminPrefix := bytes.Repeat([]byte{'A'}, blockSize-len("email="))
	adminPadded := PKCS7Pad([]byte("admin"), blockSize)

	adminBlock := Oracle13(append(adminPrefix, adminPadded...), key)[blockSize : blockSize*2]

	email := "a@example.com"

	for len("email="+email+"&uid=10&role=")%blockSize != 0 {
		email = "a" + email
	}

	baseProfile := Oracle13([]byte(email), key)
	prefixBlocks := baseProfile[0 : len(baseProfile)-blockSize]

	cutAndPaste := append(prefixBlocks, adminBlock...)

	log.Printf("%s", hex.EncodeToString(cutAndPaste))
	log.Print(DecryptedProfileFrom(cutAndPaste, key))
}

type Profile struct {
	email string
	uid   int
	role  string
}

func Oracle13(email []byte, key []byte) []byte {

	return EncryptedProfileFor(string(email), key)
}

func DecryptedProfileFrom(b, key []byte) Profile {
	crypter := ECBCrypter{}
	b, err := crypter.decrypt(b, key, []byte{})
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	return ParseProfile(string(b))
}

func EncryptedProfileFor(email string, key []byte) []byte {

	crypter := ECBCrypter{}

	encoded := ProfileFor(email)

	c, err := crypter.encrypt([]byte(encoded), key, []byte{})
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}

	return c
}

func ProfileFor(email string) string {
	p := Profile{email, 10, "user"}

	return p.Encode()
}

func (p Profile) Encode() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", Santize(p.email), p.uid, p.role)
}

func Santize(s string) string {
	s = strings.ReplaceAll(s, "&", "")
	s = strings.ReplaceAll(s, "=", "")
	return s
}

func ProfileFromMap(m map[string]string) Profile {
	email := m["email"]
	uid, err := strconv.Atoi(m["uid"])
	if err != nil {
		panic("failed to convert from map to Profile")
	}
	role := m["role"]

	return Profile{email, uid, role}
}

func ParseProfile(profile string) Profile {
	parts := strings.Split(profile, "&")

	m := make(map[string]string)

	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			panic("invalid encoding")
		}
		m[kv[0]] = kv[1]
	}

	return ProfileFromMap(m)
}
