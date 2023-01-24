package main

import (
	"testing"
)

func TestParseProfile(t *testing.T) {

	expected := Profile{"foo@bar.com", 10, "user"}
	actual := ParseProfile("email=foo@bar.com&uid=10&role=user")
	if expected != actual {
		t.Fatalf("%v != %v", expected, actual)
	}

	expected = Profile{"baz@qux.com", 1000, "admin"}
	actual = ParseProfile("email=baz@qux.com&uid=1000&role=admin")
	if expected != actual {
		t.Fatalf("%v != %v", expected, actual)
	}
}

func TestEncodeProfile(t *testing.T) {

	expected := "email=foo@bar.com&uid=10&role=user"
	actual := ProfileFor("foo@bar.com")

	if expected != actual {
		t.Fatalf("%v != %v", expected, actual)
	}

	expected = "email=foobaz@bar.com&uid=10&role=user"
	actual = ProfileFor("foo&baz@bar.com")

	if expected != actual {
		t.Fatalf("%v != %v", expected, actual)
	}

}

func TestRoundTripEncryption(t *testing.T) {

	key, err := RandomAesKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	expected := Profile{"foo@bar.com", 10, "user"}
	actual := DecryptedProfileFrom(EncryptedProfileFor("foo@bar.com", key), key)

	t.Logf("decrypted: %v", actual)
	if expected != actual {
		t.Fatalf("%v != %v", expected, actual)
	}
}
