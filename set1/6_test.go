package main

import "testing"

func TestHamming(t *testing.T) {

	if hamming([]byte("this is a test"), []byte("wokka wokka!!!")) != 37 {
		t.Fail()
	}
}
