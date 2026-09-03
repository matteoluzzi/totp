package main

import (
	"bytes"
	"encoding/base32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Table driven test style, think JUnit @ParametrizedTest but in Go you have to manually
// create a slice of test cases and iterate over them in the test function.
func TestDynamicTruncate(t *testing.T) {
	tests := []struct {
		name string
		hmac []byte
		want uint32
	}{
		{
			name: "Test case 1",
			hmac: []byte{0x1f, 0x86, 0x2e, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2},
			want: 703902,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dynamicTruncate(tt.hmac)
			if result != tt.want {
				t.Errorf("got %d, want %d", result, tt.want)
			}
		})
	}

}

func TestReadOrGenerateSecret(t *testing.T) {

	path := filepath.Join(t.TempDir(), "totp_secret.txt")

	secret := readOrGenerateSecret(path)

	if len(secret) != 16 {
		t.Errorf("Expected secret length of 16 bytes, got %d", len(secret))
	}

	// Check if the secret was a valid Base32 encoded string by trying to decode it'
	raw, err := os.ReadFile(path)

	if err != nil {
		t.Fatalf("failed to read secret file: %v", err)
	}

	decodedSecret, err := base32.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("file content is not valid base32: %v", err)
	}

	if !bytes.Equal(secret, decodedSecret) {
		t.Errorf("Decoded secret does not match the generated secret")
	}

	// Now check if the file was created and contains the correct base32 encoded secret
	_, err = os.ReadFile(path)
	if err != nil {
		t.Errorf("Secret file should exist after invoking the function")
	}

	// Read the secret again to ensure it reads the same value
	secretAgain := readOrGenerateSecret(path)

	if !bytes.Equal(secret, secretAgain) {
		t.Errorf("Expected the same secret to be read from the file, but got different values")
	}
}
