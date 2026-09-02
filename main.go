package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/base32"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func generate128BitRandomSecret() []byte {

	byteArray := make([]byte, 16) // 128 bits = 16 bytes as the RFC 4226 standard specifies a 128-bit secret key for TOTP
	_, err := rand.Read(byteArray)
	if err != nil {
		panic(err)
	}
	return byteArray
}

func computeHMACSHA1(key, message []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(message)
	return h.Sum(nil)
}

func readOrGenerateSecret() []byte {

	var secret []byte
	path := filepath.Join(os.TempDir(), "totp_secret.txt")
	base32Bytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Secret file not found, generating a new secret and saving it to %s\n", path)
		secret = generate128BitRandomSecret()
		base32Secret := base32.StdEncoding.EncodeToString(secret)

		err = os.WriteFile(path, []byte(base32Secret), 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write secret to file: %v\n", err)
			panic(err)
		}
	} else {
		secret, err = base32.StdEncoding.DecodeString(strings.TrimSpace(string(base32Bytes)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode secret from file: %v\n", err)
			panic(err)
		}
	}

	return secret
}

func dynamicTruncate(hmac []byte) uint32 {

	offset := hmac[len(hmac)-1] & 0x0f // last nibble of the hmac. This returns a value between 0 and 15, which is used as an offset to select a 4-byte slice from the HMAC result.

	// each byte of the selected slice is shifted into a uint32 in the right position and concatenateds with.
	// could have used binary.BigEndian.Uint32(hmac[offset:offset+4]) but this is more explicit and shows the bitwise operations involved in the process.
	n := uint32(hmac[offset]&0x7f)<<24 | // first byte of the selected slice, with the most significant bit masked to ensure a positive integer
		uint32(hmac[offset+1]&0xff)<<16 | // second byte of the selected slice
		uint32(hmac[offset+2]&0xff)<<8 | // third byte of the selected slice
		uint32(hmac[offset+3]&0xff)<<0 // fourth byte of the selected slice, no need to shift as it's already in the least significant position

	return n % 1_000_000 // returns the last 6 digits of the integer, which is the final TOTP value

}

func main() {

	steps := 30 //30 seconds
	unixTimestamp := time.Now().Unix()

	numOfSteps := int(math.Floor(float64(unixTimestamp) / float64(steps))) // 8 bytes
	secret := readOrGenerateSecret()

	buffer := make([]byte, 8) // same as numOfSteps, 8 bytes for uint64
	binary.BigEndian.PutUint64(buffer, uint64(numOfSteps))

	hmac := computeHMACSHA1(secret, buffer)

	fmt.Printf("TOTP: %d\n", dynamicTruncate(hmac))
}
