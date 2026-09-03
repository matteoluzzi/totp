package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
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

func readOrGenerateSecret(path string) []byte {

	var secret []byte
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

func validateTOTP(secret []byte, totp uint32) bool {

	//Generate the current TOTP value based on the secret and the current time, then compare it to the provided TOTP value. If they match, return true; otherwise, return false.

	steps := 30 //30 seconds
	unixTimestamp := time.Now().Unix()

	numOfSteps := int(math.Floor(float64(unixTimestamp) / float64(steps))) // 8 bytes

	buffer := make([]byte, 8) // same as numOfSteps, 8 bytes for uint64
	binary.BigEndian.PutUint64(buffer, uint64(numOfSteps))

	hmac := computeHMACSHA1(secret, buffer)

	return dynamicTruncate(hmac) == totp
}

func main() {

	// Read or generate the secret key
	secret := readOrGenerateSecret(filepath.Join(os.TempDir(), "totp_secret.txt"))

	issuer := "MyApp"
	user := "matteo@example.no"

	// Generate the otpauth URL for QR code generation
	otpauthURL := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", issuer, user, base32.StdEncoding.EncodeToString(secret), issuer)

	qr, err := qrcode.New(otpauthURL, qrcode.Medium)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate QR code: %v\n", err)
		panic(err)
	}

	fmt.Println(qr.ToSmallString(false))
	fmt.Printf("\nScan the QR code with your authentication app\n")
	fmt.Print("Enter the OTP from your authenticator app: ")

	scanner := bufio.NewScanner(os.Stdin)
	b := scanner.Scan()
	if !b {
		fmt.Fprintf(os.Stderr, "Failed to read input: %v\n", scanner.Err())
		return
	}
	input := scanner.Text()

	totp, err := strconv.ParseUint(input, 10, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid OTP format: %v\n", err)
		return
	}

	if validateTOTP(secret, uint32(totp)) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed! Invalid OTP.")
	}
}
