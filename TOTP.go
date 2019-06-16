package goTOTP

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

func GenerateTOTP(key string, time int64, returnDigits int, crypto string) string {
	var cryptoFunc func() hash.Hash
	switch crypto {
	case "SHA256":
		cryptoFunc = sha256.New
	case "SHA512":
		cryptoFunc = sha512.New
	default:
		cryptoFunc = sha1.New
	}

	s := fmt.Sprintf("%016x", time)
	msg, _ := hex.DecodeString(s)
	k, _ := hex.DecodeString(key)
	h := hmacSha(cryptoFunc, k, msg)

	DigitsPower := []int{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000}

	offset := h[len(h)-1] & 0xf
	binary := int(((h[offset] & 0x7f) << 24) |
		((h[offset+1] & 0xff) << 16) |
		((h[offset+2] & 0xff) << 8) |
		(h[offset+3] & 0xff))

	otp := binary % DigitsPower[returnDigits]

	return fmt.Sprintf("%0*d", returnDigits, otp)
}

func hmacSha(crypto func() hash.Hash, keyBytes []byte, text []byte) []int {
	h := hmac.New(crypto, keyBytes)
	h.Write(text)

	var result []int
	for _, digit := range h.Sum(nil) {
		result = append(result, int(digit))
	}

	return result
}
