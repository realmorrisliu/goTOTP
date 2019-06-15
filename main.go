package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strconv"
	"time"
)

func main() {
	// Seed for HMAC-SHA1 - 20 bytes
	seed := "3132333435363738393031323334353637383930"
	// Seed for HMAC-SHA256 - 32 bytes
	seed32 := "3132333435363738393031323334353637383930313233343536373839303132"
	// Seed for HMAC-SHA512 - 64 bytes
	seed64 := "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"

	var (
		TO        int64 = 0
		X         int64 = 30
		testTimes       = []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	)

	dateFormat := "2006-01-02 15:04:05"

	fmt.Println("+---------------+-----------------------+------------------+--------+--------+")
	fmt.Println("|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  | Mode   |")
	fmt.Println("+---------------+-----------------------+------------------+--------+--------+")

	for _, testTime := range testTimes {
		T := (testTime - TO) / X
		steps := fmt.Sprintf("%016X", T)
		fmtTime := fmt.Sprintf("%-11s", strconv.FormatInt(testTime, 10))
		utcTime := time.Unix(testTime, 0).UTC().Format(dateFormat)

		fmt.Print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |")
		fmt.Println(GenerateTOTP(seed, T, 8, sha1.New) + "| SHA1   |")
		fmt.Print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |")
		fmt.Println(GenerateTOTP(seed32, T, 8, sha256.New) + "| SHA256 |")
		fmt.Print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |")
		fmt.Println(GenerateTOTP(seed64, T, 8, sha512.New) + "| SHA512 |")
		fmt.Println("+---------------+-----------------------+------------------+--------+--------+")
	}
}
