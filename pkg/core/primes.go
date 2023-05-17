//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package core

import (
	"errors"
	"github.com/joho/godotenv"
	"github.com/rainycape/dl"
	"math/big"
	"os"
	"regexp"
)

var bnNew func() uintptr
var bnFree func(uintptr)
var bnGenPrime func(uintptr, int, int, uintptr, uintptr, uintptr) int
var bnToHex func(uintptr) string

const projectDirName = "kryptology" // change to relevant project name

func linkOpenssl() (*dl.DL, error) {
	projectName := regexp.MustCompile(`^(.*` + projectDirName + `)`)
	currentWorkDirectory, _ := os.Getwd()
	rootPath := projectName.Find([]byte(currentWorkDirectory))

	err := godotenv.Load(string(rootPath) + `/.env`)

	if err != nil {
		return nil, err
	}

	path := os.Getenv("LIBSSL_PATH")

	if path == "" {
		path = "libssl"
	}

	openssl, err := dl.Open(path, 0)
	if err != nil {
		return nil, err
	}

	if err = openssl.Sym("BN_new", &bnNew); err != nil {
		return nil, err
	}

	if err = openssl.Sym("BN_clear_free", &bnFree); err != nil {
		return nil, err
	}

	if err = openssl.Sym("BN_generate_prime_ex", &bnGenPrime); err != nil {
		return nil, err
	}

	if err = openssl.Sym("BN_bn2hex", &bnToHex); err != nil {
		return nil, err
	}

	return openssl, nil
}

// GenerateSafePrime creates a prime number `p`
// where (`p`-1)/2 is also prime with at least `bits`
func GenerateSafePrime(bits uint) (*big.Int, error) {
	openssl, err := linkOpenssl()
	if err != nil {
		return nil, err
	}
	defer openssl.Close()

	bignum := bnNew()
	if bignum == 0 {
		return nil, errors.New("BN_new could not allocate new bignum")
	}
	defer bnFree(bignum)

	if r := bnGenPrime(bignum, int(bits), 1, 0, 0, 0); r != 1 {
		return nil, errors.New("BN_generate_prime_ex failed")
	}

	x := new(big.Int)
	x.SetString(bnToHex(bignum), 16)
	return x, nil
}

func GenerateSafePrimes(bits uint, n uint) (chan *big.Int, error) {
	openssl, _ := linkOpenssl()

	defer openssl.Close()

	primes := make(chan *big.Int, n)

	for i := uint(0); i < n; i++ {
		go func() {
			bignum := bnNew()
			if bignum == 0 {
				panic("BN_new could not allocate new bignum")
			}
			defer bnFree(bignum)
			if bnGenPrime(bignum, int(bits), 1, 0, 0, 0) != 1 {
				panic("BN_generate_prime_ex failed")
			}
			x := new(big.Int)
			x.SetString(bnToHex(bignum), 16)
			primes <- x
		}()
	}

	return primes, nil
}
