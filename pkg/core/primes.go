//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package core

import (
	"math/big"
	"github.com/credentials/safeprime"
)

// GenerateSafePrime creates a prime number `p`
// where (`p`-1)/2 is also prime with at least `bits`
func GenerateSafePrime(bits uint) (*big.Int, error) {
	return safeprime.Generate(int(bits))
}
