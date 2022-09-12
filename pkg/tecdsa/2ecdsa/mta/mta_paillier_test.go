package mta

import (
	"math/big"
	"testing"

	crypto "github.com/coinbase/kryptology/pkg/core"
	"github.com/stretchr/testify/require"
)

func TestMtAPaillier(t *testing.T) {

	//Keygen
	sender, receiver, q := KeyGenProve(128)
	require.True(t, sender.KeyGenVerify())

	//setup of proof in pwr
	pwrpp, qrst, qrproof := sender.Init_setup()
	receiver.Init_setup(qrst, qrproof)

	a, err := crypto.Rand(q)
	require.NoError(t, err)
	b, err := crypto.Rand(q)
	require.NoError(t, err)

	round1Output := receiver.Init(pwrpp, b)
	ta, round2Output := sender.Update(pwrpp, a, round1Output)
	tb := receiver.Multiply(round2Output)

	product := new(big.Int).Mod(new(big.Int).Mul(a, b), q)
	sum := new(big.Int).Mod(new(big.Int).Add(ta, tb), q)
	require.Equal(t, product, sum)
}
