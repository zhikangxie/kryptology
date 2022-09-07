package mta

import (
	"math/big"
	"testing"

	tt "github.com/coinbase/kryptology/internal"
	crypto "github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/stretchr/testify/require"
)

func makeNewPaillierPublicKey(t *testing.T, n *big.Int) *paillier.PublicKey {
	t.Helper()
	publicKey, err := paillier.NewPubkey(n)
	require.NoError(t, err)
	return publicKey
}

func TestMtAPaillier(t *testing.T) {
	p := tt.B10("165498465971525536497859961269214938631289964308823560526920537236787050377699904896554622379770774622567664583533323254169290844053351296829514419428489585830394868303448384771151376037064711115810339324861594209655768995895643373763166292366557525131878080032169065959558884224551806641003919879441772258023")
	q := tt.B10("153220808452726670380485250948911100156879705361932013063379432599289284377538415448437552509228215741069875651231891196863559464003506000735603508391315084830677543632875274002601909274977876224268309554767555583618065737119993835971994691072180460197745186395985316826257903003552375842892383205848110359007")
	sk, _ := paillier.NewSecretKey(p, q)
	pk := makeNewPaillierPublicKey(t, sk.N)

	sender, err := NewMultiplySender(pk)
	require.NoError(t, err)
	receiver, err := NewMultiplyReceiver(pk, sk)
	require.NoError(t, err)

	a, err := crypto.Rand(q)
	b, err := crypto.Rand(q)

	round1Output := receiver.init(b)
	ta, round2Output := sender.update(a, round1Output)
	tb := receiver.multiply(round2Output)

	product := new(big.Int).Mul(a, b)
	sum := new(big.Int).Add(ta, tb)
	require.Equal(t, product, sum)
}
