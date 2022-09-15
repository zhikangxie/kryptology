package zk_r_pwr

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	q := curves.K256Curve().Params().N

	pk, _, _ := paillier.NewKeys()
	N := pk.N
	x, _ := rand.Int(rand.Reader, q)
	c, r, _ := pk.Encrypt(x)

	pk, _, _ = paillier.NewKeys()
	N0 := pk.N
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	alpha, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, alpha, N0)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	pp := NewAgreed(q, N0, g, h, N)
	statement := c
	witness := NewWitness(x, r)

	proof := Prove(prover_tx, pp, witness, statement)

	require.True(t, Verify(verifier_tx, pp, statement, proof))
}

func BenchmarkProve(b *testing.B) {
	q := curves.K256Curve().Params().N

	pk, _, _ := paillier.NewKeys()
	N := pk.N
	x, _ := rand.Int(rand.Reader, q)
	c, r, _ := pk.Encrypt(x)

	pk, _, _ = paillier.NewKeys()
	N0 := pk.N
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	alpha, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, alpha, N0)

	prover_tx := merlin.NewTranscript("test")

	pp := NewAgreed(q, N0, g, h, N)
	statement := c
	witness := NewWitness(x, r)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Prove(prover_tx, pp, witness, statement)
	}
}

func BenchmarkVerify(b *testing.B) {
	q := curves.K256Curve().Params().N

	pk, _, _ := paillier.NewKeys()
	N := pk.N
	x, _ := rand.Int(rand.Reader, q)
	c, r, _ := pk.Encrypt(x)

	pk, _, _ = paillier.NewKeys()
	N0 := pk.N
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	alpha, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, alpha, N0)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	pp := NewAgreed(q, N0, g, h, N)
	statement := c
	witness := NewWitness(x, r)

	proof := Prove(prover_tx, pp, witness, statement)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(verifier_tx, pp, statement, proof)
	}
}
