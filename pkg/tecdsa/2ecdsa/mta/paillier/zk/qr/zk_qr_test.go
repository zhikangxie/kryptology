package zk_qr

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	pk, _, _ := paillier.NewKeys()
	pp := &Agreed{pk.N}
	h_sqrt, _ := rand.Int(rand.Reader, pp.N)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), pp.N)
	st := h

	proof := Prove(prover_tx, pp, &Witness{h_sqrt}, st)
	require.True(t, Verify(verifier_tx, pp, st, proof))
}

func BenchmarkProve(b *testing.B) {
	pk, _, _ := paillier.NewKeys()
	pp := &Agreed{pk.N}
	h_sqrt, _ := rand.Int(rand.Reader, pp.N)

	prover_tx := merlin.NewTranscript("test")

	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), pp.N)
	st := h

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Prove(prover_tx, pp, &Witness{h_sqrt}, st)
	}
}

func BenchmarkVerify(b *testing.B) {
	pk, _, _ := paillier.NewKeys()
	pp := &Agreed{pk.N}
	h_sqrt, _ := rand.Int(rand.Reader, pp.N)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), pp.N)
	st := h

	proof := Prove(prover_tx, pp, &Witness{h_sqrt}, st)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(verifier_tx, pp, st, proof)
	}
}
