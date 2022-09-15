package zk_r_p

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	p, _ := core.GenerateSafePrime(paillier.PaillierPrimeBits)
	q, _ := core.GenerateSafePrime(paillier.PaillierPrimeBits)
	sk, _ := paillier.NewSecretKey(p, q)
	
	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	proof := Prove(prover_tx, &Witness{p, q}, sk.N)
	require.True(t, Verify(verifier_tx, sk.N, proof))
}

func BenchmarkProve(b *testing.B) {
	p, _ := core.GenerateSafePrime(paillier.PaillierPrimeBits)
	q, _ := core.GenerateSafePrime(paillier.PaillierPrimeBits)
	sk, _ := paillier.NewSecretKey(p, q)
	
	prover_tx := merlin.NewTranscript("test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Prove(prover_tx, &Witness{p, q}, sk.N)
	}
}

func BenchmarkVerify(b *testing.B) {
	p, _ := core.GenerateSafePrime(paillier.PaillierPrimeBits)
	q, _ := core.GenerateSafePrime(paillier.PaillierPrimeBits)
	sk, _ := paillier.NewSecretKey(p, q)
	
	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	proof := Prove(prover_tx, &Witness{p, q}, sk.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(verifier_tx, sk.N, proof)
	}
}
