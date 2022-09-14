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
