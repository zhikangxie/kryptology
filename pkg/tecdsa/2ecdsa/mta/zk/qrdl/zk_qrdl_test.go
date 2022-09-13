package zk_qrdl

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
	h_sqrt, _ := rand.Int(rand.Reader, pk.N)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), pk.N)
	pp := &Agreed{pk.N, h}

	alpha, _ := rand.Int(rand.Reader, pk.N)
	g := new(big.Int).Exp(h, alpha, pk.N)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	st := g

	proof := Prove(prover_tx, pp, &Witness{alpha}, st)
	require.True(t, Verify(verifier_tx, pp, st, proof))
}
