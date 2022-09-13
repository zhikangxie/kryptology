package zk_qrdl

import (
	"crypto/rand"
	"math/big"
	"testing"

	core "github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	p, _ := core.GenerateSafePrime(zk.N_BITS / 2)
	q, _ := core.GenerateSafePrime(zk.N_BITS / 2)
	N0 := new(big.Int).Mul(p, q)
	h_sqrt, _ := rand.Int(rand.Reader, N0)
	h := new(big.Int).Mod(new(big.Int).Mul(h_sqrt, h_sqrt), N0)
	alpha, _ := rand.Int(rand.Reader, N0)
	g := new(big.Int).Exp(h, alpha, N0)
	pp := &Param{N0, h}

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	st := Statement{g}

	proof := Prove(Witness{alpha}, st, prover_tx, pp)
	//require.True(t, verifier.Verify(statement, commitment, proof))
	require.True(t, Verify(st, proof, verifier_tx, pp))
}
