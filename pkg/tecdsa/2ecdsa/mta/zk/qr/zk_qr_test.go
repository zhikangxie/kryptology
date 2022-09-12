package zk_qr

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
	pp := &Param{N0}
	h_sqrt, _ := rand.Int(rand.Reader, N0)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	prover := Prover{pp, prover_tx}
	verifier := Verifier{pp, verifier_tx}

	statement, commitment, proof := prover.Prove(Witness{h_sqrt})
	require.True(t, verifier.Verify(statement, commitment, proof))
}
