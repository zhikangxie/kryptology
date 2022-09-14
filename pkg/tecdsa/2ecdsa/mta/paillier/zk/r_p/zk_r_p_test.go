package zk_r_p

import (
	"crypto/rand"
	"testing"

	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	p, _ := rand.Prime(rand.Reader,paillier.PaillierPrimeBits)
	q, _ := rand.Prime(rand.Reader,paillier.PaillierPrimeBits)
	sk, _ := paillier.NewSecretKey(p, q)
	
	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	proof := Prove(prover_tx, &Witness{p, q}, sk.N)
	require.False(t, Verify(verifier_tx, sk.N, proof))
}
