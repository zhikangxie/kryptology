package zk_qr

import (
	"testing"

	core "github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	p, _ := core.GenerateSafePrime(zk.N_BITS / 2)
	q, _ := core.GenerateSafePrime(zk.N_BITS / 2)

	prover_tx := merlin.NewTranscript("test")
	verifier_tx := merlin.NewTranscript("test")

	prover := Prover{prover_tx}
	verifier := Verifier{verifier_tx}

	statement, commitment, proof := prover.Prove(Witness{p, q})
	require.True(t, verifier.Verify(statement, commitment, proof))
}
