package zk

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZKRAffRan(t *testing.T) {
	verifier := NewVerifier(2048)
	prover := new(AffRanProver)
	NN := new(big.Int).Mul(verifier.N, verifier.N)
	c_B, _ := rand.Int(rand.Reader, NN)
	prover.SetParamsAndWitnesses(verifier.N, verifier.g, verifier.h, verifier.q, c_B)
	verifier.SetStatement(prover.c_A, prover.c_B)
	A, B1, B2, B3, B4 := prover.Prove1()
	e := verifier.Challenge(A, B1, B2, B3, B4)
	z1, z2, z3, z4 := prover.Prove2(e)
	require.True(t, verifier.Verify(z1, z2, z3, z4))
}
