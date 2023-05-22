package rre

import (
	"crypto/rand"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"testing"
)

func TestZKPOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for i, curve := range curveInstances {
		basePoint := curve.Point.Random(rand.Reader)
		ek := curve.Point.Random(rand.Reader)
		A := curve.Point.Random(rand.Reader)
		B := curve.Point.Random(rand.Reader)
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover, _ := NewProver(curve, basePoint, ek, A, B, uniqueSessionId)

		s := curve.Scalar.Random(rand.Reader)
		r := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(s, r)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, basePoint, ek, A, B, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}

func TestComZKPOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for i, curve := range curveInstances {
		basePoint := curve.Point.Random(rand.Reader)
		ek := curve.Point.Random(rand.Reader)
		A := curve.Point.Random(rand.Reader)
		B := curve.Point.Random(rand.Reader)
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover, _ := NewProver(curve, basePoint, ek, A, B, uniqueSessionId)

		s := curve.Scalar.Random(rand.Reader)
		r := curve.Scalar.Random(rand.Reader)
		proof, commitment, err := prover.ComProve(s, r)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = DeComVerify(proof, commitment, curve, basePoint, ek, A, B, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
