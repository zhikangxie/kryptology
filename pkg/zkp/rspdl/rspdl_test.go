package rspdl

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
		T := curve.Point.Random(rand.Reader)
		A := curve.Point.Random(rand.Reader)
		B := curve.Point.Random(rand.Reader)
		x := curve.Scalar.Random(rand.Reader)
		X := basePoint.Mul(x)
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover, _ := NewProver(curve, basePoint, T, A, B, X, uniqueSessionId)

		r := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(x, r)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, basePoint, T, A, B, X, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
