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
		A := curve.Point.Random(rand.Reader)
		B := curve.Point.Random(rand.Reader)
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover, _ := NewProver(curve, basePoint, A, B, uniqueSessionId)

		x := curve.Scalar.Random(rand.Reader)
		r := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(x, r)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, basePoint, A, B, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
