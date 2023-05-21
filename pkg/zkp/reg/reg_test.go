package reg

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
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover, _ := NewProver(curve, basePoint, ek, uniqueSessionId)

		m := curve.Scalar.Random(rand.Reader)
		r := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(m, r)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, basePoint, ek, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
