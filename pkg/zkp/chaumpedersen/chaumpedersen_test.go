package chaumpedersen

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
		u := curve.Point.Random(rand.Reader)
		v := curve.Point.Random(rand.Reader)
		uniqueSessionId := sha3.New256().Sum([]byte("random seed"))
		prover, _ := NewProver(curve, u, v, uniqueSessionId)

		x := curve.Scalar.Random(rand.Reader)
		proof, err := prover.Prove(x)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))

		err = Verify(proof, curve, u, v, uniqueSessionId)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
