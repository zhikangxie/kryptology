package mta

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestMtAPaillier(t *testing.T) {
	curve := curves.K256()

	sender := NewMultiplySender(curve)
	receiver := NewMultiplyReceiver(curve)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	round1Output := receiver.Init(beta)
	ta, round2Output := sender.Update(alpha, round1Output)
	tb := receiver.Multiply(round2Output)

	require.Equal(t, alpha.Mul(beta), ta.Add(tb))
}
