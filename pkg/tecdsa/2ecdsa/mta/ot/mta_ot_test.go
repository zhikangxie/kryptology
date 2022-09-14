package mta_ot

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/ot/ottest"
)

func TestMtAOT(t *testing.T) {
	curve := curves.K256()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)

	baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, kos.Kappa, hashKeySeed)
	require.NoError(t, err)

	sender, err := NewSender(baseOtReceiverOutput, curve, hashKeySeed)
	require.NoError(t, err)
	receiver, err := NewReceiver(baseOtSenderOutput, curve, hashKeySeed)
	require.NoError(t, err)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	round1Output := receiver.Init(beta)
	ta, round2Output := sender.Update(alpha, round1Output)
	tb := receiver.Multiply(round2Output)

	product := alpha.Mul(beta)
	sum := ta.Add(tb)
	require.Equal(t, product, sum)
}
