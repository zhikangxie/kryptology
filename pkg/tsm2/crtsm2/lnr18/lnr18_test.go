package lnr18

import (
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/paillier"
	mta_paillier "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/paillier"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkDSPaillier(b *testing.B) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	str := "test message test message test message test message test message test message test message test message test message test message "
	scheme.message = []byte(str)

	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var sender = mta_paillier.NewSender(scheme.curve, p, q)
	var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)
	scheme.mtaSender = sender
	scheme.mtaReceiver = receiver

	err := scheme.DKGPhase1()
	require.NoError(b, err, "failed in Phase 1 of DKG")

	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		err = scheme.DSPhase1()
		require.NoError(b, err, "failed in Phase 1 of DS")

		err = scheme.DSPhase2()
		require.NoError(b, err, "failed in Phase 2 of DS")

		err = scheme.DSPhase3()
		require.NoError(b, err, "failed in Phase 3 of DS")

		err = scheme.DSPhase4()
		require.NoError(b, err, "failed in Phase 4 of DS")

		err = scheme.DSPhase5()
		require.NoError(b, err, "failed in Phase 5 of DS")

		err = scheme.DSPhase6()
		require.NoError(b, err, "failed in Phase 6 of DS")

		err = scheme.DSPhase7()
		require.NoError(b, err, "failed in Phase 7 of DS")

		err = scheme.DSPhase8()
		require.NoError(b, err, "failed in Phase 8 of DS")
	}
}
