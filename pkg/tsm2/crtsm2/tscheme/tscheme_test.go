package tscheme

import (
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/ot/ottest"
	"github.com/coinbase/kryptology/pkg/paillier"
	mta_ot "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/ot"
	mta_paillier "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/paillier"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkDKGPaillier(b *testing.B) {
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

	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		err := scheme.DKGPhase1()
		require.NoError(b, err, "failed in Phase 1 of DKG")

		err = scheme.DKGPhase2()
		require.NoError(b, err, "failed in Phase 2 of DKG")

		err = scheme.DKGPhase3()
		require.NoError(b, err, "failed in Phase 3 of DKG")

		err = scheme.DKGPhase4()
		require.NoError(b, err, "failed in Phase 4 of DKG")
	}
}

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

	err = scheme.DKGPhase2()
	require.NoError(b, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(b, err, "failed in Phase 3 of DKG")

	err = scheme.DKGPhase4()
	require.NoError(b, err, "failed in Phase 4 of DKG")

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
		require.NoError(b, err, "failed in Phase 4 of DS")
	}
}

func BenchmarkMtAInitPaillier(b *testing.B) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	str := "test message test message test message test message test message test message test message test message test message test message "
	scheme.message = []byte(str)

	b.ResetTimer()

	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var sender = mta_paillier.NewSender(scheme.curve, p, q)
	var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)
}

func BenchmarkDKGOT(b *testing.B) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_ot.Round1Output, *mta_ot.Round2Output](curveInit)
	str := "test message test message test message test message test message test message test message test message test message test message "
	scheme.message = []byte(str)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curveInit, kos.Kappa, uniqueSessionId)

	sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curveInit, uniqueSessionId)
	receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curveInit, uniqueSessionId)
	scheme.mtaSender = sender
	scheme.mtaReceiver = receiver

	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		err := scheme.DKGPhase1()
		require.NoError(b, err, "failed in Phase 1 of DKG")

		err = scheme.DKGPhase2()
		require.NoError(b, err, "failed in Phase 2 of DKG")

		err = scheme.DKGPhase3()
		require.NoError(b, err, "failed in Phase 3 of DKG")

		err = scheme.DKGPhase4()
		require.NoError(b, err, "failed in Phase 4 of DKG")
	}
}

func BenchmarkDSOT(b *testing.B) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_ot.Round1Output, *mta_ot.Round2Output](curveInit)
	str := "test message test message test message test message test message test message test message test message test message test message "
	scheme.message = []byte(str)

	uniqueSessionId := [simplest.DigestSize]byte{}

	baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curveInit, kos.Kappa, uniqueSessionId)

	sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curveInit, uniqueSessionId)
	receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curveInit, uniqueSessionId)
	scheme.mtaSender = sender
	scheme.mtaReceiver = receiver

	err := scheme.DKGPhase1()
	require.NoError(b, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(b, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(b, err, "failed in Phase 3 of DKG")

	err = scheme.DKGPhase4()
	require.NoError(b, err, "failed in Phase 4 of DKG")

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
		require.NoError(b, err, "failed in Phase 4 of DS")
	}
}

func BenchmarkMtAInitOT(b *testing.B) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_ot.Round1Output, *mta_ot.Round2Output](curveInit)
	str := "test message test message test message test message test message test message test message test message test message test message "
	scheme.message = []byte(str)

	b.ResetTimer()

	for k := 0; k < b.N; k++ {
		uniqueSessionId := [simplest.DigestSize]byte{}

		baseOtSenderOutput, baseOtReceiverOutput, _ := ottest.RunSimplestOT(curveInit, kos.Kappa, uniqueSessionId)

		sender, _ := mta_ot.NewSender(baseOtReceiverOutput, curveInit, uniqueSessionId)
		receiver, _ := mta_ot.NewReceiver(baseOtSenderOutput, curveInit, uniqueSessionId)
		scheme.mtaSender = sender
		scheme.mtaReceiver = receiver
	}
}
