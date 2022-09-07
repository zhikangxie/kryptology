package sign_online

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/dkg"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline"
)

func TestOnline(t *testing.T) {
	curve := curves.K256()

	alice := dkg.NewAlice(curve)
	bob := dkg.NewBob(curve)

	commitment, err := alice.Step1()
	require.NoError(t, err)
	bobProof, err := bob.Step2(commitment)
	require.NoError(t, err)
	aliceProof, err := alice.Step3(bobProof)
	require.NoError(t, err)
	err = bob.Step4(aliceProof)
	require.NoError(t, err)

	aliceView := alice.Output()
	bobView := bob.Output()

	require.Equal(t, aliceView.Pk, bobView.PkPeer)
	require.Equal(t, aliceView.PkPeer, bobView.Pk)
	require.Equal(t, aliceView.PkJoint, bobView.PkJoint)

	uniqueSessionId := [simplest.DigestSize]byte{}

	sender, _ := simplest.NewSender(curve, kos.Kappa, uniqueSessionId)
	receiver, _ := simplest.NewReceiver(curve, kos.Kappa, uniqueSessionId)
	r1, _ := sender.Round1ComputeAndZkpToPublicKey()
	r2, _ := receiver.Round2VerifySchnorrAndPadTransfer(r1)
	r3, _ := sender.Round3PadTransfer(r2)
	r4, _ := receiver.Round4RespondToChallenge(r3)
	r5, _ := sender.Round5Verify(r4)
	receiver.Round6Verify(r5)

	mta_sender, _ := sign_offline.NewMultiplySender(receiver.Output, curve, uniqueSessionId)
	mta_receiver, _ := sign_offline.NewMultiplyReceiver(sender.Output, curve, uniqueSessionId)

	{
		alice := sign_offline.NewAlice[*kos.Round1Output, *sign_offline.MultiplyRound2Output](curve, aliceView, mta_sender)
		bob := sign_offline.NewBob[*kos.Round1Output, *sign_offline.MultiplyRound2Output](curve, bobView, mta_receiver)

		commitment, a := bob.Step1()
		q1, r1, cc, proof, b := alice.Step2(commitment, a)
		proof = bob.Step3(q1, r1, cc, proof, b)
		alice.Step4(proof)

		aliceView := alice.Output()
		bobView := bob.Output()

		{
			alice := NewAlice(curve, aliceView)
			bob := NewBob(curve, bobView)
			m := [100]byte{}
			s2 := bob.Step1(m[:])
			alice.Step2(m[:], s2)
		}
	}
}
