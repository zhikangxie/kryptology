package dkg

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestDkg(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		boundCurve := curve
		t.Run(fmt.Sprintf("testing dkg for curve %s", boundCurve.Name), func(tt *testing.T) {
			tt.Parallel()
			alice := NewAlice(boundCurve)
			bob := NewBob(boundCurve)

			commitment, err := alice.Step1()
			require.NoError(tt, err)
			bobProof, err := bob.Step2(commitment)
			require.NoError(tt, err)
			aliceProof, err := alice.Step3(bobProof)
			require.NoError(tt, err)
			err = bob.Step4(aliceProof)
			require.NoError(tt, err)

			aliceView := alice.Output()
			bobView := bob.Output()

			require.Equal(tt, aliceView.pk, bobView.pkPeer)
			require.Equal(tt, aliceView.pkPeer, bobView.pk)
			require.Equal(tt, aliceView.pkJoint, bobView.pkJoint)
		})
	}
}
