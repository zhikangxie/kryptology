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

			require.Equal(tt, aliceView.Pk, bobView.PkPeer)
			require.Equal(tt, aliceView.PkPeer, bobView.Pk)
			require.Equal(tt, aliceView.PkJoint, bobView.PkJoint)
		})
	}
}

func BenchmarkDkg(b *testing.B) {
	curve := curves.K256()
	alice := NewAlice(curve)
	bob := NewBob(curve)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		commitment, _ := alice.Step1()
		bobProof, _ := bob.Step2(commitment)
		aliceProof, _ := alice.Step3(bobProof)
		bob.Step4(aliceProof)
	}
}

func BenchmarkDkgStep1(b *testing.B) {
	curve := curves.K256()
	alice := NewAlice(curve)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alice.Step1()
	}
}

func BenchmarkDkgStep2(b *testing.B) {
	curve := curves.K256()
	alice := NewAlice(curve)
	bob := NewBob(curve)
	commitment, _ := alice.Step1()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bob.Step2(commitment)
	}
}

func BenchmarkDkgStep3(b *testing.B) {
	curve := curves.K256()
	alice := NewAlice(curve)
	bob := NewBob(curve)
	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alice.Step3(bobProof)
	}
}

func BenchmarkDkgStep4(b *testing.B) {
	curve := curves.K256()
	alice := NewAlice(curve)
	bob := NewBob(curve)
	commitment, _ := alice.Step1()
	bobProof, _ := bob.Step2(commitment)
	aliceProof, _ := alice.Step3(bobProof)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bob.Step4(aliceProof)
	}
}
