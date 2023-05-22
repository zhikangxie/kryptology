package scheme

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkDKG(b *testing.B) {
	curveInit := curves.K256()

	nInit := num

	str := "test message"
	messageInit := []byte(str)

	var sksInit [num]curves.Scalar
	var pkProofsInit [num]*schnorr.Proof
	var pkCommitmentsInit [num]schnorr.Commitment
	var pkProofSessionIdsInit [num]schnorr.SessionId

	var jointPkProofsInit [num]*chaumpedersen.Proof
	var jointPkProofSessionIdsInit [num]chaumpedersen.SessionId

	var nonceInit [num]curves.Scalar
	var nonceProofsInit [num]*schnorr.Proof
	var nonceCommitmentsInit [num]schnorr.Commitment
	var nonceProofSessionIdsInit [num]schnorr.SessionId

	scheme := NewScheme(curveInit, nInit, messageInit, sksInit, pkProofsInit, pkCommitmentsInit, pkProofSessionIdsInit,
		jointPkProofsInit, jointPkProofSessionIdsInit, nonceInit, nonceProofsInit, nonceCommitmentsInit, nonceProofSessionIdsInit)

	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = scheme.DKGStep1()
		require.NoError(b, err, fmt.Sprintf("failed in step 1 of DKG"))

		err = scheme.DKGStep2()
		require.NoError(b, err, fmt.Sprintf("failed in step 2 of DKG"))

		err = scheme.DKGStep3A()
		require.NoError(b, err, fmt.Sprintf("failed in step 3A of DKG"))

		err = scheme.DKGStep3B()
		require.NoError(b, err, fmt.Sprintf("failed in step 3B of DKG"))
	}
}

func BenchmarkDS(b *testing.B) {
	curveInit := curves.K256()

	nInit := num

	str := "test message"
	messageInit := []byte(str)

	var sksInit [num]curves.Scalar
	var pkProofsInit [num]*schnorr.Proof
	var pkCommitmentsInit [num]schnorr.Commitment
	var pkProofSessionIdsInit [num]schnorr.SessionId

	var jointPkProofsInit [num]*chaumpedersen.Proof
	var jointPkProofSessionIdsInit [num]chaumpedersen.SessionId

	var nonceInit [num]curves.Scalar
	var nonceProofsInit [num]*schnorr.Proof
	var nonceCommitmentsInit [num]schnorr.Commitment
	var nonceProofSessionIdsInit [num]schnorr.SessionId

	scheme := NewScheme(curveInit, nInit, messageInit, sksInit, pkProofsInit, pkCommitmentsInit, pkProofSessionIdsInit,
		jointPkProofsInit, jointPkProofSessionIdsInit, nonceInit, nonceProofsInit, nonceCommitmentsInit, nonceProofSessionIdsInit)

	var err error
	err = scheme.DKGStep1()
	require.NoError(b, err, fmt.Sprintf("failed in step 1 of DKG"))

	err = scheme.DKGStep2()
	require.NoError(b, err, fmt.Sprintf("failed in step 2 of DKG"))

	err = scheme.DKGStep3A()
	require.NoError(b, err, fmt.Sprintf("failed in step 3A of DKG"))

	err = scheme.DKGStep3B()
	require.NoError(b, err, fmt.Sprintf("failed in step 3B of DKG"))

	var r curves.Scalar
	var s curves.Scalar

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = scheme.DSStep1()
		require.NoError(b, err, fmt.Sprintf("failed in step 1 of DS"))

		err = scheme.DSStep2A()
		require.NoError(b, err, fmt.Sprintf("failed in step 2A of DS"))

		r = scheme.DSStep2B()

		s = scheme.DSStep3A(r)

		err = scheme.DSStep3B(r, s)
		require.NoError(b, err, fmt.Sprintf("failed in step 3B of DS"))
	}
}
