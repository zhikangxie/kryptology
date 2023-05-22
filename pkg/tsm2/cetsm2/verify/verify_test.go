package verify

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tsm2/cetsm2/dkg"
	"github.com/coinbase/kryptology/pkg/tsm2/cetsm2/ds"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDSOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}

	const n = 50

	var sks [n]curves.Scalar
	var pkProofs [n]*schnorr.Proof
	var pkCommitments [n]schnorr.Commitment
	var pkProofSessionIds [n]schnorr.SessionId

	var jointPkProofs [n]*chaumpedersen.Proof
	var jointPkProofSessionIds [n]chaumpedersen.SessionId

	var nonces [n]curves.Scalar
	var nonceProofs [n]*schnorr.Proof
	var nonceCommitments [n]schnorr.Commitment
	var nonceProofSessionIds [n]schnorr.SessionId

	str := "test message"
	message := []byte(str)

	for i, curve := range curveInstances {
		// generate pks and proofs
		for id := 1; id <= n; id++ {
			sk, pkProof, commitment, sessionId, err := dkg.PkComProve(curve)
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when generating pk with comproof for party %d", i, id))
			sks[id-1] = sk
			pkProofs[id-1] = pkProof
			pkCommitments[id-1] = commitment
			pkProofSessionIds[id-1] = sessionId
		}

		// de-com and verify pk proofs
		for id := 1; id <= n; id++ {
			err := dkg.PkDeComVerify(curve, pkProofs[id-1], pkCommitments[id-1], pkProofSessionIds[id-1])
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when verify the de-commitment and pk proof for party %d", i, id))
		}

		// generate (mid-)joint pks
		for id := 2; id <= n; id++ {
			if id == 2 {
				jointPkProof, sessionId, err := dkg.JointPkCompProve(curve, sks[id-1], pkProofs[id-2].Statement)
				require.NoError(t, err, fmt.Sprintf("failed in curve %d when party %d computing joint pk with proof", i, id))
				jointPkProofs[id-1] = jointPkProof
				jointPkProofSessionIds[id-1] = sessionId
				continue
			}
			jointPkProof, sessionId, err := dkg.JointPkCompProve(curve, sks[id-1], jointPkProofs[id-2].Statement2)
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when party %d computing joint pk with proof", i, id))
			jointPkProofs[id-1] = jointPkProof
			jointPkProofSessionIds[id-1] = sessionId
		}

		// verify joint pk proofs
		for id := 2; id <= n; id++ {
			if id == 2 {
				err := dkg.JointPkVerify(curve, pkProofs[id-2].Statement, jointPkProofs[id-1], jointPkProofSessionIds[id-1])
				require.NoError(t, err, fmt.Sprintf("failed in curve %d when verifying the joint pk proof of party %d", i, id))
				continue
			}
			err := dkg.JointPkVerify(curve, jointPkProofs[id-2].Statement2, jointPkProofs[id-1], jointPkProofSessionIds[id-1])
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when verifying the joint pk proof of party %d", i, id))
		}

		// generate nonces and proofs
		var basePoint curves.Point
		for id := 1; id <= n; id++ {
			if id == 1 {
				basePoint = curve.NewGeneratorPoint()
			} else if id == 2 {
				basePoint = pkProofs[0].Statement
			} else {
				basePoint = jointPkProofs[id-2].Statement2
			}
			k, nonceProof, commitment, sessionId, err := ds.NonceComProve(curve, basePoint)
			require.NoError(t, err, fmt.Sprintf("faied in curve %d when party %d generating nonce", i, id))
			nonces[id-1] = k
			nonceProofs[id-1] = nonceProof
			nonceCommitments[id-1] = commitment
			nonceProofSessionIds[id-1] = sessionId
		}

		// de-com and verify nonce proofs
		for id := 1; id <= n; id++ {
			if id == 1 {
				basePoint = curve.NewGeneratorPoint()
			} else if id == 2 {
				basePoint = pkProofs[0].Statement
			} else {
				basePoint = jointPkProofs[id-2].Statement2
			}
			err := ds.NonceDeComVerify(curve, basePoint, nonceProofs[id-1], nonceCommitments[id-1], nonceProofSessionIds[id-1])
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when verify the de-commitment and nonce proof for party %d", i, id))
		}

		// compute r-part of signature (each party should do this)
		R := nonceProofs[0].Statement
		for id := 2; id <= n; id++ {
			R = R.Add(nonceProofs[id-1].Statement)
		}

		r := ds.RPartComp(curve, R, message)

		// compute s-part of signature
		s := r
		for id := 1; id <= n; id++ {
			RId := nonceProofs[0].Statement
			for j := 2; j <= id; j++ {
				RId = RId.Add(nonceProofs[j-1].Statement)
			}
			if id == 1 {
				s = ds.SPartComp(curve, r, s, sks[id-1], nonces[id-1], nil, RId, pkProofs[0].Statement)
			} else {
				s = ds.SPartComp(curve, r, s, sks[id-1], nonces[id-1], nil, RId, jointPkProofs[id-1].Statement2)
			}
		}
		/*******************************************
		BACK TO THE PURE VERIFICATION ALGORITHM TEST
		*******************************************/

		err := Verify(curve, nil, jointPkProofs[n-1].Statement2, message, r, s)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d when verify the signature", i))
	}
}
