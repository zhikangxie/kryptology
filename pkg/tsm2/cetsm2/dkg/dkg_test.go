package dkg

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDKGOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}

	const n = 50

	var sks [n]curves.Scalar
	var pkProofs [n]*schnorr.Proof
	var commitments [n]schnorr.Commitment
	var pkProofSessionIds [n]*[]byte

	var jointPkProofs [n]*chaumpedersen.Proof
	var jointPkProofSessionIds [n]*[]byte

	for i, curve := range curveInstances {
		// generate pks and proofs
		for id := 1; id <= n; id++ {
			sk, pkProof, commitment, sessionId, err := PkComProve(curve)
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when generating pk with comproof for party %d", i, id))
			sks[id-1] = sk
			pkProofs[id-1] = pkProof
			commitments[id-1] = commitment
			pkProofSessionIds[id-1] = sessionId
		}

		// de-com and verify pk proofs
		for id := 1; id <= n; id++ {
			err := PkDeComVerify(curve, pkProofs[id-1], commitments[id-1], pkProofSessionIds[id-1])
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when verify the de-commitment and pk proof for party %d", i, id))
		}

		// generate (mid-)joint pks
		for id := 2; id <= n; id++ {
			if id == 2 {
				jointPkProof, sessionId, err := JointPkCompProve(curve, sks[id-1], pkProofs[id-2].Statement)
				require.NoError(t, err, fmt.Sprintf("failed in curve %d when party %d computing joint pk with proof", i, id))
				jointPkProofs[id-1] = jointPkProof
				jointPkProofSessionIds[id-1] = sessionId
				continue
			}
			jointPkProof, sessionId, err := JointPkCompProve(curve, sks[id-1], jointPkProofs[id-2].Statement2)
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when party %d computing joint pk with proof", i, id))
			jointPkProofs[id-1] = jointPkProof
			jointPkProofSessionIds[id-1] = sessionId
		}

		// verify joint pk proofs
		for id := 2; id <= n; id++ {
			if id == 2 {
				err := JointPkVerify(curve, pkProofs[id-2].Statement, jointPkProofs[id-1], jointPkProofSessionIds[id-1])
				require.NoError(t, err, fmt.Sprintf("failed in curve %d when verifying the joint pk proof of party %d", i, id))
				continue
			}
			err := JointPkVerify(curve, jointPkProofs[id-2].Statement2, jointPkProofs[id-1], jointPkProofSessionIds[id-1])
			require.NoError(t, err, fmt.Sprintf("failed in curve %d when verifying the joint pk proof of party %d", i, id))
		}
	}
}

func BenchmarkDKG(b *testing.B) {
	curve := curves.K256()

	const n = 10

	var sks [n]curves.Scalar
	var pkProofs [n]*schnorr.Proof
	var commitments [n]schnorr.Commitment
	var pkProofSessionIds [n]*[]byte

	var jointPkProofs [n]*chaumpedersen.Proof
	var jointPkProofSessionIds [n]*[]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// generate pks and proofs
		for id := 1; id <= n; id++ {
			sk, pkProof, commitment, sessionId, err := PkComProve(curve)
			require.NoError(b, err, fmt.Sprintf("generating pk with comproof for party %d", id))
			sks[id-1] = sk
			pkProofs[id-1] = pkProof
			commitments[id-1] = commitment
			pkProofSessionIds[id-1] = sessionId
		}

		// de-com and verify pk proofs
		/****************************************
		EACH PARTY WILL DO THIS SIMILAR PROCEDURE
		****************************************/
		for numParty := 1; numParty <= n; numParty++ {
			for id := 1; id <= n; id++ {
				err := PkDeComVerify(curve, pkProofs[id-1], commitments[id-1], pkProofSessionIds[id-1])
				require.NoError(b, err, fmt.Sprintf("verifying the de-commitment and pk proof for party %d", id))
			}
		}

		// generate (mid-)joint pks
		for id := 2; id <= n; id++ {
			if id == 2 {
				jointPkProof, sessionId, err := JointPkCompProve(curve, sks[id-1], pkProofs[id-2].Statement)
				require.NoError(b, err, fmt.Sprintf("party %d computing joint pk with proof", id))
				jointPkProofs[id-1] = jointPkProof
				jointPkProofSessionIds[id-1] = sessionId
				continue
			}
			jointPkProof, sessionId, err := JointPkCompProve(curve, sks[id-1], jointPkProofs[id-2].Statement2)
			require.NoError(b, err, fmt.Sprintf("party %d computing joint pk with proof", id))
			jointPkProofs[id-1] = jointPkProof
			jointPkProofSessionIds[id-1] = sessionId
		}

		// verify joint pk proofs
		/****************************************
		EACH PARTY WILL DO THIS SIMILAR PROCEDURE
		****************************************/
		for numParty := 1; numParty <= n; numParty++ {
			for id := 2; id <= n; id++ {
				if id == 2 {
					err := JointPkVerify(curve, pkProofs[id-2].Statement, jointPkProofs[id-1], jointPkProofSessionIds[id-1])
					require.NoError(b, err, fmt.Sprintf("verifying the joint pk proof of party %d", id))
					continue
				}
				err := JointPkVerify(curve, jointPkProofs[id-2].Statement2, jointPkProofs[id-1], jointPkProofSessionIds[id-1])
				require.NoError(b, err, fmt.Sprintf("verifying the joint pk proof of party %d", id))
			}
		}
	}

}
