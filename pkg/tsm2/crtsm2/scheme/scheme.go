package scheme

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const num = 10

type Scheme struct {
	curve *curves.Curve

	n int

	message []byte

	xs               [num]curves.Scalar
	QProofs          [num]*schnorr.Proof
	QCommitments     [num]schnorr.Commitment
	QProofSessionIds [num]schnorr.SessionId
	Q                curves.Point

	ds               [num]curves.Scalar
	TProofs          [num]*schnorr.Proof
	TCommitments     [num]schnorr.Commitment
	TProofSessionIds [num]schnorr.Commitment
	T                curves.Point
}

func (scheme *Scheme) DKGPhase1() error {
	// generate pks for SM2 and proofs
	for id := 1; id <= scheme.n; id++ {
		x, QProof, QCommitment, QProofSessionId, err := dkg.PkComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.xs[id-1] = x
		scheme.QProofs[id-1] = QProof
		scheme.QCommitments[id-1] = QCommitment
		scheme.QProofSessionIds[id-1] = QProofSessionId
	}

	// de-com and verify Q proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.PkDeComVerify(scheme.curve, scheme.QProofs[id-1], scheme.QCommitments[id-1], scheme.QProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute Q
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.Q = scheme.QProofs[0].Statement
		for id := 2; id <= scheme.n; id++ {
			scheme.Q = scheme.Q.Add(scheme.QProofs[id-1].Statement)
		}
	}

	// generate pks for ElGamal and proofs
	for id := 1; id <= scheme.n; id++ {
		d, TProof, TCommitment, TProofSessionId, err := dkg.PkComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.ds[id-1] = d
		scheme.TProofs[id-1] = TProof
		scheme.TCommitments[id-1] = TCommitment
		scheme.TProofSessionIds[id-1] = TProofSessionId
	}

	// de-com and verify T proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.PkDeComVerify(scheme.curve, scheme.TProofs[id-1], scheme.TCommitments[id-1], scheme.TProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute T
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.T = scheme.TProofs[0].Statement
		for id := 2; id <= scheme.n; id++ {
			scheme.T = scheme.T.Add(scheme.TProofs[id-1].Statement)
		}
	}

	return nil
}
