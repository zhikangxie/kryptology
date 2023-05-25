package scheme

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tsm2/cetsm2/dkg"
	"github.com/coinbase/kryptology/pkg/tsm2/cetsm2/ds"
	"github.com/coinbase/kryptology/pkg/tsm2/cetsm2/verify"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const num = 50

type Scheme struct {
	curve *curves.Curve

	n int

	message []byte

	sks               [num]curves.Scalar
	pkProofs          [num]*schnorr.Proof
	pkCommitments     [num]schnorr.Commitment
	pkProofSessionIds [num]schnorr.SessionId

	jointPkProofs          [num]*chaumpedersen.Proof
	jointPkProofSessionIds [num]chaumpedersen.SessionId

	nonce                [num]curves.Scalar
	nonceProofs          [num]*schnorr.Proof
	nonceCommitments     [num]schnorr.Commitment
	nonceProofSessionIds [num]schnorr.SessionId
}

func NewScheme(curve *curves.Curve, n int, message []byte,
	sks [num]curves.Scalar, pkProofs [num]*schnorr.Proof, pkCommitments [num]schnorr.Commitment, pkProofSessionIds [num]schnorr.SessionId,
	jointPkProofs [num]*chaumpedersen.Proof, jointPkProofSessionIds [num]chaumpedersen.SessionId,
	nonce [num]curves.Scalar, nonceProofs [num]*schnorr.Proof, nonceCommitments [num]schnorr.Commitment, nonceProofSessionIds [num]schnorr.SessionId) *Scheme {
	return &Scheme{
		curve:                  curve,
		n:                      n,
		message:                message,
		sks:                    sks,
		pkProofs:               pkProofs,
		pkCommitments:          pkCommitments,
		pkProofSessionIds:      pkProofSessionIds,
		jointPkProofs:          jointPkProofs,
		jointPkProofSessionIds: jointPkProofSessionIds,
		nonce:                  nonce,
		nonceProofs:            nonceProofs,
		nonceCommitments:       nonceCommitments,
		nonceProofSessionIds:   nonceProofSessionIds,
	}
}

func (scheme *Scheme) DKGStep1() error {
	// generate pks and proofs
	for id := 1; id <= scheme.n; id++ {
		sk, pkProof, pkCommitment, pkProofSessionId, err := dkg.PkComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.sks[id-1] = sk
		scheme.pkProofs[id-1] = pkProof
		scheme.pkCommitments[id-1] = pkCommitment
		scheme.pkProofSessionIds[id-1] = pkProofSessionId
	}
	return nil
}

func (scheme *Scheme) DKGStep2() error {
	// de-com and verify pk proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			err := dkg.PkDeComVerify(scheme.curve, scheme.pkProofs[id-1], scheme.pkCommitments[id-1], scheme.pkProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (scheme *Scheme) DKGStep3A() error {
	// generate (mid-)joint pks
	for id := 2; id <= scheme.n; id++ {
		if id == 2 {
			jointPkProof, jointPkProofSessionId, err := dkg.JointPkCompProve(scheme.curve, scheme.sks[id-1], scheme.pkProofs[id-2].Statement)
			if err != nil {
				return err
			}
			scheme.jointPkProofs[id-1] = jointPkProof
			scheme.jointPkProofSessionIds[id-1] = jointPkProofSessionId
			continue
		}
		jointPkProof, jointPkProofSessionId, err := dkg.JointPkCompProve(scheme.curve, scheme.sks[id-1], scheme.jointPkProofs[id-2].Statement2)
		if err != nil {
			return err
		}
		scheme.jointPkProofs[id-1] = jointPkProof
		scheme.jointPkProofSessionIds[id-1] = jointPkProofSessionId
	}
	return nil
}

func (scheme *Scheme) DKGStep3B() error {
	// verify joint pk proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 2; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			if id == 2 {
				err := dkg.JointPkVerify(scheme.curve, scheme.pkProofs[id-2].Statement, scheme.jointPkProofs[id-1], scheme.jointPkProofSessionIds[id-1])
				if err != nil {
					return err
				}
				continue
			}
			err := dkg.JointPkVerify(scheme.curve, scheme.jointPkProofs[id-2].Statement2, scheme.jointPkProofs[id-1], scheme.jointPkProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (scheme *Scheme) DSStep1() error {
	// generate nonce and proofs
	var basePoint curves.Point
	for id := 1; id <= scheme.n; id++ {
		if id == 1 {
			basePoint = scheme.curve.NewGeneratorPoint()
		} else if id == 2 {
			basePoint = scheme.pkProofs[0].Statement
		} else {
			basePoint = scheme.jointPkProofs[id-2].Statement2
		}
		k, nonceProof, nonceCommitment, nonceSessionId, err := ds.NonceComProve(scheme.curve, basePoint)
		if err != nil {
			return err
		}
		scheme.nonce[id-1] = k
		scheme.nonceProofs[id-1] = nonceProof
		scheme.nonceCommitments[id-1] = nonceCommitment
		scheme.nonceProofSessionIds[id-1] = nonceSessionId
	}
	return nil
}

func (scheme *Scheme) DSStep2A() error {
	// de-com and verify nonce proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	var basePoint curves.Point
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			if id == 1 {
				basePoint = scheme.curve.NewGeneratorPoint()
			} else if id == 2 {
				basePoint = scheme.pkProofs[0].Statement
			} else {
				basePoint = scheme.jointPkProofs[id-2].Statement2
			}
			err := ds.NonceDeComVerify(scheme.curve, basePoint, scheme.nonceProofs[id-1], scheme.nonceCommitments[id-1], scheme.nonceProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (scheme *Scheme) DSStep2B() curves.Scalar {
	// compute r-part of signature
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	var r curves.Scalar
	for numParty := 1; numParty <= scheme.n; numParty++ {
		R := scheme.nonceProofs[0].Statement
		for id := 2; id <= scheme.n; id++ {
			R = R.Add(scheme.nonceProofs[id-1].Statement)
		}
		r = ds.RPartComp(scheme.curve, R, scheme.message)
	}
	return r
}

func (scheme *Scheme) DSStep3A(r curves.Scalar) curves.Scalar {
	// compute s-part of signature
	s := r
	for id := 1; id <= scheme.n; id++ {
		RId := scheme.nonceProofs[0].Statement
		for j := 2; j <= id; j++ {
			RId = RId.Add(scheme.nonceProofs[j-1].Statement)
		}
		if id == 1 {
			s = ds.SPartComp(scheme.curve, r, s, scheme.sks[id-1], scheme.nonce[id-1], nil, RId, scheme.pkProofs[0].Statement)
		} else {
			s = ds.SPartComp(scheme.curve, r, s, scheme.sks[id-1], scheme.nonce[id-1], nil, RId, scheme.jointPkProofs[id-1].Statement2)
		}
	}
	return s
}

func (scheme *Scheme) DSStep3B(r curves.Scalar, s curves.Scalar) error {
	// verify the final signature
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		err := verify.Verify(scheme.curve, nil, scheme.jointPkProofs[scheme.n-1].Statement2, scheme.message, r, s)
		if err != nil {
			return err
		}
	}
	return nil
}
