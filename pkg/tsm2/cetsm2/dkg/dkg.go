package dkg

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// functions for step 1

// pk is stored in the Statement of pkProof

func PkComProve(curve *curves.Curve) (curves.Scalar, *schnorr.Proof, schnorr.Commitment, *[]byte, error) {
	sk := curve.Scalar.Random(rand.Reader)

	uniqueSessionId := [simplest.DigestSize]byte{}
	sessionId := uniqueSessionId[:]
	pkProver := schnorr.NewProver(curve, nil, sessionId)
	pkProof, commitment, err := pkProver.ProveCommit(sk)

	return sk, pkProof, commitment, &sessionId, err
}

// functions for step 2

func PkDeComVerify(curve *curves.Curve, proof *schnorr.Proof, commitment schnorr.Commitment, sessionId *[]byte) error {
	return schnorr.DecommitVerify(proof, commitment, curve, nil, *sessionId)
}

// functions for step 3

// currentJointPk is stored in the Statement2 of jointPkProof
// for the last party, currentJointPk is the calculated joint pk for all parties

func JointPkCompProve(curve *curves.Curve, sk curves.Scalar, formerJointPk curves.Point) (*chaumpedersen.Proof, *[]byte, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	sessionId := uniqueSessionId[:]
	jointPkProver, err := chaumpedersen.NewProver(curve, nil, formerJointPk, sessionId)
	if err != nil {
		return nil, &sessionId, err
	}

	jointPkProof, err := jointPkProver.Prove(sk)

	return jointPkProof, &sessionId, err
}

func JointPkVerify(curve *curves.Curve, formerJointPk curves.Point, proof *chaumpedersen.Proof, sessionId *[]byte) error {
	return chaumpedersen.Verify(proof, curve, nil, formerJointPk, *sessionId)
}
