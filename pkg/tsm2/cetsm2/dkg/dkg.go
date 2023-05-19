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

func PkComProve(curve *curves.Curve) (*schnorr.Proof, schnorr.Commitment, []byte, error) {
	sk := curve.Scalar.Random(rand.Reader)

	uniqueSessionId := [simplest.DigestSize]byte{}
	pkProver := schnorr.NewProver(curve, nil, uniqueSessionId[:])
	pkProof, commitment, err := pkProver.ProveCommit(sk)

	return pkProof, commitment, uniqueSessionId[:], err
}

// functions for step 2

func PkDeComVerify(curve *curves.Curve, proof *schnorr.Proof, commitment schnorr.Commitment, uniqueSessionId []byte) error {
	return schnorr.DecommitVerify(proof, commitment, curve, nil, uniqueSessionId)
}

// functions for step 3

// currentJointPk is stored in the Statement2 of jointPkProof

func JointPkCompProve(curve *curves.Curve, sk curves.Scalar, formerJointPk curves.Point) (*chaumpedersen.Proof, []byte, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	jointPkProver, err := chaumpedersen.NewProver(curve, nil, formerJointPk, uniqueSessionId[:])
	if err != nil {
		return nil, uniqueSessionId[:], err
	}

	jointPkProof, err := jointPkProver.Prove(sk)

	return jointPkProof, uniqueSessionId[:], err
}

func JointPkVerify(curve *curves.Curve, basePoint2 curves.Point, proof *chaumpedersen.Proof, uniqueSessionId []byte) error {
	return chaumpedersen.Verify(proof, curve, nil, basePoint2, uniqueSessionId)
}
