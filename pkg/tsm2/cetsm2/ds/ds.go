package ds

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
	"math/big"
)

// functions for step 1
// R_i is stored in nonceProof.Statement

func NonceComProve(curve *curves.Curve, basePoint curves.Point) (curves.Scalar, *schnorr.Proof, schnorr.Commitment, []byte, error) {
	k := curve.Scalar.Random(rand.Reader)

	uniqueSessionId := [simplest.DigestSize]byte{}
	sessionId := uniqueSessionId[:]
	nonceProver := schnorr.NewProver(curve, basePoint, sessionId)
	nonceProof, commitment, err := nonceProver.ProveCommit(k)

	return k, nonceProof, commitment, sessionId, err
}

// functions for step 2

func NonceDeComVerify(curve *curves.Curve, basePoint curves.Point, proof *schnorr.Proof, commitment schnorr.Commitment, sessionId []byte) error {
	return schnorr.DecommitVerify(proof, commitment, curve, basePoint, sessionId)
}

func RPartComp(curve *curves.Curve, R curves.Point, message []byte) curves.Scalar {
	h := curve.Scalar.Hash(message)

	RAffine := R.ToAffineCompressed()
	rx, err := curve.Scalar.SetBigInt(new(big.Int).SetBytes(RAffine[1 : 1+(len(RAffine)>>1)]))
	if err != nil {
		panic("when computing x-coordinate of R")
	}

	return h.Add(rx)
}

// functions for step 3

func SPartComp(curve *curves.Curve, r curves.Scalar, formerS curves.Scalar, sk curves.Scalar, k curves.Scalar,
	basePoint curves.Point, currentR curves.Point, currentJointPk curves.Point) curves.Scalar {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}

	skInvert, err := sk.Invert()
	if err != nil {
		panic("when computing the invert of sk")
	}

	currentS := skInvert.Mul(formerS.Add(k))

	if !currentJointPk.Mul(currentS).Equal(basePoint.Mul(r).Add(currentR)) {
		panic("failed when computing the s part of the signature")
	}

	return currentS
}
