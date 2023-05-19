package dkg

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// functions for step 1

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
