package dkg

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

type Party struct {
	prover *schnorr.Prover
	proof  *schnorr.Proof
	curve  *curves.Curve
	sk     curves.Scalar
	pk     curves.Point
}

func NewParty(curve *curves.Curve) *Party {
	return &Party{
		curve: curve,
	}
}

func (party *Party) ComProve() (schnorr.Commitment, error) {
	party.sk = party.curve.Scalar.Random(rand.Reader)
	party.pk = party.curve.ScalarBaseMult(party.sk)

	proof, commitment, err := party.prover.ProveCommit(party.sk)
	if err != nil {
		return nil, err
	}
	party.proof = proof

	return commitment, nil
}
