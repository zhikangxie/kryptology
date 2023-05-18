package dkg

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

type Party struct {
	n  int
	id int

	curve     *curves.Curve
	basePoint curves.Point

	sk       curves.Scalar
	pk       curves.Point
	pkProver *schnorr.Prover
	pkProof  *schnorr.Proof

	pkJointMidProver *chaumpedersen.Prover

	pkJoint curves.Point

	peerCommitment       []schnorr.Commitment
	peerPk               []curves.Point
	peerPkProof          []*schnorr.Proof
	peerPkProofSessionId [][]byte

	pkJointMid               []curves.Point
	pkJointMidProof          []*chaumpedersen.Proof
	pkJointMidProofSessionId [][]byte
}

func NewParty(n int, id int, curve *curves.Curve, basePoint curves.Point) *Party {
	return &Party{
		n:         n,
		id:        id,
		curve:     curve,
		basePoint: basePoint,
	}
}

// functions for step 1

func (party *Party) KeyGen() {
	party.sk = party.curve.Scalar.Random(rand.Reader)
	party.pk = party.curve.ScalarBaseMult(party.sk)
}

func (party *Party) PkComProve() (schnorr.Commitment, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	party.pkProver = schnorr.NewProver(party.curve, party.basePoint, uniqueSessionId[:])
	dlProof, commitment, err := party.pkProver.ProveCommit(party.sk)
	if err != nil {
		return nil, err
	}
	party.pkProof = dlProof

	return commitment, nil
}

// functions for step 2

func (party *Party) PeerComReceive(commitment schnorr.Commitment, peerNum int) {
	party.peerCommitment[peerNum-1] = commitment
}

func (party *Party) PeerDeComReceive(pk curves.Point, proof *schnorr.Proof, uniqueSessionId []byte, peerNum int) {
	party.peerPk[peerNum-1] = pk
	party.peerPkProof[peerNum-1] = proof
	party.peerPkProofSessionId[peerNum-1] = uniqueSessionId
}

func (party *Party) PeerPksVerify() error {
	var err error
	for i := 0; i <= party.n-1; i++ {
		err = schnorr.DecommitVerify(party.peerPkProof[i], party.peerCommitment[i], party.curve, party.basePoint, party.peerPkProofSessionId[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// functions for step 3

func (party *Party) PkJointMidComp() {

}
