package dkg

import (
	"crypto/rand"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

type Alice struct {
	prover *schnorr.Prover
	proof *schnorr.Proof
	curve *curves.Curve
	sk curves.Scalar
	pk curves.Point
	pkPeer curves.Point
	pkJoint curves.Point
}

type Bob struct {
	prover *schnorr.Prover
	curve *curves.Curve
	sk curves.Scalar
	pk curves.Point
	pkPeer curves.Point
	pkJoint curves.Point
	aliceCommitment schnorr.Commitment
}

type Output struct {
	sk      curves.Scalar
	pk      curves.Point
	pkPeer  curves.Point
	pkJoint curves.Point
}

func NewAlice(curve *curves.Curve) *Alice {
	sk := curve.Scalar.Random(rand.Reader)
	return &Alice{
		sk:         sk,
		pk:         curve.ScalarBaseMult(sk),
		curve:      curve,
	}
}

func NewBob(curve *curves.Curve) *Bob {
	sk := curve.Scalar.Random(rand.Reader)
	return &Bob{
		sk:         sk,
		pk:         curve.ScalarBaseMult(sk),
		curve:      curve,
	}
}

func (alice *Alice) Step1() (schnorr.Commitment, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	alice.prover = schnorr.NewProver(alice.curve, nil, uniqueSessionId[:])
	proof, commitment, err := alice.prover.ProveCommit(alice.sk)
	if err != nil {
		return nil, err
	}
	alice.proof = proof
	return commitment, nil
}

func (bob *Bob) Step2(commitment schnorr.Commitment) (*schnorr.Proof, error) {
	bob.aliceCommitment = commitment

	uniqueSessionId := [simplest.DigestSize]byte{}

	bob.prover = schnorr.NewProver(bob.curve, nil, uniqueSessionId[:])
	proof, err := bob.prover.Prove(bob.sk)
	if err != nil {
		return nil, err
	}
	return proof, err
}

func (alice *Alice) Step3(proof *schnorr.Proof) (*schnorr.Proof, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}

	err := schnorr.Verify(proof, alice.curve, nil, uniqueSessionId[:])
	if err != nil {
		return nil, err
	}
	alice.pkPeer = proof.Statement
	alice.pkJoint = alice.pkPeer.Add(alice.pk)
	return alice.proof, nil
}

func (bob *Bob) Step4(proof *schnorr.Proof) error {
	uniqueSessionId := [simplest.DigestSize]byte{}

	err := schnorr.DecommitVerify(proof, bob.aliceCommitment, bob.curve, nil, uniqueSessionId[:])
	if err != nil {
		return err
	}

	bob.pkPeer = proof.Statement
	bob.pkJoint = bob.pkPeer.Add(bob.pk)
	return nil
}

func (alice *Alice) Output() *Output {
	return &Output{
		pk:      alice.pk,
		sk:      alice.sk,
		pkJoint: alice.pkJoint,
		pkPeer:  alice.pkPeer,
	}
}

func (bob *Bob) Output() *Output {
	return &Output{
		pk:      bob.pk,
		sk:      bob.sk,
		pkJoint: bob.pkJoint,
		pkPeer:  bob.pkPeer,
	}
}
