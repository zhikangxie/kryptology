package dkg

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/reg"
	"github.com/coinbase/kryptology/pkg/zkp/rspdl"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// functions for phase 1

// pk is stored in the Statement of pkProof

func PkComProve(curve *curves.Curve) (curves.Scalar, *schnorr.Proof, schnorr.Commitment, schnorr.SessionId, error) {
	sk := curve.Scalar.Random(rand.Reader)

	uniqueSessionId := [simplest.DigestSize]byte{}
	pkProofSessionId := uniqueSessionId[:]
	pkProver := schnorr.NewProver(curve, nil, pkProofSessionId)
	pkProof, pkCommitment, err := pkProver.ProveCommit(sk)

	return sk, pkProof, pkCommitment, pkProofSessionId, err
}

func PkDeComVerify(curve *curves.Curve, pkProof *schnorr.Proof, pkCommitment schnorr.Commitment, pkProofSessionId []byte) error {
	return schnorr.DecommitVerify(pkProof, pkCommitment, curve, nil, pkProofSessionId)
}

// functions for phase 2

func REGProve(curve *curves.Curve, T curves.Point) (curves.Scalar, *reg.Proof, reg.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	regProofSessionId := uniqueSessionId[:]
	regProver, err := reg.NewProver(curve, nil, T, regProofSessionId)
	if err != nil {
		return nil, nil, nil, err
	}
	gamma := curve.Scalar.Random(rand.Reader)
	rGamma := curve.Scalar.Random(rand.Reader)
	regProof, err := regProver.Prove(gamma, rGamma)
	if err != nil {
		return nil, nil, nil, err
	}
	return gamma, regProof, regProofSessionId, nil
}

func REGVerify(curve *curves.Curve, T curves.Point, regProof *reg.Proof, regProofSessionId reg.SessionId) error {
	return reg.Verify(regProof, curve, nil, T, regProofSessionId)
}

func RSPDLProve(curve *curves.Curve, U curves.Point, V curves.Point, x curves.Scalar) (*rspdl.Proof, rspdl.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	rspdlProofSessionId := uniqueSessionId[:]
	rspdlProver, err := rspdl.NewProver(curve, nil, U, V, rspdlProofSessionId)
	if err != nil {
		return nil, nil, err
	}
	rx := curve.Scalar.Random(rand.Reader)
	rspdlProof, err := rspdlProver.Prove(x, rx)
	if err != nil {
		return nil, nil, err
	}
	return rspdlProof, rspdlProofSessionId, nil
}

func RSPDLVerify(curve *curves.Curve, rspdlProof *rspdl.Proof, U curves.Point, V curves.Point, rspdlProofSessionId rspdl.SessionId) error {
	return rspdl.Verify(rspdlProof, curve, nil, U, V, rspdlProofSessionId)
}
