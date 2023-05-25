package dkg

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/reg"
	"github.com/coinbase/kryptology/pkg/zkp/rre"
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

func RSPDLProve(curve *curves.Curve, T curves.Point, U curves.Point, V curves.Point, X curves.Point, x curves.Scalar) (*rspdl.Proof, rspdl.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	rspdlProofSessionId := uniqueSessionId[:]
	rspdlProver, err := rspdl.NewProver(curve, nil, T, U, V, X, rspdlProofSessionId)
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

func RSPDLVerify(curve *curves.Curve, T curves.Point, rspdlProof *rspdl.Proof, U curves.Point, V curves.Point, X curves.Point, rspdlProofSessionId rspdl.SessionId) error {
	return rspdl.Verify(rspdlProof, curve, nil, T, U, V, X, rspdlProofSessionId)
}

// functions for phase 3

func MtASimu[A any, B any](curve *curves.Curve, gamma curves.Scalar, x curves.Scalar, sender sign_offline.MTASender[A, B], receiver sign_offline.MTAReceiver[A, B]) (curves.Scalar, curves.Scalar) {
	a := receiver.Init(x)
	alpha, b := sender.Update(gamma, a)
	beta := receiver.Multiply(b)

	return alpha, beta
}

func SigmaREGProve(curve *curves.Curve, T curves.Point, sigma curves.Scalar) (curves.Scalar, *reg.Proof, reg.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	sigmaRegProofSessionId := uniqueSessionId[:]
	sigmaRegProver, err := reg.NewProver(curve, nil, T, sigmaRegProofSessionId)
	if err != nil {
		return nil, nil, nil, err
	}

	rsigma := curve.Scalar.Random(rand.Reader)
	sigmaRegProof, err := sigmaRegProver.Prove(sigma, rsigma)
	if err != nil {
		return nil, nil, nil, err
	}
	return rsigma, sigmaRegProof, sigmaRegProofSessionId, nil
}

func SigmaREGVerify(curve *curves.Curve, T curves.Point, sigmaRegProof *reg.Proof, sigmaRegProofSessionId reg.SessionId) error {
	return reg.Verify(sigmaRegProof, curve, nil, T, sigmaRegProofSessionId)
}

// functions for phase 4

func RREComProve(curve *curves.Curve, T curves.Point, U curves.Point, V curves.Point) (*rre.Proof, rre.Commitment, rre.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	rreProofSessionId := uniqueSessionId[:]
	rreProver, err := rre.NewProver(curve, nil, T, U, V, rreProofSessionId)
	if err != nil {
		return nil, nil, nil, err
	}

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)
	rreProof, rreCommitment, err := rreProver.ComProve(alpha, beta)
	if err != nil {
		return nil, nil, nil, err
	}

	return rreProof, rreCommitment, rreProofSessionId, nil
}

func RREDeComVerify(curve *curves.Curve, rreProof *rre.Proof, rreCommitment rre.Commitment, rreProofSessionId rre.SessionId, T curves.Point, U curves.Point, V curves.Point) error {
	return rre.DeComVerify(rreProof, rreCommitment, curve, nil, T, U, V, rreProofSessionId)
}

func DDHComProve(curve *curves.Curve, P curves.Point, UPrime curves.Point, Ti curves.Point, UiPrime curves.Point, di curves.Scalar) (*chaumpedersen.Proof, chaumpedersen.Commitment, chaumpedersen.SessionId, error) {
	if P == nil {
		P = curve.NewGeneratorPoint()
	}
	uniqueSessionId := [simplest.DigestSize]byte{}
	ddhProofSessionId := uniqueSessionId[:]
	ddhProver, err := chaumpedersen.NewProver(curve, P, UPrime, ddhProofSessionId)
	if err != nil {
		return nil, nil, nil, err
	}

	ddhProof, ddhCommitment, err := ddhProver.ComProveWithStatement(Ti, UiPrime, di)
	if err != nil {
		return nil, nil, nil, err
	}

	return ddhProof, ddhCommitment, ddhProofSessionId, nil
}

func DDHDeComVerify(curve *curves.Curve, ddhProof *chaumpedersen.Proof, ddhCommitment chaumpedersen.Commitment, ddhProofSessionId chaumpedersen.SessionId, P curves.Point, UPrime curves.Point) error {
	if P == nil {
		P = curve.NewGeneratorPoint()
	}
	return chaumpedersen.DeComVerify(ddhProof, ddhCommitment, curve, P, UPrime, ddhProofSessionId)
}

func SigmaDDHProve(curve *curves.Curve, P curves.Point, T curves.Point, USigma curves.Point, VSigmaPrime curves.Point, rSigma curves.Scalar) (*chaumpedersen.Proof, chaumpedersen.SessionId, error) {
	if P == nil {
		P = curve.NewGeneratorPoint()
	}
	uniqueSessionId := [simplest.DigestSize]byte{}
	ddhProofSessionId := uniqueSessionId[:]
	ddhProver, err := chaumpedersen.NewProver(curve, P, T, ddhProofSessionId)
	if err != nil {
		return nil, nil, err
	}

	ddhProof, err := ddhProver.ProveWithStatement(USigma, VSigmaPrime, rSigma)
	if err != nil {
		return nil, nil, err
	}

	return ddhProof, ddhProofSessionId, nil
}

func SigmaDDHVerify(curve *curves.Curve, ddhProof *chaumpedersen.Proof, ddhProofSessionId chaumpedersen.SessionId, P curves.Point, T curves.Point) error {
	if P == nil {
		P = curve.NewGeneratorPoint()
	}
	return chaumpedersen.Verify(ddhProof, curve, P, T, ddhProofSessionId)
}
