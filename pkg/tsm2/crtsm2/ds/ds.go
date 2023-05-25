package ds

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline"
	"github.com/coinbase/kryptology/pkg/zkp/reg"
	"github.com/coinbase/kryptology/pkg/zkp/rspdl"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// functions for phase 1

func NonceComProve(curve *curves.Curve) (curves.Scalar, *schnorr.Proof, schnorr.Commitment, schnorr.SessionId, error) {
	k := curve.Scalar.Random(rand.Reader)

	uniqueSessionId := [simplest.DigestSize]byte{}
	kProofSessionId := uniqueSessionId[:]
	kProver := schnorr.NewProver(curve, nil, kProofSessionId)
	kProof, kCommitment, err := kProver.ProveCommit(k)

	return k, kProof, kCommitment, kProofSessionId, err
}

func NonceDeComVerify(curve *curves.Curve, kProof *schnorr.Proof, kCommitment schnorr.Commitment, kProofSessionId schnorr.SessionId) error {
	return schnorr.DecommitVerify(kProof, kCommitment, curve, nil, kProofSessionId)
}

// functions for phase 2

func SRanCTGammaProve(curve *curves.Curve, T curves.Point, U curves.Point, V curves.Point, R curves.Point, k curves.Scalar) (*rspdl.Proof, rspdl.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	sRanProofSessionId := uniqueSessionId[:]
	sRanProver, err := rspdl.NewProver(curve, nil, T, U, V, R, sRanProofSessionId)
	if err != nil {
		return nil, nil, err
	}

	rk := curve.Scalar.Random(rand.Reader)
	sRanProof, err := sRanProver.Prove(k, rk)
	if err != nil {
		return nil, nil, err
	}

	return sRanProof, sRanProofSessionId, nil
}

func SRanCTGammaVerify(curve *curves.Curve, T curves.Point, sRanCTGammaProof *rspdl.Proof, U curves.Point, V curves.Point, R curves.Point, sRanCTGammaProofSessionId rspdl.SessionId) error {
	return rspdl.Verify(sRanCTGammaProof, curve, nil, T, U, V, R, sRanCTGammaProofSessionId)
}

// functions for phase 3

func MtASimu[A any, B any](curve *curves.Curve, gamma curves.Scalar, k curves.Scalar, sender sign_offline.MTASender[A, B], receiver sign_offline.MTAReceiver[A, B]) (curves.Scalar, curves.Scalar) {
	a := receiver.Init(k)
	mu, b := sender.Update(gamma, a)
	nu := receiver.Multiply(b)

	return mu, nu
}

func DeltaEGProve(curve *curves.Curve, T curves.Point, delta curves.Scalar) (*reg.Proof, reg.SessionId, error) {
	uniqueSessionId := [simplest.DigestSize]byte{}
	deltaEGProofSessionId := uniqueSessionId[:]
	deltaEGProver, err := reg.NewProver(curve, nil, T, deltaEGProofSessionId)
	if err != nil {
		return nil, nil, err
	}

	r_delta := curve.Scalar.Random(rand.Reader)
	deltaEGProof, err := deltaEGProver.Prove(delta, r_delta)
	if err != nil {
		return nil, nil, err
	}
	return deltaEGProof, deltaEGProofSessionId, nil
}

func DeltaEGVerify(curve *curves.Curve, T curves.Point, deltaEGProof *reg.Proof, deltaEGProofSessionId reg.SessionId) error {
	return reg.Verify(deltaEGProof, curve, nil, T, deltaEGProofSessionId)
}
