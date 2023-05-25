package ds

import (
	"crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

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
