package tschnorr

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/dkg"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/verify"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const num = 50

type Scheme struct {
	curve *curves.Curve
	P     curves.Point

	n int

	message []byte

	xs               [num]curves.Scalar
	QProofs          [num]*schnorr.Proof
	QCommitments     [num]schnorr.Commitment
	QProofSessionIds [num]schnorr.SessionId
	Q                curves.Point

	ks               [num]curves.Scalar
	RProofs          [num]*schnorr.Proof
	RCommitments     [num]schnorr.Commitment
	RProofSessionIds [num]schnorr.SessionId
	R                curves.Point

	ss [num]curves.Scalar

	s curves.Scalar

	e curves.Scalar
}

func NewScheme(curve *curves.Curve) *Scheme {
	return &Scheme{
		curve: curve,
		n:     num,
		P:     curve.NewGeneratorPoint(),
	}
}

func (scheme *Scheme) DKG() error {
	// generate pks for T-Schnorr and proofs
	for id := 1; id <= scheme.n; id++ {
		x, QProof, QCommitment, QProofSessionId, err := dkg.PkComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.xs[id-1] = x
		scheme.QProofs[id-1] = QProof
		scheme.QCommitments[id-1] = QCommitment
		scheme.QProofSessionIds[id-1] = QProofSessionId
	}

	// de-com and verify Q proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			err := dkg.PkDeComVerify(scheme.curve, scheme.QProofs[id-1], scheme.QCommitments[id-1], scheme.QProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute Q
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.Q = scheme.QProofs[0].Statement
		for id := 2; id <= scheme.n; id++ {
			scheme.Q = scheme.Q.Add(scheme.QProofs[id-1].Statement)
		}
	}

	return nil
}

func (scheme *Scheme) DS() error {
	// generate Rs and proofs
	for id := 1; id <= scheme.n; id++ {
		k, RProof, RCommitment, RProofSessionId, err := dkg.PkComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.ks[id-1] = k
		scheme.RProofs[id-1] = RProof
		scheme.RCommitments[id-1] = RCommitment
		scheme.RProofSessionIds[id-1] = RProofSessionId
	}

	// de-com and verify R proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			err := dkg.PkDeComVerify(scheme.curve, scheme.RProofs[id-1], scheme.RCommitments[id-1], scheme.RProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute R
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.R = scheme.RProofs[0].Statement
		for id := 2; id <= scheme.n; id++ {
			scheme.R = scheme.R.Add(scheme.RProofs[id-1].Statement)
		}
	}

	// compute e and si
	for id := 1; id <= scheme.n; id++ {
		scheme.e = scheme.curve.Scalar.Hash(append(append(scheme.R.ToAffineCompressed(), scheme.Q.ToAffineCompressed()...), scheme.message...))
		scheme.ss[id-1] = scheme.ks[id-1].Sub(scheme.xs[id-1].Mul(scheme.e))
	}

	// compute s and verify the signature
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.s = scheme.ss[0]
		for id := 2; id <= scheme.n; id++ {
			scheme.s = scheme.s.Add(scheme.ss[id-1])
		}
		err := verify.SchnorrVerify(scheme.curve, nil, scheme.Q, scheme.message, scheme.e, scheme.s)
		if err != nil {
			return err
		}
	}

	return nil
}
