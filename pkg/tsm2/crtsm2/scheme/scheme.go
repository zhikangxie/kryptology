package scheme

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/reg"
	"github.com/coinbase/kryptology/pkg/zkp/rspdl"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const num = 10

type Scheme struct {
	curve *curves.Curve

	n int

	message []byte

	xs               [num]curves.Scalar
	QProofs          [num]*schnorr.Proof
	QCommitments     [num]schnorr.Commitment
	QProofSessionIds [num]schnorr.SessionId
	Q                curves.Point

	ds               [num]curves.Scalar
	TProofs          [num]*schnorr.Proof
	TCommitments     [num]schnorr.Commitment
	TProofSessionIds [num]schnorr.Commitment
	T                curves.Point

	gammas               [num]curves.Scalar
	xGammas              [num]curves.Scalar
	regProofs            [num]*reg.Proof
	regProofSessionIds   [num]reg.SessionId
	UGamma               curves.Point
	VGamma               curves.Point
	rspdlproofs          [num]*rspdl.Proof
	rspdlProofSessionIds [num]rspdl.SessionId
	UXGamma              curves.Point
	VXGamma              curves.Point
}

func NewScheme(curve *curves.Curve) *Scheme {
	return &Scheme{
		curve: curve,
		n:     num,
	}
}

func (scheme *Scheme) DKGPhase1() error {
	// generate pks for SM2 and proofs
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

	// generate pks for ElGamal and proofs
	for id := 1; id <= scheme.n; id++ {
		d, TProof, TCommitment, TProofSessionId, err := dkg.PkComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.ds[id-1] = d
		scheme.TProofs[id-1] = TProof
		scheme.TCommitments[id-1] = TCommitment
		scheme.TProofSessionIds[id-1] = TProofSessionId
	}

	// de-com and verify T proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.PkDeComVerify(scheme.curve, scheme.TProofs[id-1], scheme.TCommitments[id-1], scheme.TProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute T
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.T = scheme.TProofs[0].Statement
		for id := 2; id <= scheme.n; id++ {
			scheme.T = scheme.T.Add(scheme.TProofs[id-1].Statement)
		}
	}

	return nil
}

func (scheme *Scheme) DKGPhase2() error {
	// encrypt gamma
	for id := 1; id <= scheme.n; id++ {
		gamma, regProof, regProofSessionId, err := dkg.REGProve(scheme.curve, scheme.T)
		if err != nil {
			return err
		}
		scheme.gammas[id-1] = gamma
		scheme.regProofs[id-1] = regProof
		scheme.regProofSessionIds[id-1] = regProofSessionId
	}

	// verify proofs of encryption of gammas
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.REGVerify(scheme.curve, scheme.T, scheme.regProofs[id-1], scheme.regProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute the encryption of gamma=sum(gammas)
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.UGamma = scheme.regProofs[0].A
		scheme.VGamma = scheme.regProofs[0].B
		for id := 2; id <= scheme.n; id++ {
			scheme.UGamma = scheme.UGamma.Add(scheme.regProofs[id-1].A)
			scheme.VGamma = scheme.VGamma.Add(scheme.regProofs[id-1].B)
		}
	}

	// compute sp-dl relations and proofs
	for id := 1; id <= scheme.n; id++ {
		rspdlProof, rspdlProofSessionId, err := dkg.RSPDLProve(scheme.curve, scheme.UGamma, scheme.VGamma, scheme.QProofs[id-1].Statement, scheme.xs[id-1])
		if err != nil {
			return err
		}
		scheme.rspdlproofs[id-1] = rspdlProof
		scheme.rspdlProofSessionIds[id-1] = rspdlProofSessionId
	}

	// verify proofs of sp-dl relations
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.RSPDLVerify(scheme.curve, scheme.rspdlproofs[id-1], scheme.UGamma, scheme.VGamma, scheme.QProofs[id-1].Statement, scheme.rspdlProofSessionIds[id-1])
			if err != nil {
				return err
			}
		}
	}

	// compute the encryption of xGamma=sum(xGammas)
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.UXGamma = scheme.rspdlproofs[0].APrime
		scheme.VXGamma = scheme.rspdlproofs[0].BPrime
		for id := 2; id <= scheme.n; id++ {
			scheme.UXGamma = scheme.UXGamma.Add(scheme.rspdlproofs[id-1].APrime)
			scheme.VXGamma = scheme.VXGamma.Add(scheme.rspdlproofs[id-1].BPrime)
		}
	}

	return nil
}
