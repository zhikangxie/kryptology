package scheme

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/reg"
	"github.com/coinbase/kryptology/pkg/zkp/rre"
	"github.com/coinbase/kryptology/pkg/zkp/rspdl"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const num = 3

type MTAReceiver[A any, B any] interface {
	Init(curves.Scalar) A
	Multiply(B) curves.Scalar
}

type MTASender[A any, B any] interface {
	Update(curves.Scalar, A) (curves.Scalar, B)
}

type Scheme[A any, B any] struct {
	curve *curves.Curve
	P     curves.Point

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

	gammas                     [num]curves.Scalar
	xGammas                    [num]curves.Scalar
	gammaRegProofs             [num]*reg.Proof
	gammaRegProofSessionIds    [num]reg.SessionId
	UGamma                     curves.Point
	VGamma                     curves.Point
	xGammaRspdlProofs          [num]*rspdl.Proof
	xGammaRspdlProofSessionIds [num]rspdl.SessionId
	UXGamma                    curves.Point
	VXGamma                    curves.Point

	alphas       [num][num]curves.Scalar
	betas        [num][num]curves.Scalar
	mtaSenders   [num][num]sign_offline.MTASender[A, B]
	mtaReceivers [num][num]sign_offline.MTAReceiver[A, B]

	sigmas                  [num]curves.Scalar
	sigmaRegProofs          [num]*reg.Proof
	sigmaRegProofSessionIds [num]reg.SessionId
	USigma                  curves.Point
	VSigma                  curves.Point

	U curves.Point
	V curves.Point

	rreProofs          [num]*rre.Proof
	rreCommitments     [num]rre.Commitment
	rreProofSessionIds [num]rre.SessionId

	UPrime  curves.Point
	VPrime  curves.Point
	UPrimes [num]curves.Point

	ddhProofs          [num]*chaumpedersen.Proof
	ddhCommitments     [num]chaumpedersen.Commitment
	ddhProofSessionIds [num]chaumpedersen.SessionId
}

func NewScheme[A any, B any](curve *curves.Curve) *Scheme[A, B] {
	return &Scheme[A, B]{
		curve: curve,
		n:     num,
		P:     curve.NewGeneratorPoint(),
	}
}

func (scheme *Scheme[A, B]) DKGPhase1() error {
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

func (scheme *Scheme[A, B]) DKGPhase2() error {
	// encrypt gamma
	for id := 1; id <= scheme.n; id++ {
		gamma, regProof, regProofSessionId, err := dkg.REGProve(scheme.curve, scheme.T)
		if err != nil {
			return err
		}
		scheme.gammas[id-1] = gamma
		scheme.gammaRegProofs[id-1] = regProof
		scheme.gammaRegProofSessionIds[id-1] = regProofSessionId
	}

	// verify proofs of encryption of gammas
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.REGVerify(scheme.curve, scheme.T, scheme.gammaRegProofs[id-1], scheme.gammaRegProofSessionIds[id-1])
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
		scheme.UGamma = scheme.gammaRegProofs[0].A
		scheme.VGamma = scheme.gammaRegProofs[0].B
		for id := 2; id <= scheme.n; id++ {
			scheme.UGamma = scheme.UGamma.Add(scheme.gammaRegProofs[id-1].A)
			scheme.VGamma = scheme.VGamma.Add(scheme.gammaRegProofs[id-1].B)
		}
	}

	// compute sp-dl relations and proofs
	for id := 1; id <= scheme.n; id++ {
		rspdlProof, rspdlProofSessionId, err := dkg.RSPDLProve(scheme.curve, scheme.T, scheme.UGamma, scheme.VGamma, scheme.QProofs[id-1].Statement, scheme.xs[id-1])
		if err != nil {
			return err
		}
		scheme.xGammaRspdlProofs[id-1] = rspdlProof
		scheme.xGammaRspdlProofSessionIds[id-1] = rspdlProofSessionId
	}

	// verify proofs of sp-dl relations
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.RSPDLVerify(scheme.curve, scheme.T, scheme.xGammaRspdlProofs[id-1], scheme.UGamma, scheme.VGamma, scheme.QProofs[id-1].Statement, scheme.xGammaRspdlProofSessionIds[id-1])
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
		scheme.UXGamma = scheme.xGammaRspdlProofs[0].APrime
		scheme.VXGamma = scheme.xGammaRspdlProofs[0].BPrime
		for id := 2; id <= scheme.n; id++ {
			scheme.UXGamma = scheme.UXGamma.Add(scheme.xGammaRspdlProofs[id-1].APrime)
			scheme.VXGamma = scheme.VXGamma.Add(scheme.xGammaRspdlProofs[id-1].BPrime)
		}
	}

	return nil
}

func (scheme *Scheme[A, B]) DKGPhase3() error {
	// invoke MtA
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			alpha, beta := dkg.MtASimu(scheme.curve, scheme.gammas[i-1], scheme.xs[j-1], scheme.mtaSenders[i-1][j-1], scheme.mtaReceivers[i-1][j-1])
			scheme.alphas[i-1][j-1] = alpha
			scheme.betas[j-1][i-1] = beta
			if alpha.Add(beta).Cmp(scheme.gammas[i-1].Mul(scheme.xs[j-1])) != 0 {
				return fmt.Errorf("failed in MtA")
			}
		}
	}

	// compute sigma
	for i := 1; i <= scheme.n; i++ {
		sigma := scheme.gammas[i-1].Mul(scheme.xs[i-1])
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			sigma = sigma.Add(scheme.alphas[i-1][j-1]).Add(scheme.betas[i-1][j-1])
		}
		scheme.sigmas[i-1] = sigma
	}

	// encrypt sigma and generate proof
	for i := 1; i <= scheme.n; i++ {
		sigmaRegProof, sigmaRegProofSessionId, err := dkg.SigmaREGProve(scheme.curve, scheme.T, scheme.sigmas[i-1])
		if err != nil {
			return err
		}
		scheme.sigmaRegProofs[i-1] = sigmaRegProof
		scheme.sigmaRegProofSessionIds[i-1] = sigmaRegProofSessionId
	}

	// verify proof of sigma's encryption
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for i := 1; i <= scheme.n; i++ {
			err := dkg.SigmaREGVerify(scheme.curve, scheme.T, scheme.sigmaRegProofs[i-1], scheme.sigmaRegProofSessionIds[i-1])
			if err != nil {
				return err
			}
		}
	}

	// compute the encryption of sigma=sum(sigmas)
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.USigma = scheme.sigmaRegProofs[0].A
		scheme.VSigma = scheme.sigmaRegProofs[0].B
		for i := 2; i <= scheme.n; i++ {
			scheme.USigma = scheme.USigma.Add(scheme.sigmaRegProofs[i-1].A)
			scheme.VSigma = scheme.VSigma.Add(scheme.sigmaRegProofs[i-1].B)
		}
	}

	return nil
}

func (scheme *Scheme[A, B]) DKGPhase4() error {
	// compute U and V
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.U = scheme.UXGamma.Sub(scheme.USigma)
		scheme.V = scheme.VXGamma.Sub(scheme.VSigma)
	}

	// re-randomize, generate proof and commitment
	for id := 1; id <= scheme.n; id++ {
		rreProof, rreCommitment, rreProofSessionId, err := dkg.RREComProve(scheme.curve, scheme.T, scheme.U, scheme.V)
		if err != nil {
			return err
		}
		scheme.rreProofs[id-1] = rreProof
		scheme.rreCommitments[id-1] = rreCommitment
		scheme.rreProofSessionIds[id-1] = rreProofSessionId
	}

	// de-com, verify proof of re-randomization
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.RREDeComVerify(scheme.curve, scheme.rreProofs[id-1], scheme.rreCommitments[id-1], scheme.rreProofSessionIds[id-1], scheme.T, scheme.U, scheme.V)
			if err != nil {
				return err
			}
		}
	}

	// compute UPrime, VPrime
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.UPrime = scheme.rreProofs[0].APrime
		scheme.VPrime = scheme.rreProofs[0].BPrime
		for id := 2; id <= scheme.n; id++ {
			scheme.UPrime = scheme.UPrime.Add(scheme.rreProofs[id-1].APrime)
			scheme.VPrime = scheme.VPrime.Add(scheme.rreProofs[id-1].BPrime)
		}
	}

	// compute U'_i
	for id := 1; id <= scheme.n; id++ {
		scheme.UPrimes[id-1] = scheme.UPrime.Mul(scheme.ds[id-1])
	}

	// generate DDH proof and commitment
	for id := 1; id <= scheme.n; id++ {
		ddhProof, ddhCommitment, ddhProofSessionId, err := dkg.DDHComProve(scheme.curve, nil, scheme.UPrime, scheme.TProofs[id-1].Statement, scheme.UPrimes[id-1], scheme.ds[id-1])
		if err != nil {
			return err
		}
		scheme.ddhProofs[id-1] = ddhProof
		scheme.ddhCommitments[id-1] = ddhCommitment
		scheme.ddhProofSessionIds[id-1] = ddhProofSessionId
	}

	// de-com, verify proof of ddh
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			err := dkg.DDHDeComVerify(scheme.curve, scheme.ddhProofs[id-1], scheme.ddhCommitments[id-1], scheme.ddhProofSessionIds[id-1], nil, scheme.UPrime)
			if err != nil {
				return err
			}
		}
	}

	// compute sum of UiPrime and compare it with VPrime
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		sumUiPrime := scheme.UPrimes[0]
		for id := 2; id <= scheme.n; id++ {
			sumUiPrime = sumUiPrime.Add(scheme.UPrimes[id-1])
		}
		if !sumUiPrime.Equal(scheme.VPrime) {
			return fmt.Errorf("failed when verifying sum of U'_i")
		}
	}

	return nil
}
