package lnr18

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/sign_offline"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/dkg"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/ds"
	"github.com/coinbase/kryptology/pkg/tsm2/crtsm2/verify"
	"github.com/coinbase/kryptology/pkg/zkp/chaumpedersen"
	"github.com/coinbase/kryptology/pkg/zkp/reg"
	"github.com/coinbase/kryptology/pkg/zkp/rre"
	"github.com/coinbase/kryptology/pkg/zkp/rspdl"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
	"math/big"
)

const num = 5

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

	alphas      [num][num]curves.Scalar
	betas       [num][num]curves.Scalar
	mtaSender   sign_offline.MTASender[A, B]
	mtaReceiver sign_offline.MTAReceiver[A, B]

	sigmas                  [num]curves.Scalar
	rDeltas                 [num]curves.Scalar
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

	BDeltaPrimes            [num]curves.Point
	deltaDDHProofs          [num]*chaumpedersen.Proof
	deltaDDHProofSessionIds [num]chaumpedersen.SessionId

	delta curves.Scalar

	/*
		structures for signing
	*/

	ks               [num]curves.Scalar
	kProofs          [num]*schnorr.Proof
	kCommitments     [num]schnorr.Commitment
	kProofSessionIds [num]schnorr.Commitment

	R curves.Point

	sRanCTGammaProofs          [num]*rspdl.Proof
	sRanCTGammaProofSessionIds [num]rspdl.SessionId
	AKGamma                    curves.Point
	BKGamma                    curves.Point

	mus    [num][num]curves.Scalar
	nus    [num][num]curves.Scalar
	deltas [num]curves.Scalar

	deltaEGProofs          [num]*reg.Proof
	deltaEGProofSessionIds [num]reg.SessionId

	ADelta curves.Point
	BDelta curves.Point

	A curves.Point
	B curves.Point

	abREProofs          [num]*rre.Proof
	abRECommitments     [num]rre.Commitment
	abREProofSessionIds [num]rre.SessionId

	abDDHProofs          [num]*chaumpedersen.Proof
	abDDHCommitments     [num]chaumpedersen.Commitment
	abDDHProofSessionIds [num]chaumpedersen.SessionId

	APrime curves.Point
	BPrime curves.Point

	APrimes [num]curves.Point

	r  curves.Scalar
	ss [num]curves.Scalar
	s  curves.Scalar
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
			if id == numParty {
				continue
			}
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

func (scheme *Scheme[A, B]) DSPhase1() error {
	// generate k_i, compute R_i and proof
	for i := 1; i <= scheme.n; i++ {
		ki, kiProof, kiCommitment, kiProofSessionId, err := ds.NonceComProve(scheme.curve)
		if err != nil {
			return err
		}
		scheme.ks[i-1] = ki
		scheme.kProofs[i-1] = kiProof
		scheme.kCommitments[i-1] = kiCommitment
		scheme.kProofSessionIds[i-1] = kiProofSessionId
	}

	// verify proof of k_i
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		for i := 1; i <= scheme.n; i++ {
			if i == party {
				continue
			}
			err := ds.NonceDeComVerify(scheme.curve, scheme.kProofs[i-1], scheme.kCommitments[i-1], scheme.kProofSessionIds[i-1])
			if err != nil {
				return err
			}
		}
	}

	// compute R and rx
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		var err error
		scheme.R = scheme.kProofs[0].Statement
		for i := 2; i <= scheme.n; i++ {
			scheme.R = scheme.R.Add(scheme.kProofs[i-1].Statement)
		}
		RAffine := scheme.R.ToAffineCompressed()
		scheme.r, err = scheme.curve.Scalar.SetBigInt(new(big.Int).SetBytes(RAffine[1 : 1+(len(RAffine)>>1)]))
		if err != nil {
			return fmt.Errorf("failed when computing x-coordinate of R")
		}
	}

	return nil
}

func (scheme *Scheme[A, B]) DSPhase2() error {
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
			if id == numParty {
				continue
			}
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
			if id == numParty {
				continue
			}
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

func (scheme *Scheme[A, B]) DSPhase3() error {
	// invoke MtA
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			a := scheme.mtaReceiver.Init(scheme.xs[j-1])
			alpha, b := scheme.mtaSender.Update(scheme.gammas[i-1], a)
			beta := scheme.mtaReceiver.Multiply(b)
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
		sigmaRegProof, sigmaRegProofSessionId, err := ds.DeltaEGProve(scheme.curve, scheme.T, scheme.sigmas[i-1])
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
			if i == numParty {
				continue
			}
			err := ds.DeltaEGVerify(scheme.curve, scheme.T, scheme.sigmaRegProofs[i-1], scheme.sigmaRegProofSessionIds[i-1])
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

func (scheme *Scheme[A, B]) DSPhase4() error {
	// compute U and V
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.U = scheme.UXGamma.Sub(scheme.USigma)
		scheme.V = scheme.VXGamma.Sub(scheme.VSigma)
	}

	/*
		START OF DDH CHECK
	*/

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
			if id == numParty {
				continue
			}
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
			if id == numParty {
				continue
			}
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

	/*
		END OF DDH CHECK
	*/

	return nil
}

func (scheme *Scheme[A, B]) DSPhase5() error {
	// re-randomize the ciphertext of gamma
	for i := 1; i <= scheme.n; i++ {
		sRanCTGammaProof, sRanCTGammaSessionId, err := ds.SRanCTGammaProve(scheme.curve, scheme.T, scheme.UGamma, scheme.VGamma, scheme.kProofs[i-1].Statement, scheme.ks[i-1])
		if err != nil {
			return err
		}
		scheme.sRanCTGammaProofs[i-1] = sRanCTGammaProof
		scheme.sRanCTGammaProofSessionIds[i-1] = sRanCTGammaSessionId
	}

	// verify the re-randomization to the ciphertext of gamma
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		for i := 1; i <= scheme.n; i++ {
			if i == party {
				continue
			}
			err := ds.SRanCTGammaVerify(scheme.curve, scheme.T, scheme.sRanCTGammaProofs[i-1], scheme.UGamma, scheme.VGamma, scheme.kProofs[i-1].Statement, scheme.sRanCTGammaProofSessionIds[i-1])
			if err != nil {
				return err
			}
		}
	}

	// compute the ciphertext of k*gamma
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		scheme.AKGamma = scheme.sRanCTGammaProofs[0].APrime
		scheme.BKGamma = scheme.sRanCTGammaProofs[0].BPrime
		for i := 2; i <= scheme.n; i++ {
			scheme.AKGamma = scheme.AKGamma.Add(scheme.sRanCTGammaProofs[i-1].APrime)
			scheme.BKGamma = scheme.BKGamma.Add(scheme.sRanCTGammaProofs[i-1].BPrime)
		}
	}

	return nil
}

func (scheme *Scheme[A, B]) DSPhase6() error {
	// invoke MtA
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			a := scheme.mtaReceiver.Init(scheme.ks[j-1])
			mu, b := scheme.mtaSender.Update(scheme.gammas[i-1], a)
			nu := scheme.mtaReceiver.Multiply(b)
			scheme.mus[i-1][j-1] = mu
			scheme.nus[j-1][i-1] = nu
		}
	}

	// compute delta_i
	for i := 1; i <= scheme.n; i++ {
		delta_i := scheme.gammas[i-1].Mul(scheme.ks[i-1])
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			delta_i = delta_i.Add(scheme.mus[i-1][j-1].Add(scheme.nus[i-1][j-1]))
		}
		scheme.deltas[i-1] = delta_i
	}

	// encrypt delta_i and generate proof
	for i := 1; i <= scheme.n; i++ {
		rDelta, deltaEGProof, deltaEGProofSessionId, err := dkg.SigmaREGProve(scheme.curve, scheme.T, scheme.deltas[i-1])
		if err != nil {
			return err
		}
		scheme.rDeltas[i-1] = rDelta
		scheme.deltaEGProofs[i-1] = deltaEGProof
		scheme.deltaEGProofSessionIds[i-1] = deltaEGProofSessionId
	}

	// verify proof of delta_i's encryption
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		for i := 1; i <= scheme.n; i++ {
			if i == party {
				continue
			}
			err := ds.DeltaEGVerify(scheme.curve, scheme.T, scheme.deltaEGProofs[i-1], scheme.deltaEGProofSessionIds[i-1])
			if err != nil {
				return err
			}
		}
	}

	// compute the encryption of sum(delta_i)
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		scheme.ADelta = scheme.deltaEGProofs[0].A
		scheme.BDelta = scheme.deltaEGProofs[0].B
		for i := 2; i <= scheme.n; i++ {
			scheme.ADelta = scheme.ADelta.Add(scheme.deltaEGProofs[i-1].A)
			scheme.BDelta = scheme.BDelta.Add(scheme.deltaEGProofs[i-1].B)
		}
	}

	return nil
}

func (scheme *Scheme[A, B]) DSPhase7() error {
	// compute A and B
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		scheme.A = scheme.AKGamma.Sub(scheme.ADelta)
		scheme.B = scheme.BKGamma.Sub(scheme.BDelta)
	}

	/*
		START OF DDH CHECK
	*/

	// re-randomize, generate proof and commitment
	for i := 1; i <= scheme.n; i++ {
		reProof, reCommitment, reProofSessionId, err := ds.REComProve(scheme.curve, scheme.T, scheme.A, scheme.B)
		if err != nil {
			return err
		}
		scheme.abREProofs[i-1] = reProof
		scheme.abRECommitments[i-1] = reCommitment
		scheme.abREProofSessionIds[i-1] = reProofSessionId
	}

	// de-com, verify proof of re-randomization
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		for i := 1; i <= scheme.n; i++ {
			if i == party {
				continue
			}
			err := ds.REDeComVerify(scheme.curve, scheme.abREProofs[i-1], scheme.abRECommitments[i-1], scheme.abREProofSessionIds[i-1], scheme.T, scheme.A, scheme.B)
			if err != nil {
				return err
			}
		}
	}

	// compute A', B'
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		scheme.APrime = scheme.abREProofs[0].APrime
		scheme.BPrime = scheme.abREProofs[0].BPrime
		for i := 2; i <= scheme.n; i++ {
			scheme.APrime = scheme.APrime.Add(scheme.abREProofs[i-1].APrime)
			scheme.BPrime = scheme.BPrime.Add(scheme.abREProofs[i-1].BPrime)
		}
	}

	// compute A'_i
	for i := 1; i <= scheme.n; i++ {
		scheme.APrimes[i-1] = scheme.APrime.Mul(scheme.ds[i-1])
	}

	// generate DDH proof and commitment
	for i := 1; i <= scheme.n; i++ {
		ddhProof, ddhCommitment, ddhProofSessionId, err := ds.DDHComProve(scheme.curve, nil, scheme.APrime, scheme.TProofs[i-1].Statement, scheme.APrimes[i-1], scheme.ds[i-1])
		if err != nil {
			return err
		}
		scheme.abDDHProofs[i-1] = ddhProof
		scheme.abDDHCommitments[i-1] = ddhCommitment
		scheme.abDDHProofSessionIds[i-1] = ddhProofSessionId
	}

	// de-com, verify proof of DDH
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		for i := 1; i <= scheme.n; i++ {
			if i == party {
				continue
			}
			err := ds.DDHDeComVerify(scheme.curve, scheme.abDDHProofs[i-1], scheme.abDDHCommitments[i-1], scheme.abDDHProofSessionIds[i-1], nil, scheme.APrime)
			if err != nil {
				return err
			}
		}
	}

	// compute sum of A'_i and compare it with B'
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		sumAPrimes := scheme.APrimes[0]
		for i := 2; i <= scheme.n; i++ {
			sumAPrimes = sumAPrimes.Add(scheme.APrimes[i-1])
		}
		if !sumAPrimes.Equal(scheme.BPrime) {
			return fmt.Errorf("failed when verifying DDH relation")
		}
	}

	/*
		END OF DDH CHECK
	*/

	// compute BDeltaPrimes and DDH proofs
	for id := 1; id <= scheme.n; id++ {
		scheme.BDeltaPrimes[id-1] = scheme.deltaEGProofs[id-1].B.Sub(scheme.P.Mul(scheme.deltas[id-1]))
		deltaDDHProof, deltaDDHProofSessionId, err := dkg.SigmaDDHProve(scheme.curve, scheme.P, scheme.T, scheme.deltaEGProofs[id-1].A, scheme.BDeltaPrimes[id-1], scheme.rDeltas[id-1])
		if err != nil {
			return err
		}
		scheme.deltaDDHProofs[id-1] = deltaDDHProof
		scheme.deltaDDHProofSessionIds[id-1] = deltaDDHProofSessionId
	}

	// verify DDH proofs
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			err := dkg.SigmaDDHVerify(scheme.curve, scheme.deltaDDHProofs[id-1], scheme.deltaDDHProofSessionIds[id-1], scheme.P, scheme.T)
			if err != nil {
				return err
			}
		}
	}

	// verify sigmas
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		for id := 1; id <= scheme.n; id++ {
			if id == numParty {
				continue
			}
			if !scheme.P.Mul(scheme.deltas[id-1]).Equal(scheme.deltaEGProofs[id-1].B.Sub(scheme.deltaDDHProofs[id-1].Statement2)) {
				return fmt.Errorf("failed when verifying the validation of sigma")
			}
		}
	}

	// compute sigma
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for numParty := 1; numParty <= scheme.n; numParty++ {
		scheme.delta = scheme.deltas[0]
		for id := 2; id <= scheme.n; id++ {
			scheme.delta = scheme.delta.Add(scheme.deltas[id-1])
		}
	}

	return nil
}

func (scheme *Scheme[A, B]) DSPhase8() error {
	// compute s_i
	for i := 1; i <= scheme.n; i++ {
		deltaInvert, err := scheme.delta.Invert()
		if err != nil {
			return fmt.Errorf("failed in computing the inverse of delta")
		}

		h := scheme.curve.Scalar.Hash(scheme.message)

		scheme.ss[i-1] = deltaInvert.Mul(h.Mul(scheme.gammas[i-1]).Add(scheme.r.Mul(scheme.sigmas[i-1])))
	}

	// compute s
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		scheme.s = scheme.ss[0]
		for i := 2; i <= scheme.n; i++ {
			scheme.s = scheme.s.Add(scheme.ss[i-1])
		}
	}

	// verify the final signature
	/****************************************
	EACH PARTY WILL DO THIS SIMILAR PROCEDURE
	****************************************/
	for party := 1; party <= scheme.n; party++ {
		err := verify.ECDSAVerify(scheme.curve, nil, scheme.Q, scheme.message, scheme.r, scheme.s)
		if err != nil {
			return err
		}
	}

	return nil
}
