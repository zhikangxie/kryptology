package scheme

import (
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/elgamalexp"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/paillier"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestScheme_DKGPhase1(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	d := scheme.ds[0]
	for id := 2; id <= scheme.n; id++ {
		d = d.Add(scheme.ds[id-1])
	}
	if !scheme.T.Equal(scheme.P.Mul(d)) {
		panic("T")
	}
}

func TestScheme_DKGPhase2(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")
	// TO VERIFY TWO CIPHERTEXTS
	d := scheme.ds[0]
	for id := 2; id <= scheme.n; id++ {
		d = d.Add(scheme.ds[id-1])
	}
	semiDecryptor := elgamalexp.NewSemiDecryptor(scheme.curve, nil, scheme.T, d)
	// verify the correctness of gamma's ciphertext
	ctGamma := elgamalexp.NewCiphertext(scheme.UGamma, scheme.VGamma)
	semiGamma := semiDecryptor.SemiDecrypt(ctGamma)
	gamma := scheme.gammas[0]
	for id := 2; id <= scheme.n; id++ {
		gamma = gamma.Add(scheme.gammas[id-1])
	}
	err = elgamalexp.Compare(scheme.curve, nil, gamma, semiGamma)
	require.NoError(t, err, "failed when generating encryption of gamma")
	// verify the correctness of xGamma's ciphertext
	ctXGamma := elgamalexp.NewCiphertext(scheme.UXGamma, scheme.VXGamma)
	semiXGamma := semiDecryptor.SemiDecrypt(ctXGamma)
	x := scheme.xs[0]
	for id := 2; id <= scheme.n; id++ {
		x = x.Add(scheme.xs[id-1])
	}
	err = elgamalexp.Compare(scheme.curve, nil, x.Mul(gamma), semiXGamma)
	require.NoError(t, err, "failed when generating encryption of xGamma")
}

func TestScheme_DKGPhase3(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	t.Log("safe primes generated")
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			var sender = mta_paillier.NewSender(scheme.curve, p, q)
			var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
			setup1Statement, setup1Proof := receiver.SetupInit()
			setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
			receiver.SetupDone(setup2Statement, setup2Proof)
			scheme.mtaSenders[i-1][j-1] = sender
			scheme.mtaReceivers[i-1][j-1] = receiver
			t.Logf("MtA between party %d and party %d initiated", i, j)
		}
	}

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(t, err, "failed in Phase 3 of DKG")

	// verify encryption of sigma=sum(sigmas)
	d := scheme.ds[0]
	for id := 2; id <= scheme.n; id++ {
		d = d.Add(scheme.ds[id-1])
	}
	semiDecryptor := elgamalexp.NewSemiDecryptor(scheme.curve, nil, scheme.T, d)
	ctSigma := elgamalexp.NewCiphertext(scheme.USigma, scheme.VSigma)
	semiSigma := semiDecryptor.SemiDecrypt(ctSigma)
	sigma := scheme.sigmas[0]
	for id := 2; id <= scheme.n; id++ {
		sigma = sigma.Add(scheme.sigmas[id-1])
	}
	err = elgamalexp.Compare(scheme.curve, nil, sigma, semiSigma)
	require.NoError(t, err, "failed when generating encryption of sigma")

	// verify sum(sigmas) = xr
	x := scheme.xs[0]
	for id := 2; id <= scheme.n; id++ {
		x = x.Add(scheme.xs[id-1])
	}
	gamma := scheme.gammas[0]
	for id := 2; id <= scheme.n; id++ {
		gamma = gamma.Add(scheme.gammas[id-1])
	}
	if sigma.Cmp(x.Mul(gamma)) != 0 {
		panic("sum of sigmas is not equal to xr")
	}
}

func TestScheme_DKGPhase4(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	t.Log("safe primes generated")
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			var sender = mta_paillier.NewSender(scheme.curve, p, q)
			var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
			setup1Statement, setup1Proof := receiver.SetupInit()
			setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
			receiver.SetupDone(setup2Statement, setup2Proof)
			scheme.mtaSenders[i-1][j-1] = sender
			scheme.mtaReceivers[i-1][j-1] = receiver
			t.Logf("MtA between party %d and party %d initiated", i, j)
		}
	}

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(t, err, "failed in Phase 3 of DKG")

	err = scheme.DKGPhase4()
	require.NoError(t, err, "failed in Phase 4 of DKG")
}

func TestScheme_DSPhase1(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)

	err := scheme.DSPhase1()
	require.NoError(t, err, "failed in Phase 1 of DS")
}

func TestScheme_DSPhase2(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")

	err = scheme.DSPhase1()
	require.NoError(t, err, "failed in Phase 1 of DS")

	err = scheme.DSPhase2()
	require.NoError(t, err, "failed in Phase 2 of DS")

	// verify the correctness of encryption of k*gamma
	k := scheme.ks[0]
	for i := 2; i <= scheme.n; i++ {
		k = k.Add(scheme.ks[i-1])
	}
	gamma := scheme.gammas[0]
	for i := 2; i <= scheme.n; i++ {
		gamma = gamma.Add(scheme.gammas[i-1])
	}
	d := scheme.ds[0]
	for i := 2; i <= scheme.n; i++ {
		d = d.Add(scheme.ds[i-1])
	}
	semiDecryptor := elgamalexp.NewSemiDecryptor(scheme.curve, nil, scheme.T, d)
	ctKGamma := elgamalexp.NewCiphertext(scheme.AKGamma, scheme.BKGamma)
	semiKGamma := semiDecryptor.SemiDecrypt(ctKGamma)
	err = elgamalexp.Compare(scheme.curve, nil, k.Mul(gamma), semiKGamma)
	require.NoError(t, err, "failed in generating the ciphertext of k*gamma")
}

func TestScheme_DSPhase3(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	t.Log("safe primes generated")
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			var sender = mta_paillier.NewSender(scheme.curve, p, q)
			var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
			setup1Statement, setup1Proof := receiver.SetupInit()
			setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
			receiver.SetupDone(setup2Statement, setup2Proof)
			scheme.mtaSenders[i-1][j-1] = sender
			scheme.mtaReceivers[i-1][j-1] = receiver
			t.Logf("MtA between party %d and party %d initiated", i, j)
		}
	}

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(t, err, "failed in Phase 3 of DKG")

	err = scheme.DKGPhase4()
	require.NoError(t, err, "failed in Phase 4 of DKG")

	err = scheme.DSPhase1()
	require.NoError(t, err, "failed in Phase 1 of DS")

	err = scheme.DSPhase2()
	require.NoError(t, err, "failed in Phase 2 of DS")

	err = scheme.DSPhase3()
	require.NoError(t, err, "failed in Phase 3 of DS")

	// verify the correctness of encryption of sum(delta_i)
	delta := scheme.deltas[0]
	for i := 2; i <= scheme.n; i++ {
		delta = delta.Add(scheme.deltas[i-1])
	}
	d := scheme.ds[0]
	for i := 2; i <= scheme.n; i++ {
		d = d.Add(scheme.ds[i-1])
	}
	semiDecryptor := elgamalexp.NewSemiDecryptor(scheme.curve, nil, scheme.T, d)
	ctDelta := elgamalexp.NewCiphertext(scheme.ADelta, scheme.BDelta)
	semiDelta := semiDecryptor.SemiDecrypt(ctDelta)
	err = elgamalexp.Compare(scheme.curve, nil, delta, semiDelta)
	require.NoError(t, err, "failed in generating the ciphertext of delta")

	// verify sum(delta_i) = k*gamma
	k := scheme.ks[0]
	for i := 2; i <= scheme.n; i++ {
		k = k.Add(scheme.ks[i-1])
	}
	gamma := scheme.gammas[0]
	for i := 2; i <= scheme.n; i++ {
		gamma = gamma.Add(scheme.gammas[i-1])
	}
	if delta.Cmp(k.Mul(gamma)) != 0 {
		panic("delta is not equal to k*gamma")
	}
}

func TestScheme_DSPhase4(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	t.Log("safe primes generated")
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			var sender = mta_paillier.NewSender(scheme.curve, p, q)
			var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
			setup1Statement, setup1Proof := receiver.SetupInit()
			setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
			receiver.SetupDone(setup2Statement, setup2Proof)
			scheme.mtaSenders[i-1][j-1] = sender
			scheme.mtaReceivers[i-1][j-1] = receiver
			t.Logf("MtA between party %d and party %d initiated", i, j)
		}
	}

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(t, err, "failed in Phase 3 of DKG")

	err = scheme.DKGPhase4()
	require.NoError(t, err, "failed in Phase 4 of DKG")

	err = scheme.DSPhase1()
	require.NoError(t, err, "failed in Phase 1 of DS")

	err = scheme.DSPhase2()
	require.NoError(t, err, "failed in Phase 2 of DS")

	err = scheme.DSPhase3()
	require.NoError(t, err, "failed in Phase 3 of DS")

	err = scheme.DSPhase4()
	require.NoError(t, err, "failed in Phase 4 of DS")
}

func TestScheme_DSPhase5(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme[*mta_paillier.Round1Output, *mta_paillier.Round2Output](curveInit)
	str := "test message"
	scheme.message = []byte(str)
	var p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	var q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
	t.Log("safe primes generated")
	for i := 1; i <= scheme.n; i++ {
		for j := 1; j <= scheme.n; j++ {
			if i == j {
				continue
			}
			var sender = mta_paillier.NewSender(scheme.curve, p, q)
			var receiver = mta_paillier.NewReceiver(scheme.curve, p0, q0)
			setup1Statement, setup1Proof := receiver.SetupInit()
			setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
			receiver.SetupDone(setup2Statement, setup2Proof)
			scheme.mtaSenders[i-1][j-1] = sender
			scheme.mtaReceivers[i-1][j-1] = receiver
			t.Logf("MtA between party %d and party %d initiated", i, j)
		}
	}

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")

	err = scheme.DKGPhase2()
	require.NoError(t, err, "failed in Phase 2 of DKG")

	err = scheme.DKGPhase3()
	require.NoError(t, err, "failed in Phase 3 of DKG")

	err = scheme.DKGPhase4()
	require.NoError(t, err, "failed in Phase 4 of DKG")

	err = scheme.DSPhase1()
	require.NoError(t, err, "failed in Phase 1 of DS")

	err = scheme.DSPhase2()
	require.NoError(t, err, "failed in Phase 2 of DS")

	err = scheme.DSPhase3()
	require.NoError(t, err, "failed in Phase 3 of DS")

	err = scheme.DSPhase4()
	require.NoError(t, err, "failed in Phase 4 of DS")

	err = scheme.DSPhase5()
	require.NoError(t, err, "failed in Phase 4 of DS")
}
