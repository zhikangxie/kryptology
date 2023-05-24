package scheme

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/elgamalexp"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestScheme_DKGPhase1(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme(curveInit)

	err := scheme.DKGPhase1()
	require.NoError(t, err, "failed in Phase 1 of DKG")
}

func TestScheme_DKGPhase2(t *testing.T) {
	curveInit := curves.K256()
	scheme := NewScheme(curveInit)

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
