package zk

import (
	"testing"

	tt "github.com/coinbase/kryptology/internal"
	crypto "github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/stretchr/testify/require"
)

func TestZKPwr(t *testing.T) {
	st, ws := genQRN0StatementAndWit(128)
	pp := NewSecurityPP(128, 128, 80, st.h, st.g, st.N0)
	proof := qrcommit(st, ws, pp)
	qrchallenge(proof)
	qrrespond(st, ws, proof)

	res := qrverify(st, proof)
	require.Equal(t, true, res)

	q := tt.B10("12122745362522189816168535264551355768089283231069686330301128627041958196835868405970767150401427191976786435200511843851744213149595052566013030642866907")
	p := tt.B10("13334877681824046536664719753000692481615243060546695171749157112026072862294410162436291925578885141357927002155461724765584886877402066038258074266638227")

	sk, _ := paillier.NewSecretKey(p, q)
	pk := makeNewPaillierPublicKey(t, sk.N)

	x, err := crypto.Rand(q)
	require.NoError(t, err)

	r, err := crypto.Rand(sk.N)
	require.NoError(t, err)

	c, r, err := pk.Encrypt(x)

	require.NoError(t, err)

	pwrst := NewPwrStatement(pk.N, pk.N2, q, c)

	pwrws := NewPwrWitness(x, r)

	pwrproof := PwrCommit(pwrst, pwrws, pp)

	PwrChallenge(pwrst, pwrproof, pp)

	PwrRespond(pwrst, pwrws, pwrproof, pp)

	res = PwrVerify(pwrst, pwrproof, pp)

	require.Equal(t, true, res)
}
