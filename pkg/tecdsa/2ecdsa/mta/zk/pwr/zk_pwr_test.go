package zk_pwr

import (
	"math/big"
	"testing"

	tt "github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/stretchr/testify/require"
)

func makeNewPaillierPublicKey(t *testing.T, n *big.Int) *paillier.PublicKey {
	t.Helper()
	publicKey, err := paillier.NewPubkey(n)
	require.NoError(t, err)
	return publicKey
}

func TestZKPwr(t *testing.T) {
	pp, qrst, qrproof, qrpp, qrdlst, qrdlproof, qrdlpp := SetUpProve(128)

	res := SetUpVerify(qrst, qrproof, qrpp, qrdlst, qrdlproof, qrdlpp)

	require.Equal(t, true, res)

	q := tt.B10("12122745362522189816168535264551355768089283231069686330301128627041958196835868405970767150401427191976786435200511843851744213149595052566013030642866907")
	p := tt.B10("13334877681824046536664719753000692481615243060546695171749157112026072862294410162436291925578885141357927002155461724765584886877402066038258074266638227")

	sk, _ := paillier.NewSecretKey(p, q)
	pk := makeNewPaillierPublicKey(t, sk.N)

	x, err := core.Rand(q)
	require.NoError(t, err)

	r, err := core.Rand(sk.N)
	require.NoError(t, err)

	c, r, err := pk.Encrypt(x)

	require.NoError(t, err)

	pwrst := NewPwrStatement(pk.N, pk.N2, q, c)
	pwrws := NewPwrWitness(x, r)

	proof := Prove(pwrws, pwrst, pp)

	res = Verify(pwrst, proof, pp)
	require.Equal(t, true, res)

}
