package zk_raffran

import (
	"crypto/rand"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	zk_pwr "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/pwr"
	"github.com/gtank/merlin"
)

type AffranStatement struct {
	NN  *big.Int
	N   *big.Int
	q   *big.Int
	c_A *big.Int
	c_B *big.Int
}

func NewAffranStatement(NN *big.Int, N *big.Int, q *big.Int, c_A *big.Int, c_B *big.Int) AffranStatement {
	st := AffranStatement{}
	st.NN = NN
	st.N = N
	st.q = q
	st.c_A = c_A
	st.c_B = c_B
	return st
}

type AffranWitness struct {
	a     *big.Int
	alpha *big.Int
}

func NewAffranWitness(a *big.Int, alpha *big.Int) AffranWitness {
	ws := AffranWitness{}
	ws.a = a
	ws.alpha = alpha
	return ws
}

type AffranProof struct {
	e  *big.Int
	A  *big.Int
	B1 *big.Int
	B2 *big.Int
	B3 *big.Int
	B4 *big.Int

	z1 *big.Int
	z2 *big.Int
	z3 *big.Int
	z4 *big.Int
}

func Prove(ws AffranWitness, st AffranStatement, pp zk_pwr.PwrSecurityPP) AffranProof {
	tx := merlin.NewTranscript("Affran")
	k := new(big.Int).Lsh(new(big.Int).Mul(st.q, st.q), zk.T+zk.L+zk.S)
	N_plus_1 := new(big.Int).Add(st.N, big.NewInt(1))

	b, _ := rand.Int(rand.Reader, new(big.Int).Lsh(st.q, zk.T+zk.L))
	beta, _ := rand.Int(rand.Reader, new(big.Int).Lsh(k, zk.T+zk.L))
	rho1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(st.N, zk.T+zk.L))
	rho2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(st.N, zk.T+zk.L))
	rho3, _ := rand.Int(rand.Reader, st.N)
	rho4, _ := rand.Int(rand.Reader, st.N)

	c := new(big.Int).Mod(new(big.Int).Mul(st.c_B, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(st.q, zk.T+zk.L), st.NN)), st.NN)
	tx.AppendMessage([]byte("c"), c.Bytes())
	A := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, b, st.NN), new(big.Int).Exp(N_plus_1, beta, st.NN)), st.NN)
	tx.AppendMessage([]byte("A"), A.Bytes())
	B1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.GetG(), b, pp.N0), new(big.Int).Exp(pp.GetH(), rho1, pp.N0)), pp.N0)
	tx.AppendMessage([]byte("B1"), B1.Bytes())
	B2 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.GetG(), beta, pp.N0), new(big.Int).Exp(pp.GetH(), rho2, pp.N0)), pp.N0)
	tx.AppendMessage([]byte("B2"), B2.Bytes())
	B3 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.GetG(), ws.a, pp.N0), new(big.Int).Exp(pp.GetH(), rho3, pp.N0)), pp.N0)
	tx.AppendMessage([]byte("B3"), B3.Bytes())
	B4 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.GetG(), ws.alpha, pp.N0), new(big.Int).Exp(pp.GetH(), rho4, pp.N0)), pp.N0)
	tx.AppendMessage([]byte("B4"), B4.Bytes())

	e := new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	z1 := new(big.Int).Add(b, new(big.Int).Mul(e, ws.a))
	z2 := new(big.Int).Add(beta, new(big.Int).Mul(e, ws.alpha))
	z3 := new(big.Int).Add(rho1, new(big.Int).Mul(e, rho3))
	z4 := new(big.Int).Add(rho2, new(big.Int).Mul(e, rho4))

	return AffranProof{e, A, B1, B2, B3, B4, z1, z2, z3, z4}
}

func Verify(st AffranStatement, proof AffranProof, pp zk_pwr.PwrSecurityPP) bool {

	k := new(big.Int).Lsh(new(big.Int).Mul(st.q, st.q), zk.T+zk.L+zk.S)

	N_plus_1 := new(big.Int).Add(st.N, big.NewInt(1))

	if proof.z1.Cmp(new(big.Int).Lsh(st.q, zk.T+zk.L)) != -1 {
		return false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(st.q, zk.T)) == -1 {
		return false
	}
	if proof.z2.Cmp(new(big.Int).Lsh(k, zk.T+zk.L)) == 1 {
		return false
	}
	if proof.z2.Cmp(new(big.Int).Lsh(k, zk.T)) == -1 {
		return false
	}

	c := new(big.Int).Mod(new(big.Int).Mul(st.c_B, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(st.q, zk.T+zk.L), st.NN)), st.NN)
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, proof.z1, st.NN), new(big.Int).Exp(N_plus_1, proof.z2, st.NN)), st.NN).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(proof.A, new(big.Int).Exp(st.c_A, proof.e, st.NN)), st.NN),
	) != 0 {
		return false
	}
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.GetG(), proof.z1, pp.N0), new(big.Int).Exp(pp.GetH(), proof.z3, pp.N0)), pp.N0).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(proof.B1, new(big.Int).Exp(proof.B3, proof.e, pp.N0)), pp.N0),
	) != 0 {
		return false
	}
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.GetG(), proof.z2, pp.N0), new(big.Int).Exp(pp.GetH(), proof.z4, pp.N0)), pp.N0).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(proof.B2, new(big.Int).Exp(proof.B4, proof.e, pp.N0)), pp.N0),
	) != 0 {
		return false
	}
	return true
}
