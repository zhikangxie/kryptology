package zk

import (
	"crypto/rand"
	"math/big"

	crypto "github.com/coinbase/kryptology/pkg/core"
)

type AffranStatement struct {
	NN  *big.Int
	N   *big.Int
	q   *big.Int
	c_A *big.Int
	c_B *big.Int
}

func NewAffranStatement(NN *big.Int, N *big.Int, q *big.Int, c_A *big.Int, c_B *big.Int) *AffranStatement {
	st := &AffranStatement{}
	st.NN = NN
	st.N = N
	st.q = q
	st.c_A = c_A
	st.c_B = c_B
	return st
}

type AffranWitness struct {
	a       *big.Int
	alpha   *big.Int
	alpha_r *big.Int

	b    *big.Int
	beta *big.Int
	rho1 *big.Int
	rho2 *big.Int
	rho3 *big.Int
	rho4 *big.Int
}

func NewAffranWitness(a *big.Int, alpha *big.Int) *AffranWitness {
	ws := &AffranWitness{}
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

func AffranCommit(st *AffranStatement, ws *AffranWitness, pp *PwrSecurityPP) *AffranProof {
	var err error
	proof := &AffranProof{}

	k := new(big.Int).Lsh(new(big.Int).Mul(st.q, st.q), t+l+s)
	N_plus_1 := new(big.Int).Add(st.N, big.NewInt(1))

	ws.b, _ = rand.Int(rand.Reader, new(big.Int).Lsh(st.q, t+l))
	ws.beta, _ = rand.Int(rand.Reader, new(big.Int).Lsh(k, t+l))
	ws.rho1, _ = rand.Int(rand.Reader, new(big.Int).Lsh(st.N, t+l))
	ws.rho2, _ = rand.Int(rand.Reader, new(big.Int).Lsh(st.N, t+l))
	ws.rho3, _ = rand.Int(rand.Reader, st.N)
	ws.rho4, _ = rand.Int(rand.Reader, st.N)

	c := new(big.Int).Mod(new(big.Int).Mul(st.c_B, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(st.q, t+l), st.NN)), st.NN)
	proof.A = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, ws.b, st.NN), new(big.Int).Exp(N_plus_1, ws.beta, st.NN)), st.NN)
	proof.B1 = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.b, pp.N0), new(big.Int).Exp(pp.h, ws.rho1, pp.N0)), pp.N0)
	proof.B2 = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.beta, pp.N0), new(big.Int).Exp(pp.h, ws.rho2, pp.N0)), pp.N0)
	proof.B3 = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.a, pp.N0), new(big.Int).Exp(pp.h, ws.rho3, pp.N0)), pp.N0)
	proof.B4 = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.alpha, pp.N0), new(big.Int).Exp(pp.h, ws.rho4, pp.N0)), pp.N0)

	if err != nil {
		panic("ZK Affran commit")
	}
	return proof
}

func AffranChallenge(st *AffranStatement, proof *AffranProof, pp *PwrSecurityPP) {
	var err error
	two_t := new(big.Int).Exp(crypto.Two, big.NewInt(pp.t), st.N)
	proof.e, err = crypto.Rand(two_t)
	if err != nil {
		panic("ZK Pwr challenge")
	}
}

func AffranRespond(st *AffranStatement, ws *AffranWitness, proof *AffranProof, pp *PwrSecurityPP) {
	proof.z1 = new(big.Int).Add(ws.b, new(big.Int).Mul(proof.e, ws.a))
	proof.z2 = new(big.Int).Add(ws.beta, new(big.Int).Mul(proof.e, ws.alpha))
	proof.z3 = new(big.Int).Add(ws.rho1, new(big.Int).Mul(proof.e, ws.rho3))
	proof.z4 = new(big.Int).Add(ws.rho2, new(big.Int).Mul(proof.e, ws.rho4))
}

func AffranVerify(st *AffranStatement, proof *AffranProof, pp *PwrSecurityPP) bool {

	k := new(big.Int).Lsh(new(big.Int).Mul(st.q, st.q), t+l+s)

	N_plus_1 := new(big.Int).Add(st.N, big.NewInt(1))

	if proof.z1.Cmp(new(big.Int).Lsh(st.q, t+l)) != -1 {
		return false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(st.q, t)) == -1 {
		return false
	}
	if proof.z2.Cmp(new(big.Int).Lsh(k, t+l)) == 1 {
		return false
	}
	if proof.z2.Cmp(new(big.Int).Lsh(k, t)) == -1 {
		return false
	}

	c := new(big.Int).Mod(new(big.Int).Mul(st.c_B, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(st.q, t+l), st.NN)), st.NN)
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, proof.z1, st.NN), new(big.Int).Exp(N_plus_1, proof.z2, st.NN)), st.NN).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(proof.A, new(big.Int).Exp(st.c_A, proof.e, st.NN)), st.NN),
	) != 0 {
		return false
	}
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, proof.z1, pp.N0), new(big.Int).Exp(pp.h, proof.z3, pp.N0)), pp.N0).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(proof.B1, new(big.Int).Exp(proof.B3, proof.e, pp.N0)), pp.N0),
	) != 0 {
		return false
	}
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, proof.z2, pp.N0), new(big.Int).Exp(pp.h, proof.z4, pp.N0)), pp.N0).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(proof.B2, new(big.Int).Exp(proof.B4, proof.e, pp.N0)), pp.N0),
	) != 0 {
		return false
	}
	return true
}
