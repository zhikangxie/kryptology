package zk

import (
	"crypto/rand"
	"math/big"
)

type AffRanProver struct {
	N   *big.Int
	g   *big.Int
	h   *big.Int
	q   *big.Int
	c_A *big.Int
	c_B *big.Int

	a     *big.Int
	alpha *big.Int

	b    *big.Int
	beta *big.Int
	rho1 *big.Int
	rho2 *big.Int
	rho3 *big.Int
	rho4 *big.Int
}

type AffRanVerifier struct {
	N   *big.Int
	g   *big.Int
	h   *big.Int
	q   *big.Int
	c_A *big.Int
	c_B *big.Int

	e  *big.Int
	A  *big.Int
	B1 *big.Int
	B2 *big.Int
	B3 *big.Int
	B4 *big.Int
}

const t = 128
const s = 128
const l = 80

func NewVerifier(lambda int) *AffRanVerifier {
	var p *big.Int
	var q *big.Int
	for {
		pp, _ := rand.Prime(rand.Reader, lambda/2)
		p = new(big.Int).Add(new(big.Int).Mul(pp, big.NewInt(2)), big.NewInt(1))
		if p.ProbablyPrime(20) {
			break
		}
	}
	for {
		qq, _ := rand.Prime(rand.Reader, lambda/2)
		q = new(big.Int).Add(new(big.Int).Mul(qq, big.NewInt(2)), big.NewInt(1))
		if q.ProbablyPrime(20) {
			break
		}
	}
	N := new(big.Int).Mul(p, q)
	var h *big.Int
	for {
		h, _ = rand.Int(rand.Reader, N)
		if big.Jacobi(h, N) == 1 {
			break
		}
	}
	r, _ := rand.Int(rand.Reader, N)
	g := new(big.Int).Exp(h, r, N)

	return &AffRanVerifier{
		N: N,
		g: g,
		h: h,
		q: q,
	}
}

func (prover *AffRanProver) SetParamsAndWitnesses(N, g, h, q, c_B *big.Int) {
	prover.N = N
	prover.g = g
	prover.h = h
	prover.q = q

	k := new(big.Int).Lsh(new(big.Int).Mul(prover.q, prover.q), t+l+s)
	NN := new(big.Int).Mul(prover.N, prover.N)
	N_plus_1 := new(big.Int).Add(prover.N, big.NewInt(1))

	prover.a, _ = rand.Int(rand.Reader, q)
	prover.alpha, _ = rand.Int(rand.Reader, k)

	prover.c_B = c_B
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			prover.c_B,
			new(big.Int).Exp(
				N_plus_1,
				new(big.Int).Lsh(prover.q, t+l),
				NN,
			),
		),
		NN,
	)
	prover.c_A = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, prover.a, NN), new(big.Int).Exp(N_plus_1, prover.alpha, NN)), NN)
}

func (verifier *AffRanVerifier) SetStatement(c_A, c_B *big.Int) {
	verifier.c_A = c_A
	verifier.c_B = c_B
}

func (prover *AffRanProver) Prove1() (*big.Int, *big.Int, *big.Int, *big.Int, *big.Int) {
	k := new(big.Int).Lsh(new(big.Int).Mul(prover.q, prover.q), t+l+s)
	NN := new(big.Int).Mul(prover.N, prover.N)
	N_plus_1 := new(big.Int).Add(prover.N, big.NewInt(1))

	prover.b, _ = rand.Int(rand.Reader, new(big.Int).Lsh(prover.q, t+l))
	prover.beta, _ = rand.Int(rand.Reader, new(big.Int).Lsh(k, t+l))
	prover.rho1, _ = rand.Int(rand.Reader, new(big.Int).Lsh(prover.N, t+l))
	prover.rho2, _ = rand.Int(rand.Reader, new(big.Int).Lsh(prover.N, t+l))
	prover.rho3, _ = rand.Int(rand.Reader, prover.N)
	prover.rho4, _ = rand.Int(rand.Reader, prover.N)

	c := new(big.Int).Mod(new(big.Int).Mul(prover.c_B, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(prover.q, t+l), NN)), NN)
	A := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, prover.b, NN), new(big.Int).Exp(N_plus_1, prover.beta, NN)), NN)
	B1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(prover.g, prover.b, prover.N), new(big.Int).Exp(prover.h, prover.rho1, prover.N)), prover.N)
	B2 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(prover.g, prover.beta, prover.N), new(big.Int).Exp(prover.h, prover.rho2, prover.N)), prover.N)
	B3 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(prover.g, prover.a, prover.N), new(big.Int).Exp(prover.h, prover.rho3, prover.N)), prover.N)
	B4 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(prover.g, prover.alpha, prover.N), new(big.Int).Exp(prover.h, prover.rho4, prover.N)), prover.N)

	return A, B1, B2, B3, B4
}

func (verifier *AffRanVerifier) Challenge(A, B1, B2, B3, B4 *big.Int) *big.Int {
	verifier.A = A
	verifier.B1 = B1
	verifier.B2 = B2
	verifier.B3 = B3
	verifier.B4 = B4

	verifier.e, _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), t))
	return verifier.e
}

func (prover *AffRanProver) Prove2(e *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	z1 := new(big.Int).Add(prover.b, new(big.Int).Mul(e, prover.a))
	z2 := new(big.Int).Add(prover.beta, new(big.Int).Mul(e, prover.alpha))
	z3 := new(big.Int).Add(prover.rho1, new(big.Int).Mul(e, prover.rho3))
	z4 := new(big.Int).Add(prover.rho2, new(big.Int).Mul(e, prover.rho4))
	return z1, z2, z3, z4
}

func (verifier *AffRanVerifier) Verify(z1, z2, z3, z4 *big.Int) bool {
	k := new(big.Int).Lsh(new(big.Int).Mul(verifier.q, verifier.q), t+l+s)
	NN := new(big.Int).Mul(verifier.N, verifier.N)
	N_plus_1 := new(big.Int).Add(verifier.N, big.NewInt(1))

	if z1.Cmp(new(big.Int).Lsh(verifier.q, t+l)) != -1 {
		return false
	}
	if z1.Cmp(new(big.Int).Lsh(verifier.q, t)) == -1 {
		return false
	}
	if z2.Cmp(new(big.Int).Lsh(k, t+l)) == 1 {
		return false
	}
	if z2.Cmp(new(big.Int).Lsh(k, t)) == -1 {
		return false
	}

	c := new(big.Int).Mod(new(big.Int).Mul(verifier.c_B, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(verifier.q, t+l), NN)), NN)
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(c, z1, NN), new(big.Int).Exp(N_plus_1, z2, NN)), NN).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(verifier.A, new(big.Int).Exp(verifier.c_A, verifier.e, NN)), NN),
	) != 0 {
		return false
	}
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(verifier.g, z1, verifier.N), new(big.Int).Exp(verifier.h, z3, verifier.N)), verifier.N).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(verifier.B1, new(big.Int).Exp(verifier.B3, verifier.e, verifier.N)), verifier.N),
	) != 0 {
		return false
	}
	if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(verifier.g, z2, verifier.N), new(big.Int).Exp(verifier.h, z4, verifier.N)), verifier.N).Cmp(
		new(big.Int).Mod(new(big.Int).Mul(verifier.B2, new(big.Int).Exp(verifier.B4, verifier.e, verifier.N)), verifier.N),
	) != 0 {
		return false
	}

	return true
}
