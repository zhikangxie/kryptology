package zk

import (
	"math/big"

	crypto "github.com/coinbase/kryptology/pkg/core"
)

type PwrSecurityPP struct {
	t  int64
	l  int64
	s  int64
	h  *big.Int
	g  *big.Int
	N0 *big.Int
}

type PwrStatement struct {
	NN *big.Int
	N  *big.Int
	q  *big.Int
	c  *big.Int
}

type PwrWitness struct {
	x *big.Int
	r *big.Int

	r1 *big.Int
	r2 *big.Int
	r3 *big.Int
	r4 *big.Int
}

type PwrProof struct {
	e *big.Int
	C *big.Int
	d *big.Int
	D *big.Int

	z1 *big.Int
	z2 *big.Int
	z3 *big.Int
}

type QRStatement struct {
	h  *big.Int
	g  *big.Int
	N0 *big.Int
}

type QRWitness struct {
	x  *big.Int
	x1 *big.Int
	r  *big.Int
	r1 *big.Int
}

type QRProof struct {
	e  *big.Int
	a  *big.Int
	a1 *big.Int
	z  *big.Int
	z1 *big.Int
}

func NewQRStatement(h *big.Int, g *big.Int, N0 *big.Int) *QRStatement {
	st := &QRStatement{}
	st.N0 = N0
	st.h = h
	st.g = g
	return st
}

func NewQRWitness(x *big.Int, x1 *big.Int) *QRWitness {
	ws := &QRWitness{}
	ws.x = x
	ws.x1 = x1
	return ws
}

func qrcommit(st *QRStatement, ws *QRWitness, pp *PwrSecurityPP) *QRProof {
	var err error
	proof := &QRProof{}
	ws.r, err = crypto.Rand(st.N0)
	twosN0 := new(big.Int).Mul(new(big.Int).Exp(crypto.Two, big.NewInt(pp.s), st.N0), st.N0)
	ws.r1, err = crypto.Rand(twosN0)

	proof.a = new(big.Int).Mod(new(big.Int).Mul(ws.r, ws.r), st.N0)
	proof.a1 = new(big.Int).Exp(st.h, ws.r1, st.N0)

	if err != nil {
		panic("ZK QR commit")
	}
	return proof
}

func qrchallenge(proof *QRProof) {
	proof.e = crypto.One
	/*var err error
	proof.e, err = crypto.Rand(crypto.Two)
	if err != nil {
		panic("ZK QR challenge")
	}*/
}

func qrrespond(st *QRStatement, ws *QRWitness, proof *QRProof) {
	proof.z = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(ws.x, proof.e, st.N0), ws.r), st.N0)
	proof.z1 = new(big.Int).Add(new(big.Int).Mul(proof.e, ws.x1), ws.r1)
}

func qrverify(st *QRStatement, proof *QRProof) bool {
	res := true

	left := new(big.Int).Mod(new(big.Int).Mul(proof.z, proof.z), st.N0)

	right := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(st.h, proof.e, st.N0), proof.a), st.N0)

	left1 := new(big.Int).Exp(st.h, proof.z1, st.N0)

	right1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(st.g, proof.e, st.N0), proof.a1), st.N0)

	if left.Cmp(right) != 0 || left1.Cmp(right1) != 0 {
		panic("ZK QR verify fail")
		res = false
	}

	return res
}

func genQRN0StatementAndWit(bits uint) (st *QRStatement, ws *QRWitness) {

	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	p, q := GenPQ(bits)

	// Compute modulus
	n := new(big.Int).Mul(p, q)

	var f, alpha *big.Int

	for f == alpha {
		for range []int{1, 2} {
			go func() {
				value, err := crypto.Rand(n)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				panic("f alphe gen fail")
			}
		}

		f, alpha = <-values, <-values
	}

	// Compute Quadratic Residue generator h1
	h1, err := crypto.Mul(f, f, n)
	h2 := new(big.Int).Exp(h1, alpha, n)

	if err != nil {
		panic("H1 gen fail")
	}
	return NewQRStatement(h1, h2, n), NewQRWitness(f, alpha)
}

func PwrSetUpProve(bits uint) (*PwrSecurityPP, *QRStatement, *QRProof) {
	st, ws := genQRN0StatementAndWit(bits)
	pp := NewSecurityPP(128, 128, 80, st.h, st.g, st.N0)

	proof := qrcommit(st, ws, pp)
	qrchallenge(proof)
	qrrespond(st, ws, proof)
	return pp, st, proof
}

func PwrSetUpVerify(st *QRStatement, proof *QRProof) bool {
	return qrverify(st, proof)
}

func NewSecurityPP(t int64, l int64, s int64, h *big.Int, g *big.Int, N0 *big.Int) *PwrSecurityPP {
	pp := &PwrSecurityPP{}
	pp.t = t
	pp.l = l
	pp.s = s
	pp.h = h
	pp.g = g
	pp.N0 = N0
	return pp
}

func NewPwrStatement(N *big.Int, NN *big.Int, q *big.Int, c *big.Int) *PwrStatement {
	st := &PwrStatement{}
	st.N = N
	st.NN = NN
	st.q = q
	st.c = c
	return st
}

func NewPwrWitness(x *big.Int, r *big.Int) *PwrWitness {
	ws := &PwrWitness{}
	ws.x = x
	ws.r = r
	return ws
}

func PwrCommit(st *PwrStatement, ws *PwrWitness, pp *PwrSecurityPP) *PwrProof {
	var err error
	proof := &PwrProof{}
	ws.r1, err = crypto.Rand(pp.N0)
	twotlN0 := new(big.Int).Mul(new(big.Int).Exp(crypto.Two, big.NewInt(pp.t+pp.l), pp.N0), pp.N0)
	ws.r2, err = crypto.Rand(twotlN0)
	twotlq := new(big.Int).Mul(new(big.Int).Exp(crypto.Two, big.NewInt(pp.t+pp.l), pp.N0), st.q)
	ws.r3, err = crypto.Rand(twotlq)
	ws.r4, err = crypto.Rand(st.N)

	proof.C = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.x, pp.N0), new(big.Int).Exp(pp.h, ws.r1, pp.N0)), pp.N0)

	N_plus_one := new(big.Int).Add(st.N, crypto.One)
	proof.d = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(ws.r4, st.N, st.NN), new(big.Int).Exp(N_plus_one, ws.r3, st.NN)), st.NN)

	proof.D = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.r3, pp.N0), new(big.Int).Exp(pp.h, ws.r2, pp.N0)), pp.N0)

	if err != nil {
		panic("ZK Pwr commit")
	}
	return proof
}

func PwrChallenge(st *PwrStatement, proof *PwrProof, pp *PwrSecurityPP) {
	var err error
	two_t := new(big.Int).Exp(crypto.Two, big.NewInt(pp.t), st.N)
	proof.e, err = crypto.Rand(two_t)
	if err != nil {
		panic("ZK Pwr challenge")
	}
}

func PwrRespond(st *PwrStatement, ws *PwrWitness, proof *PwrProof, pp *PwrSecurityPP) {
	proof.z1 = new(big.Int).Add(ws.r3, new(big.Int).Mul(proof.e, ws.x))
	proof.z2 = new(big.Int).Mod(new(big.Int).Mul(ws.r4, new(big.Int).Exp(ws.r, proof.e, st.N)), st.N)
	proof.z3 = new(big.Int).Add(ws.r2, new(big.Int).Mul(proof.e, ws.r1))
}

func PwrVerify(st *PwrStatement, proof *PwrProof, pp *PwrSecurityPP) bool {
	res := true
	N_plus_one := new(big.Int).Add(st.N, crypto.One)

	left1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(proof.z2, st.N, st.NN), new(big.Int).Exp(N_plus_one, proof.z1, st.NN)), st.NN)

	right1 := new(big.Int).Mod(new(big.Int).Mul(proof.d, new(big.Int).Exp(st.c, proof.e, st.NN)), st.NN)

	left2 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, proof.z1, pp.N0), new(big.Int).Exp(pp.h, proof.z3, pp.N0)), pp.N0)

	right2 := new(big.Int).Mod(new(big.Int).Mul(proof.D, new(big.Int).Exp(proof.C, proof.e, pp.N0)), pp.N0)

	twotq := new(big.Int).Mul(new(big.Int).Exp(crypto.Two, big.NewInt(pp.t), st.q), st.q)

	//twotlq := new(big.Int).Mul(new(big.Int).Exp(crypto.Two, big.NewInt(pp.t+pp.l), st.q), st.q)

	/*if left1.Cmp(right1) != 0 || left2.Cmp(right2) != 0 || proof.z1.Cmp(twotq) == -1 || proof.z1.Cmp(twotlq) == 1 {
		panic("ZK Pwr verify fail")
		res = false
	}*/

	if left1.Cmp(right1) != 0 {
		panic("ZK Pwr verify fail 1")
		res = false
	}
	if left2.Cmp(right2) != 0 {
		panic("ZK Pwr verify fail 2")
		res = false
	}
	if proof.z1.Cmp(twotq) == -1 {
		panic("ZK Pwr verify fail 3")
		res = false
	}
	/*if proof.z1.Cmp(twotlq) == 1 {
		panic("ZK Pwr verify fail 4")
		res = false
	}*/
	return res
}
