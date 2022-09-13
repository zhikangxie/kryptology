package zk_pwr

import (
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	zk_qr "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/qr"
	zk_qrdl "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/qrdl"
	"github.com/gtank/merlin"
)

type PwrSecurityPP struct {
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
}

type PwrProof struct {
	C *big.Int
	d *big.Int
	D *big.Int

	z1 *big.Int
	z2 *big.Int
	z3 *big.Int
	e  *big.Int
}

func NewSecurityPP(h *big.Int, g *big.Int, N0 *big.Int) PwrSecurityPP {
	pp := PwrSecurityPP{}
	pp.h = h
	pp.g = g
	pp.N0 = N0
	return pp
}

func (pp PwrSecurityPP) GetH() *big.Int {
	return pp.h
}

func (pp PwrSecurityPP) GetG() *big.Int {
	return pp.g
}

func (pp PwrSecurityPP) GetN0() *big.Int {
	return pp.N0
}

func NewPwrStatement(N *big.Int, NN *big.Int, q *big.Int, c *big.Int) PwrStatement {
	st := PwrStatement{}
	st.N = N
	st.NN = NN
	st.q = q
	st.c = c
	return st
}

func NewPwrWitness(x *big.Int, r *big.Int) PwrWitness {
	ws := PwrWitness{}
	ws.x = x
	ws.r = r
	return ws
}

func genQRN0StatementAndWit(bits uint) (zk_qr.Statement, zk_qr.Witness, zk_qrdl.Statement, zk_qrdl.Witness, *big.Int) {

	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	p, _ := core.GenerateSafePrime(zk.N_BITS / 2)
	q, _ := core.GenerateSafePrime(zk.N_BITS / 2)

	// Compute modulus
	n := new(big.Int).Mul(p, q)

	var f, alpha *big.Int

	for f == alpha {
		for range []int{1, 2} {
			go func() {
				value, err := core.Rand(n)
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
	h1, err := core.Mul(f, f, n)
	h2 := new(big.Int).Exp(h1, alpha, n)

	if err != nil {
		panic("H1 gen fail")
	}
	return zk_qr.NewStatement(h1), zk_qr.NewWitness(f), zk_qrdl.NewStatement(h2), zk_qrdl.NewWitness(alpha), n
}

func SetUpProve(bits uint) (PwrSecurityPP, zk_qr.Statement, zk_qr.Proof, *zk_qr.Param, zk_qrdl.Statement, zk_qrdl.Proof, *zk_qrdl.Param) {
	qrst, qrws, qrdlst, qrdlws, n := genQRN0StatementAndWit(bits)
	qrpp := zk_qr.NewParam(n)
	pp := NewSecurityPP(qrst.GetStatementH(), qrdlst.GetStatementG(), n)

	qrprover_tx := merlin.NewTranscript("qr")
	qrproof := zk_qr.Prove(qrws, qrst, qrprover_tx, qrpp)

	qrdlpp := zk_qrdl.NewParam(n, qrst.GetStatementH())
	qrdlprover_tx := merlin.NewTranscript("qrdl")
	qrdlproof := zk_qrdl.Prove(qrdlws, qrdlst, qrdlprover_tx, qrdlpp)

	return pp, qrst, qrproof, qrpp, qrdlst, qrdlproof, qrdlpp
}

func SetUpVerify(qrst zk_qr.Statement, qrproof zk_qr.Proof, qrpp *zk_qr.Param, qrdlst zk_qrdl.Statement, qrdlproof zk_qrdl.Proof, qrdlpp *zk_qrdl.Param) bool {
	qrverifier_tx := merlin.NewTranscript("qr")

	qrdlverifier_tx := merlin.NewTranscript("qrdl")

	return zk_qr.Verify(qrst, qrproof, qrverifier_tx, qrpp) && zk_qrdl.Verify(qrdlst, qrdlproof, qrdlverifier_tx, qrdlpp)
}

func Prove(ws PwrWitness, st PwrStatement, pp PwrSecurityPP) PwrProof {
	tx := merlin.NewTranscript("pwr")
	proof := PwrProof{}
	r1, _ := core.Rand(pp.N0)
	r2, _ := core.Rand(new(big.Int).Lsh(pp.N0, zk.T+zk.L))
	r3, _ := core.Rand(new(big.Int).Lsh(st.q, zk.T+zk.L))
	r4, _ := core.Rand(st.N)

	proof.C = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, ws.x, pp.N0), new(big.Int).Exp(pp.h, r1, pp.N0)), pp.N0)
	tx.AppendMessage([]byte("C"), proof.C.Bytes())
	N_plus_one := new(big.Int).Add(st.N, core.One)
	proof.d = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(r4, st.N, st.NN), new(big.Int).Exp(N_plus_one, r3, st.NN)), st.NN)
	tx.AppendMessage([]byte("d"), proof.d.Bytes())
	proof.D = new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, r3, pp.N0), new(big.Int).Exp(pp.h, r2, pp.N0)), pp.N0)
	tx.AppendMessage([]byte("D"), proof.D.Bytes())

	proof.e = new(big.Int).SetBytes(tx.ExtractBytes([]byte("e"), zk.T/8))

	proof.z1 = new(big.Int).Add(r3, new(big.Int).Mul(proof.e, ws.x))
	proof.z2 = new(big.Int).Mod(new(big.Int).Mul(r4, new(big.Int).Exp(ws.r, proof.e, st.N)), st.N)
	proof.z3 = new(big.Int).Add(r2, new(big.Int).Mul(proof.e, r1))

	return proof
}

func Verify(st PwrStatement, proof PwrProof, pp PwrSecurityPP) bool {
	res := true
	N_plus_one := new(big.Int).Add(st.N, core.One)

	left1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(proof.z2, st.N, st.NN), new(big.Int).Exp(N_plus_one, proof.z1, st.NN)), st.NN)

	right1 := new(big.Int).Mod(new(big.Int).Mul(proof.d, new(big.Int).Exp(st.c, proof.e, st.NN)), st.NN)

	left2 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Exp(pp.g, proof.z1, pp.N0), new(big.Int).Exp(pp.h, proof.z3, pp.N0)), pp.N0)

	right2 := new(big.Int).Mod(new(big.Int).Mul(proof.D, new(big.Int).Exp(proof.C, proof.e, pp.N0)), pp.N0)

	if left1.Cmp(right1) != 0 {
		panic("ZK Pwr verify fail 1")
		res = false
	}
	if left2.Cmp(right2) != 0 {
		panic("ZK Pwr verify fail 2")
		res = false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(st.q, zk.T)) == -1 {
		panic("ZK Pwr verify fail 3")
		res = false
	}
	if proof.z1.Cmp(new(big.Int).Lsh(st.q, zk.T+zk.L)) != -1 {
		panic("ZK Pwr verify fail 4")
		res = false
	}
	return res
}
