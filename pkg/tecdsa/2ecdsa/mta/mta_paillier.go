package mta

import (
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk"
	zk_pwr "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/pwr"
	zk_qr "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/qr"
	zk_qrdl "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/qrdl"
	zk_raffran "github.com/coinbase/kryptology/pkg/tecdsa/2ecdsa/mta/zk/raffran"
)

type MTAPaillierSender struct {
	pk       *paillier.PublicKey
	modst    *zk.ModStatement
	modproof *zk.ModProof
}

type MTAPaillierReceiver struct {
	pk    *paillier.PublicKey
	sk    *paillier.SecretKey
	modws *zk.ModWitness
	p     *big.Int
	q     *big.Int
}

type MultiplyRound1Output struct {
	cb       *big.Int
	pwrst    zk_pwr.PwrStatement
	pwrproof zk_pwr.PwrProof
	pwrpp    zk_pwr.PwrSecurityPP
	q        *big.Int
	p        *big.Int
}

type MultiplyRound2Output struct {
	ca          *big.Int
	affranst    zk_raffran.AffranStatement
	affranproof zk_raffran.AffranProof
	pwrpp       zk_pwr.PwrSecurityPP
}

func NewMultiplySender(pk *paillier.PublicKey, modst *zk.ModStatement, modproof *zk.ModProof) *MTAPaillierSender {
	return &MTAPaillierSender{
		pk:       pk,
		modst:    modst,
		modproof: modproof,
	}
}

func NewMultiplyReceiver(pk *paillier.PublicKey, sk *paillier.SecretKey, modws *zk.ModWitness, p *big.Int, q *big.Int) *MTAPaillierReceiver {
	return &MTAPaillierReceiver{
		pk:    pk,
		sk:    sk,
		modws: modws,
		p:     p,
		q:     q,
	}
}

func KeyGenProve(bits uint) (*MTAPaillierSender, *MTAPaillierReceiver, *big.Int) {
	p, q := zk.GenPQ(bits)
	sk, _ := paillier.NewSecretKey(p, q)
	pk := &sk.PublicKey

	st := zk.NewRPStatement(pk.N)
	ws := zk.NewRPWitness(p, q)

	proof := zk.RPProve(st, ws)

	return NewMultiplySender(pk, st, proof), NewMultiplyReceiver(pk, sk, ws, p, q), q
}

func (sender *MTAPaillierSender) KeyGenVerify() bool {
	return zk.RPVerify(sender.modst, sender.modproof)
}

func (sender *MTAPaillierSender) Init_setup() (zk_pwr.PwrSecurityPP, zk_qr.Statement, zk_qr.Proof, *zk_qr.Param, zk_qrdl.Statement, zk_qrdl.Proof, *zk_qrdl.Param) {
	return zk_pwr.SetUpProve(128)
}

func (receiver *MTAPaillierReceiver) Init_setup(qrst zk_qr.Statement, qrproof zk_qr.Proof, qrpp *zk_qr.Param, qrdlst zk_qrdl.Statement, qrdlproof zk_qrdl.Proof, qrdlpp *zk_qrdl.Param) {
	res := zk_pwr.SetUpVerify(qrst, qrproof, qrpp, qrdlst, qrdlproof, qrdlpp)
	if res != true {
		panic("Init setup failed")
	}
}

func (receiver *MTAPaillierReceiver) Init(pwrpp zk_pwr.PwrSecurityPP, b *big.Int) *MultiplyRound1Output {
	var err error
	var r *big.Int
	round1Output := &MultiplyRound1Output{}
	round1Output.cb, r, err = receiver.pk.Encrypt(b)
	round1Output.pwrst = zk_pwr.NewPwrStatement(receiver.pk.N, receiver.pk.N2, receiver.q, round1Output.cb)
	pwrws := zk_pwr.NewPwrWitness(b, r)
	round1Output.pwrproof = zk_pwr.Prove(pwrws, round1Output.pwrst, pwrpp)

	round1Output.pwrpp = pwrpp
	round1Output.q = receiver.q
	round1Output.p = receiver.p

	if err != nil {
		panic("MtA Paillier init")
	}
	return round1Output
}

func (sender *MTAPaillierSender) Update(pwrpp zk_pwr.PwrSecurityPP, a *big.Int, round1Output *MultiplyRound1Output) (*big.Int, *MultiplyRound2Output) {
	var err error

	res := zk_pwr.Verify(round1Output.pwrst, round1Output.pwrproof, round1Output.pwrpp)
	if res != true {
		panic("Sender verify pwr proof failed")
	}

	//k := new(big.Int).Lsh(new(big.Int).Mul(round1Output.q, round1Output.q), t+l+s)
	var cipher_alpha_hat paillier.Ciphertext
	round2Output := &MultiplyRound2Output{}
	hatalpha, err := core.Rand(sender.pk.N)
	alpha := new(big.Int).Mul(hatalpha, big.NewInt(-1))
	N_plus_1 := new(big.Int).Add(sender.pk.N, big.NewInt(1))
	c := new(big.Int).Mod(new(big.Int).Mul(round1Output.cb, new(big.Int).Exp(N_plus_1, new(big.Int).Lsh(round1Output.q, zk.T+zk.L), sender.pk.N2)), sender.pk.N2)
	round2Output.ca = new(big.Int).Exp(c, a, sender.pk.N2) //cb^a mod N^2
	cipher_alpha_hat = new(big.Int).Mod(new(big.Int).Exp(N_plus_1, hatalpha, sender.pk.N2), sender.pk.N2)
	round2Output.ca, err = core.Mul(round2Output.ca, cipher_alpha_hat, sender.pk.N2)
	round2Output.affranst = zk_raffran.NewAffranStatement(sender.pk.N2, sender.pk.N, round1Output.q, round2Output.ca, round1Output.cb)
	affranws := zk_raffran.NewAffranWitness(a, hatalpha)
	round2Output.affranproof = zk_raffran.Prove(affranws, round2Output.affranst, pwrpp)

	round2Output.pwrpp = pwrpp

	if err != nil {
		panic(err)
	}

	return alpha, round2Output
}

func (receiver *MTAPaillierReceiver) Multiply(round2Output *MultiplyRound2Output) *big.Int {
	//var err error
	res := zk_raffran.Verify(round2Output.affranst, round2Output.affranproof, round2Output.pwrpp)
	if res != true {
		panic("Sender verify affran proof failed")
	}

	beta, err := receiver.sk.Decrypt(round2Output.ca)

	if err != nil {
		panic("MtA Paillier multiply")
	}

	return beta
}
