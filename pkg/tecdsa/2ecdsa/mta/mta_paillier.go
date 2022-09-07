package mta

import (
	"math/big"

	"github.com/coinbase/kryptology/pkg/paillier"

	crypto "github.com/coinbase/kryptology/pkg/core"
)

type MTAPaillierSender struct {
	pk *paillier.PublicKey
}

type MTAPaillierReceiver struct {
	pk *paillier.PublicKey
	sk *paillier.SecretKey
}

type MultiplyRound1Output struct {
	cb *big.Int
}

type MultiplyRound2Output struct {
	ca *big.Int
}

func NewMultiplySender(pk *paillier.PublicKey) (*MTAPaillierSender, error) {
	return &MTAPaillierSender{
		pk: pk,
	}, nil
}

func NewMultiplyReceiver(pk *paillier.PublicKey, sk *paillier.SecretKey) (*MTAPaillierReceiver, error) {
	return &MTAPaillierReceiver{
		pk: pk,
		sk: sk,
	}, nil
}

func (receiver *MTAPaillierReceiver) init(b *big.Int) *MultiplyRound1Output {
	var err error
	round1Output := &MultiplyRound1Output{}
	round1Output.cb, _, err = receiver.pk.Encrypt(b)
	if err != nil {
		panic("MtA Paillier init")
	}
	return round1Output
}

func (sender *MTAPaillierSender) update(a *big.Int, round1Output *MultiplyRound1Output) (*big.Int, *MultiplyRound2Output) {
	var cipher_alpha_hat paillier.Ciphertext

	round2Output := &MultiplyRound2Output{}

	hatalpha, err := crypto.Rand(sender.pk.N)

	alpha := new(big.Int).Mul(hatalpha, big.NewInt(-1))

	round2Output.ca = new(big.Int).Exp(round1Output.cb, a, sender.pk.N2) //cb^a mod N^2

	cipher_alpha_hat, _, err = sender.pk.Encrypt(hatalpha)

	round2Output.ca, err = crypto.Mul(round2Output.ca, cipher_alpha_hat, sender.pk.N2)

	if err != nil {
		panic("MtA Paillier update")
	}

	return alpha, round2Output
}

func (receiver *MTAPaillierReceiver) multiply(round2Output *MultiplyRound2Output) *big.Int {
	//var err error

	beta, err := receiver.sk.Decrypt(round2Output.ca)

	if err != nil {
		panic("MtA Paillier multiply")
	}

	return beta
}
