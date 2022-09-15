package mta_paillier

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/paillier"
)

var	p, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
var	q, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
var	p0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)
var	q0, _ = core.GenerateSafePrime(paillier.PaillierPrimeBits)

func TestMtAPaillier(t *testing.T) {
	curve := curves.K256()

	sender := NewSender(curve, p, q)
	receiver := NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	round1Output := receiver.Init(beta)
	ta, round2Output := sender.Update(alpha, round1Output)
	tb := receiver.Multiply(round2Output)

	require.Equal(t, alpha.Mul(beta), ta.Add(tb))
}

func BenchmarkMtAPaillierSetup(b *testing.B) {
	curve := curves.K256()

	sender := NewSender(curve, p, q)
	receiver := NewReceiver(curve, p0, q0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		setup1Statement, setup1Proof := receiver.SetupInit()
		setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
		receiver.SetupDone(setup2Statement, setup2Proof)
	}
}

func BenchmarkMtAPaillierMain(b *testing.B) {
	curve := curves.K256()

	sender := NewSender(curve, p, q)
	receiver := NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		round1Output := receiver.Init(beta)
		_, round2Output := sender.Update(alpha, round1Output)
		receiver.Multiply(round2Output)
	}
}

func BenchmarkMtAPaillierStep1(b *testing.B) {
	curve := curves.K256()

	sender := NewSender(curve, p, q)
	receiver := NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	beta := curve.Scalar.Random(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		receiver.Init(beta)
	}
}

func BenchmarkMtAPaillierStep2(b *testing.B) {
	curve := curves.K256()

	sender := NewSender(curve, p, q)
	receiver := NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		round1Output := receiver.Init(beta)
		b.StartTimer()
		_, round2Output := sender.Update(alpha, round1Output)
		b.StopTimer()
		receiver.Multiply(round2Output)
	}
}

func BenchmarkMtAPaillierStep3(b *testing.B) {
	curve := curves.K256()

	sender := NewSender(curve, p, q)
	receiver := NewReceiver(curve, p0, q0)

	setup1Statement, setup1Proof := receiver.SetupInit()
	setup2Statement, setup2Proof := sender.SetupUpdate(setup1Statement, setup1Proof)
	receiver.SetupDone(setup2Statement, setup2Proof)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		round1Output := receiver.Init(beta)
		_, round2Output := sender.Update(alpha, round1Output)
		b.StartTimer()
		receiver.Multiply(round2Output)
	}
}
