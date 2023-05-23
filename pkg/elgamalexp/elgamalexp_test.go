package elgamalexp

import (
	"crypto/rand"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestElGamalExpOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for i, curve := range curveInstances {
		basePoint := curve.Point.Random(rand.Reader)
		semiDecryptor := NewSemiDecryptor(curve, basePoint)
		encryptor := NewEncryptor(curve, basePoint, semiDecryptor.T)

		message := curve.Scalar.Random(rand.Reader)
		randomness := curve.Scalar.Random(rand.Reader)
		ciphertext := encryptor.Encrypt(message, randomness)

		semiMessage := semiDecryptor.SemiDecrypt(ciphertext)

		err := Compare(basePoint, message, semiMessage)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}

func TestElGamalExpReRandomizeOverMultipleCurves(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for i, curve := range curveInstances {
		basePoint := curve.Point.Random(rand.Reader)
		semiDecryptor := NewSemiDecryptor(curve, basePoint)
		encryptor := NewEncryptor(curve, basePoint, semiDecryptor.T)

		message := curve.Scalar.Random(rand.Reader)
		randomness := curve.Scalar.Random(rand.Reader)
		ciphertext := encryptor.Encrypt(message, randomness)

		s := curve.Scalar.Random(rand.Reader)
		r := curve.Scalar.Random(rand.Reader)
		newCiphertext := encryptor.ReRandomize(ciphertext, s, r)

		semiNewMessage := semiDecryptor.SemiDecrypt(newCiphertext)

		err := Compare(basePoint, message.Mul(s), semiNewMessage)
		require.NoError(t, err, fmt.Sprintf("failed in curve %d", i))
	}
}
