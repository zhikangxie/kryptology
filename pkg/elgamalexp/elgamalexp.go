package elgamalexp

import (
	"crypto/rand"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type SemiDecryptor struct {
	curve     *curves.Curve
	basePoint curves.Point
	T         curves.Point
	d         curves.Scalar
}

type Encryptor struct {
	curve     *curves.Curve
	basePoint curves.Point
	T         curves.Point
}

type Ciphertext struct {
	U curves.Point
	V curves.Point
}

func KeyGen(curve *curves.Curve, basePoint curves.Point) (curves.Point, curves.Scalar) {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}

	d := curve.Scalar.Random(rand.Reader)
	T := basePoint.Mul(d)

	return T, d
}

func NewSemiDecryptor(curve *curves.Curve, basePoint curves.Point, T curves.Point, d curves.Scalar) *SemiDecryptor {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}

	return &SemiDecryptor{
		curve:     curve,
		basePoint: basePoint,
		T:         T,
		d:         d,
	}
}

func NewEncryptor(curve *curves.Curve, basePoint curves.Point, T curves.Point) *Encryptor {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}

	return &Encryptor{
		curve:     curve,
		basePoint: basePoint,
		T:         T,
	}
}

func NewCiphertext(U curves.Point, V curves.Point) *Ciphertext {
	return &Ciphertext{
		U: U,
		V: V,
	}
}

func (encryptor *Encryptor) Encrypt(m curves.Scalar, r curves.Scalar) *Ciphertext {
	return &Ciphertext{
		U: encryptor.basePoint.Mul(r),
		V: encryptor.T.Mul(r).Add(encryptor.basePoint.Mul(m)),
	}
}

func (encryptor *Encryptor) ReRandomize(ciphertext *Ciphertext, s curves.Scalar, r curves.Scalar) *Ciphertext {
	return &Ciphertext{
		U: ciphertext.U.Mul(s).Add(encryptor.basePoint.Mul(r)),
		V: ciphertext.V.Mul(s).Add(encryptor.T.Mul(r)),
	}
}

func (semiDecryptor *SemiDecryptor) SemiDecrypt(ciphertext *Ciphertext) curves.Point {
	return ciphertext.V.Sub(ciphertext.U.Mul(semiDecryptor.d))
}

func Compare(curve *curves.Curve, basePoint curves.Point, m curves.Scalar, semiM curves.Point) error {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}
	if !semiM.Equal(basePoint.Mul(m)) {
		return fmt.Errorf("failed when comparing semi decryption result with original message")
	}
	return nil
}
