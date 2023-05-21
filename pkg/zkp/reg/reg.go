package reg

import (
	"crypto/rand"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

type Prover struct {
	curve           *curves.Curve
	basePoint       curves.Point
	ek              curves.Point
	uniqueSessionId []byte
}

type Proof struct {
	e  curves.Scalar
	z1 curves.Scalar
	z2 curves.Scalar
	A  curves.Point
	B  curves.Point
}

func NewProver(curve *curves.Curve, basePoint curves.Point, ek curves.Point, uniqueSessionId []byte) (*Prover, error) {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}
	if ek == nil {
		return nil, fmt.Errorf("encryption key missing")
	}

	return &Prover{
		curve:           curve,
		basePoint:       basePoint,
		ek:              ek,
		uniqueSessionId: uniqueSessionId,
	}, nil
}

func (p *Prover) Prove(m curves.Scalar, r curves.Scalar) (*Proof, error) {
	var err error
	result := &Proof{}

	// compute statement
	result.A = p.basePoint.Mul(r)
	result.B = p.ek.Mul(r).Add(p.basePoint.Mul(m))

	// compute commitment
	alpha := p.curve.Scalar.Random(rand.Reader)
	beta := p.curve.Scalar.Random(rand.Reader)
	Y1 := p.basePoint.Mul(beta)
	Y2 := p.ek.Mul(beta).Add(p.basePoint.Mul(alpha))

	// compute challenge
	hash := sha3.New256()
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in elgamal encryption relation proof")
	}
	if _, err = hash.Write(p.basePoint.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing base point to hash in elgamal encryption relation proof")
	}
	if _, err = hash.Write(p.ek.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing encryption key to hash in elgamal encryption relation proof")
	}
	if _, err = hash.Write(result.A.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing A (first part of statement) to hash in elgamal encryption relation proof")
	}
	if _, err = hash.Write(result.B.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing B (second part of statement) to hash in elgamal encryption relation proof")
	}
	if _, err = hash.Write(Y1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point Y1 to hash in elgamal encryption relation proof")
	}
	if _, err = hash.Write(Y2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point Y2 to hash in elgamal encryption relation proof")
	}
	result.e, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "generating challenge in elgamal encryption relation proof")
	}

	// compute response
	result.z1 = beta.Add(result.e.Mul(r))
	result.z2 = alpha.Add(result.e.Mul(m))

	return result, nil
}

func Verify(proof *Proof, curve *curves.Curve, basePoint curves.Point, ek curves.Point, uniqueSessionId []byte) error {
	if basePoint == nil {
		basePoint = curve.NewGeneratorPoint()
	}
	if ek == nil {
		return fmt.Errorf("encryption key missing")
	}
	var err error

	// compute commitment
	Y1 := basePoint.Mul(proof.z1).Sub(proof.A.Mul(proof.e))
	Y2 := ek.Mul(proof.z1).Add(basePoint.Mul(proof.z2)).Sub(proof.B.Mul(proof.e))

	// compute challenge
	hash := sha3.New256()
	if _, err = hash.Write(uniqueSessionId); err != nil {
		return errors.Wrap(err, "writing salt to hash in elgamal encryption relation verification")
	}
	if _, err = hash.Write(basePoint.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing base point to hash in elgamal encryption relation verification")
	}
	if _, err = hash.Write(ek.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing encryption key to hash in elgamal encryption relation verification")
	}
	if _, err = hash.Write(proof.A.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing A (first part of statement) to hash in elgamal encryption relation verification")
	}
	if _, err = hash.Write(proof.B.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing B (second part of statement) to hash in elgamal encryption relation verification")
	}
	if _, err = hash.Write(Y1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point Y1 to hash in elgamal encryption relation verification")
	}
	if _, err = hash.Write(Y2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point Y2 to hash in elgamal encryption relation verification")
	}
	e, err := curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return errors.Wrap(err, "generating challenge in elgamal encryption relation verification")
	}

	// compare challenge
	if e.Cmp(proof.e) != 0 {
		return fmt.Errorf("elgamal encryption relation verification failed")
	}
	return nil
}
