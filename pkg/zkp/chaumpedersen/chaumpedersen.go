package chaumpedersen

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

type Commitment = []byte

type Prover struct {
	curve           *curves.Curve
	basePoint1      curves.Point
	basePoint2      curves.Point
	uniqueSessionId []byte
}

type Proof struct {
	C          curves.Scalar
	S          curves.Scalar
	Statement1 curves.Point
	Statement2 curves.Point
}

// we allow basePoint1 to be nil, in which case it is auto-assigned to be the group's default generator
// we do NOT allow basePoint2 to be nil

func NewProver(curve *curves.Curve, basePoint1 curves.Point, basePoint2 curves.Point, uniqueSessionId []byte) (*Prover, error) {
	if basePoint1 == nil {
		basePoint1 = curve.NewGeneratorPoint()
	}
	if basePoint2 == nil {
		return nil, fmt.Errorf("base point 2 missing")
	}
	return &Prover{
		curve:           curve,
		basePoint1:      basePoint1,
		basePoint2:      basePoint2,
		uniqueSessionId: uniqueSessionId,
	}, nil
}

func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	var err error
	result := &Proof{}
	result.Statement1 = p.basePoint1.Mul(x)
	result.Statement2 = p.basePoint2.Mul(x)

	// commit
	k := p.curve.Scalar.Random(rand.Reader)
	K1 := p.basePoint1.Mul(k)
	K2 := p.basePoint2.Mul(k)

	// challenge
	hash := sha3.New256()
	if _, err = hash.Write(p.uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "writing salt to hash in chaum-pedersen prove")
	}
	if _, err = hash.Write(p.basePoint1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint1 to hash in chaum-pedersen prove")
	}
	if _, err = hash.Write(p.basePoint2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing basePoint2 to hash in chaum-pedersen prove")
	}
	if _, err = hash.Write(result.Statement1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement1 to hash in chaum-pedersen prove")
	}
	if _, err = hash.Write(result.Statement2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing statement2 to hash in chaum-pedersen prove")
	}
	if _, err = hash.Write(K1.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K1 to hash in chaum-pedersen prove")
	}
	if _, err = hash.Write(K2.ToAffineCompressed()); err != nil {
		return nil, errors.Wrap(err, "writing point K2 to hash in chaum-pedersen prove")
	}
	result.C, err = p.curve.Scalar.SetBytes(hash.Sum(nil))
	if err != nil {
		return nil, errors.Wrap(err, "generating challenge in chaum-pedersen prove")
	}

	// response
	result.S = result.C.Mul(x).Add(k)

	return result, nil
}

// we allow basePoint1 to be nil, in which case it is auto-assigned to be the group's default generator
// we do NOT allow basePoint2 to be nil

func Verify(proof *Proof, curve *curves.Curve, basePoint1 curves.Point, basePoint2 curves.Point, uniqueSessionId []byte) error {
	if basePoint1 == nil {
		basePoint1 = curve.NewGeneratorPoint()
	}
	if basePoint2 == nil {
		return fmt.Errorf("base point 2 missing")
	}
	var err error

	sBp1 := basePoint1.Mul(proof.S)
	sBp2 := basePoint2.Mul(proof.S)

	negCSta1 := proof.Statement1.Mul(proof.C.Neg())
	negCSta2 := proof.Statement2.Mul(proof.C.Neg())

	K1 := sBp1.Add(negCSta1)
	K2 := sBp2.Add(negCSta2)

	hash := sha3.New256()
	if _, err = hash.Write(uniqueSessionId); err != nil {
		return errors.Wrap(err, "writing salt to hash in chaum-pedersen verify")
	}
	if _, err = hash.Write(basePoint1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing basePoint1 to hash in chaum-pedersen verify")
	}
	if _, err = hash.Write(basePoint2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing basePoint2 to hash in chaum-pedersen verify")
	}
	if _, err = hash.Write(proof.Statement1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing statement1 to hash in chaum-pedersen verify")
	}
	if _, err = hash.Write(proof.Statement2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing statement2 to hash in chaum-pedersen verify")
	}
	if _, err = hash.Write(K1.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point K1 to hash in chaum-pedersen verify")
	}
	if _, err = hash.Write(K2.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "writing point K2 to hash in chaum-pedersen verify")
	}
	if subtle.ConstantTimeCompare(proof.C.Bytes(), hash.Sum(nil)) != 1 {
		return fmt.Errorf("chaum-pedersen verification failed")
	}
	return nil
}
