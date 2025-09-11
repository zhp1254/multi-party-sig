package curve

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/agl/ed25519/edwards25519"
	"github.com/cronokirby/saferith"
	"github.com/decred/dcrd/dcrec/edwards"
	"math/big"
)

var edwardsCurve *edwards.TwistedEdwardsCurve
var edwardsHalfN *big.Int
var edwardsOrder *saferith.Modulus

func init() {
	edwardsCurve = edwards.Edwards()
	edwardsHalfN = new(big.Int).Rsh(edwardsCurve.N, 1)

	orderNat, _ := new(saferith.Nat).SetHex("EDD3F55C1A631258D69CF7A2DEF9DE1400000000000000000000000000000010")
	edwardsOrder = saferith.ModulusFromNat(orderNat)
}

func EdwardsInstance() *edwards.TwistedEdwardsCurve {
	return edwardsCurve
}

type TwistedEdwardsCurve struct {
}

func (TwistedEdwardsCurve) NewPoint() Point {
	p := new(TwistedEdwardsPoint)
	p.X, p.Y = new(big.Int),new(big.Int)
	return p
}

func (TwistedEdwardsCurve) NewBasePoint() Point {
	return &TwistedEdwardsPoint{
		X: new(big.Int).SetBytes(edwardsCurve.Gx.Bytes()),
		Y: new(big.Int).SetBytes(edwardsCurve.Gy.Bytes()),
	}
}

func (TwistedEdwardsCurve) NewScalar() Scalar {
	return &TwistedEdwardsScalar{
		value: new(big.Int),
	}
}

func (TwistedEdwardsCurve) ScalarBits() int {
	return edwardsCurve.BitSize
}

func (TwistedEdwardsCurve) SafeScalarBytes() int {
	return edwardsCurve.N.BitLen()
}

func (TwistedEdwardsCurve) Order() *saferith.Modulus {
	return edwardsOrder
}

func (TwistedEdwardsCurve) LiftX(data []byte) (*TwistedEdwardsPoint, error) {
	return nil, errors.New("unsupport LiftX")
}

func (TwistedEdwardsCurve) Name() string {
	return "edwards25519"
}

type TwistedEdwardsScalar struct {
	value *big.Int
}

func twistedEdwardsScalar(generic Scalar) *TwistedEdwardsScalar {
	out, ok := generic.(*TwistedEdwardsScalar)
	if !ok {
		panic(fmt.Sprintf("failed to convert to TwistedEdwardsScalar: %v", generic))
	}
	return out
}

func (*TwistedEdwardsScalar) Curve() Curve {
	return TwistedEdwardsCurve{}
}

func (s *TwistedEdwardsScalar) String() string {
	return hex.EncodeToString(s.value.Bytes())
}

func (s *TwistedEdwardsScalar) MarshalBinary() ([]byte, error) {
	if s.value == nil {
		return nil, nil
	}
	/*data := edwards.BigIntToEncodedBytes(s.value)
	return data[:], nil*/
	return s.value.Bytes(), nil
}

func (s *TwistedEdwardsScalar) UnmarshalBinary(data []byte) error {
	/*if len(data) != 32 {
		return fmt.Errorf("invalid length for TwistedEdwardsScalar scalar: %d", len(data))
	}
	var exactData [32]byte
	copy(exactData[:], data)
	s.value = edwards.EncodedBytesToBigInt(&exactData)
	return nil*/

	s.value = new(big.Int).SetBytes(data)
	return nil
}

func (s *TwistedEdwardsScalar) Add(that Scalar) Scalar {
	other := twistedEdwardsScalar(that)
	if s.value == nil {
		s.value = new(big.Int)
	}

	s.value.Add(s.value, other.value)
	s.value.Mod(s.value, edwardsCurve.N)
	return s
}

func (s *TwistedEdwardsScalar) Sub(that Scalar) Scalar {
	other := twistedEdwardsScalar(that)
	if s.value == nil {
		s.value = new(big.Int)
	}
	s.value.Sub(s.value, other.value)
	return s
}

func (s *TwistedEdwardsScalar) Mul(that Scalar) Scalar {
	other := twistedEdwardsScalar(that)

	if s.value == nil {
		s.value = new(big.Int)
	}

	s.value.Mul(s.value, other.value)
	s.value.Mod(s.value, edwardsCurve.N)
	return s
}

func (s *TwistedEdwardsScalar) Invert() Scalar {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(edwardsCurve.N, two)
	s.value = new(big.Int).Exp(s.value, nMinus2, edwardsCurve.N)
	return s
}

func (s *TwistedEdwardsScalar) Negate() Scalar {
	s.value = new(big.Int).Neg(s.value)
	return s
}

func (s *TwistedEdwardsScalar) IsOverHalfOrder() bool {
	return s.value.Cmp(edwardsHalfN) >= 0
}

func (s *TwistedEdwardsScalar) Equal(that Scalar) bool {
	other := twistedEdwardsScalar(that)
	return other.value.Cmp(s.value) == 0
}

func (s *TwistedEdwardsScalar) IsZero() bool {
	return s.value.Cmp(new(big.Int).SetInt64(0)) == 0
}

func (s *TwistedEdwardsScalar) Set(that Scalar) Scalar {
	other := twistedEdwardsScalar(that)
	s.value = new(big.Int).SetBytes(other.value.Bytes())
	return s
}

func (s *TwistedEdwardsScalar) SetNat(x *saferith.Nat) Scalar {
	reduced := new(big.Int).Mod(x.Big(), edwardsCurve.N)
	s.value = new(big.Int).SetBytes(reduced.Bytes())
	return s
}

func (s *TwistedEdwardsScalar) Act(that Point) Point {
	other := twistedEdwardsCastPoint(that)
	out := new(TwistedEdwardsPoint)

	zero := new(big.Int)
	if other.X.Cmp(zero) == 0 && other.Y.Cmp(zero) == 0 {
		out.X, out.Y = new(big.Int), new(big.Int)
		return out
	}

	out.X, out.Y = edwardsCurve.ScalarMult(other.X, other.Y, s.value.Bytes())
	return out
}

func (s *TwistedEdwardsScalar) ActOnBase() Point {
	x, y := edwardsCurve.ScalarBaseMult(s.value.Bytes())
	return &TwistedEdwardsPoint{
		x, y,
	}
}

type TwistedEdwardsPoint struct {
	X, Y *big.Int
}

func twistedEdwardsCastPoint(generic Point) *TwistedEdwardsPoint {
	out, ok := generic.(*TwistedEdwardsPoint)
	if !ok {
		panic(fmt.Sprintf("failed to convert to TwistedEdwardsPoint: %v", generic))
	}
	return out
}

func (*TwistedEdwardsPoint) Curve() Curve {
	return TwistedEdwardsCurve{}
}

func (p *TwistedEdwardsPoint) MarshalBinary() ([]byte, error) {
	return edwards.Marshal(*edwardsCurve, p.X, p.Y)[:], nil
}

func (p *TwistedEdwardsPoint) UnmarshalBinary(data []byte) error {
	p.X, p.Y = edwards.Unmarshal(edwardsCurve, data)
	return nil
}

func (p *TwistedEdwardsPoint) Add(that Point) Point {
	other := twistedEdwardsCastPoint(that)
	var out TwistedEdwardsPoint

	zero := new(big.Int)
	if zero.Cmp(p.X) == 0 && zero.Cmp(p.Y) == 0 {
		out.X, out.Y = new(big.Int).SetBytes(other.X.Bytes()),new(big.Int).SetBytes(other.Y.Bytes())
	} else if zero.Cmp(other.X) == 0 && zero.Cmp(other.Y) == 0 {
		out.X, out.Y = new(big.Int).SetBytes(p.X.Bytes()),new(big.Int).SetBytes(p.Y.Bytes())
	} else {
		out.X, out.Y = edwardsCurve.Add(p.X, p.Y, other.X, other.Y)
	}
	return &out
}

func (p *TwistedEdwardsPoint) Sub(that Point) Point {
	return p.Add(that.Negate())
}

func (p *TwistedEdwardsPoint) Set(that Point) Point {
	other := twistedEdwardsCastPoint(that)
	p.X = new(big.Int).SetBytes(other.X.Bytes())
	p.Y = new(big.Int).SetBytes(other.Y.Bytes())
	return p
}

//Negate https://blog.csdn.net/mutourend/article/details/98742544
func (p *TwistedEdwardsPoint) Negate() Point {
	a := edwards.BigIntPointToEncodedBytes(p.X, p.Y)
	aEGE := new(edwards25519.ExtendedGroupElement)
	aEGE.FromBytes(a)

	var negX edwards25519.FieldElement
	var negT edwards25519.FieldElement
	edwards25519.FeNeg(&negX, &aEGE.X)
	edwards25519.FeNeg(&negT, &aEGE.T)

	bEGE := new(edwards25519.ExtendedGroupElement)
	bEGE.T = negT
	bEGE.X = negX
	edwards25519.FeCopy(&bEGE.Y, &aEGE.Y)
	edwards25519.FeCopy(&bEGE.Z, &aEGE.Z)

	var newPoint [32]byte
	bEGE.ToBytes(&newPoint)
	var out TwistedEdwardsPoint
	_ = out.UnmarshalBinary(newPoint[:])
	return &out
}

func (p *TwistedEdwardsPoint) Equal(that Point) bool {
	if p == nil || that == nil {
		return false
	}
	other := twistedEdwardsCastPoint(that)
	return other.X.Cmp(p.X) == 0 && other.Y.Cmp(p.Y) == 0
}

func (p *TwistedEdwardsPoint) IsIdentity() bool {
	zero := big.NewInt(0)
	return p == nil || (zero.Cmp(p.X) == 0 && zero.Cmp(p.Y) == 0)
}

func (p *TwistedEdwardsPoint) HasEvenY() bool {
	return false
}

func (p *TwistedEdwardsPoint) XScalar() Scalar {
	//xi := edwards.BigIntToEncodedBytes(p.X)
	out := new(TwistedEdwardsScalar)
	out.value = new(big.Int).SetBytes(p.X.Bytes())
	return out
}

func (p *TwistedEdwardsPoint) String() string {
	s := edwards.BigIntPointToEncodedBytes(p.X, p.Y)
	return hex.EncodeToString(s[:])
}
