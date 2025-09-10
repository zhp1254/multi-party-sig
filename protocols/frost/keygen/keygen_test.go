package keygen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

func checkOutput(t *testing.T, rounds []round.Session, parties party.IDSlice) {
	group := curve.TwistedEdwardsCurve{}

	N := len(rounds)
	results := make([]Config, 0, N)
	for _, r := range rounds {
		resultRound, ok := r.(*round.Output)
		require.True(t, ok)
		result, ok := resultRound.Result.(*Config)
		require.True(t, ok)
		results = append(results, *result)
		require.Equal(t, r.SelfID(), result.ID)
	}

	var publicKey curve.Point
	var chainKey []byte
	privateKey := group.NewScalar()
	lagrangeCoefficients := polynomial.Lagrange(group, parties)
	for _, result := range results {
		if publicKey != nil {
			assert.True(t, publicKey.Equal(result.PublicKey), "different public key")
		}
		publicKey = result.PublicKey
		if chainKey != nil {
			assert.Equal(t, chainKey, result.ChainKey, "different chain key")
		}
		chainKey = result.ChainKey
		privateKey.Add(group.NewScalar().Set(lagrangeCoefficients[result.ID]).Mul(result.PrivateShare))
	}

	actualPublicKey := privateKey.ActOnBase()

	require.True(t, publicKey.Equal(actualPublicKey))

	shares := make(map[party.ID]curve.Scalar)
	for _, result := range results {
		shares[result.ID] = result.PrivateShare
	}

	for _, result := range results {
		for _, id := range parties {
			expected := shares[id].ActOnBase()
			require.True(t, result.VerificationShares.Points[id].Equal(expected), "different verification shares", id)
		}
		marshalled, err := cbor.Marshal(result)
		require.NoError(t, err)
		unmarshalledResult := EmptyConfig(group)
		err = cbor.Unmarshal(marshalled, unmarshalledResult)
		require.NoError(t, err)
		for _, id := range parties {
			expected := shares[id].ActOnBase()
			require.True(t, unmarshalledResult.VerificationShares.Points[id].Equal(expected))
		}
	}
}

func TestKeygen(t *testing.T) {
	group := curve.TwistedEdwardsCurve{}
	N := 3
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		r, err := StartKeygenCommon(false, group, partyIDs, N-1, partyID, nil, nil, nil)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutput(t, rounds, partyIDs)
}

func checkOutputTaproot(t *testing.T, rounds []round.Session, parties party.IDSlice) {
	group := curve.Secp256k1{}

	N := len(rounds)
	results := make([]TaprootConfig, 0, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &TaprootConfig{}, resultRound.Result, "expected taproot result")
		result := resultRound.Result.(*TaprootConfig)
		results = append(results, *result)
		require.Equal(t, r.SelfID(), result.ID, "party IDs should be the same")
	}

	var publicKey []byte
	var chainKey []byte
	privateKey := group.NewScalar()
	lagrangeCoefficients := polynomial.Lagrange(group, parties)
	for _, result := range results {
		if publicKey != nil {
			assert.EqualValues(t, publicKey, result.PublicKey, "different public keys")
		}
		publicKey = result.PublicKey
		if chainKey != nil {
			assert.Equal(t, chainKey, result.ChainKey, "different chain keys")
		}
		chainKey = result.ChainKey
		privateKey.Add(group.NewScalar().Set(lagrangeCoefficients[result.ID]).Mul(result.PrivateShare))
	}
	effectivePublic, err := curve.Secp256k1{}.LiftX(publicKey)
	require.NoError(t, err)

	actualPublicKey := privateKey.ActOnBase()

	require.True(t, actualPublicKey.Equal(effectivePublic))

	shares := make(map[party.ID]curve.Scalar)
	for _, result := range results {
		shares[result.ID] = result.PrivateShare
	}

	for _, result := range results {
		for _, id := range parties {
			expected := shares[id].ActOnBase()
			assert.True(t, result.VerificationShares[id].Equal(expected))
		}
	}
}

func TestKeygenTaproot(t *testing.T) {
	N := 5
	partyIDs := test.PartyIDs(N)
	group := curve.Secp256k1{}

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		r, err := StartKeygenCommon(true, group, partyIDs, N-1, partyID, nil, nil, nil)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)

	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	checkOutputTaproot(t, rounds, partyIDs)
}

func TestEdd25519(t *testing.T)  {
	group := curve.TwistedEdwardsCurve{}
	a_i0 := sample.Scalar(rand.Reader, group)
	a_i0_times_G := a_i0.ActOnBase()

	h := hash.New(hash.BytesWithDomain{TheDomain: "SSID", Bytes: []byte("234563454")},)
	Sigma_i := zksch.NewProof(h, a_i0_times_G, a_i0, nil)

	fmt.Println(Sigma_i)
	h = hash.New(hash.BytesWithDomain{TheDomain: "SSID", Bytes: []byte("234563454")},)
	fmt.Println(Sigma_i.Verify(h, a_i0_times_G, nil))
}

func TestEddPub(t *testing.T)  {
	for i :=0; i<20; i++ {
		group := curve.TwistedEdwardsCurve{}
		a_i0 := sample.Scalar(rand.Reader, group)
		b_i0 := sample.Scalar(rand.Reader, group)
		c_i0 := sample.Scalar(rand.Reader, group)
		x := sample.Scalar(rand.Reader, group)

		x.UnmarshalBinary(decode("029e319c25c81bf481cb950a5af31c4a3554d968b0e91d1445133611568d2119"))
		a_i0.UnmarshalBinary(decode("0b3857f9ed42cc345b8a2b40624fbc379ab9970c40fd617abf8a03fe35bfef8d"))
		b_i0.UnmarshalBinary(decode("096146fa123836a74c710ace605d8c03d966d814e26797653b1b2c5b58700346"))
		c_i0.UnmarshalBinary(decode("06397c0fce9d1dbef5b55e3dadf488410599690a542135d60d22a2d387dbe705"))

/*		x2 := group.NewScalar().Set(x).Mul(x)

		x2c := x2.Mul(c_i0).Add(group.NewScalar().Set(b_i0).Mul(x)).Add(a_i0)
		fmt.Println(x2c.ActOnBase())
		fmt.Println(
			x.Act(
				x.Act(
					c_i0.ActOnBase()).Add(b_i0.ActOnBase())).Add(a_i0.ActOnBase()))*/

		a_i0_times_G := a_i0.ActOnBase()
		b_i0_times_G := b_i0.ActOnBase()
		c_i0_times_G := c_i0.ActOnBase()
		fmt.Println("c_i0_times_G: ", c_i0_times_G)
		//fmt.Println(a_i0_times_G, b_i0_times_G, c_i0_times_G)

		f_i := polynomial.NewPolynomialV2(group, a_i0, b_i0, c_i0)
		// 多项式 ：[a*G,b*G,c *G]
		Phi_i := polynomial.NewPolynomialExponent(f_i)
		fmt.Println("Phi_i: ", Phi_i.Evaluate(x))

		p2 :=  ( group.NewScalar().Set(x).Mul(
			group.NewScalar().Set(x).Mul(c_i0).Add(b_i0),
		).Add(a_i0) ).ActOnBase()

		fmt.Println(
			p2.Equal(
				x.Act(
					x.Act(c_i0_times_G).Add(b_i0_times_G),
				).Add(a_i0_times_G),
			),
		)

		fmt.Println(p2)
		break
	}
}

func TestPolynomial(t *testing.T)  {
	for i :=0; i<20; i++ {
		group := curve.TwistedEdwardsCurve{}
		a_i0 := sample.Scalar(rand.Reader, group)
		//b_i0 := sample.Scalar(rand.Reader, group)
		x := sample.Scalar(rand.Reader, group)
		fmt.Println("x: ", x)
		//x := group.NewScalar().SetNat(new(saferith.Nat).SetBytes([]byte("a")))
		f_i := polynomial.NewPolynomial(group, 2, a_i0)

		//fmt.Println(group.NewScalar().Set(x).Mul(a_i0).Add(b_i0).ActOnBase())
		//fmt.Println(x.Act(a_i0.ActOnBase()).Add(b_i0.ActOnBase()))

		// a_i0 + b *x + c *x^2
		fx := f_i.Evaluate(x)

		// 多项式 ：[a*G,b*G,c *G]
		Phi_i := polynomial.NewPolynomialExponent(f_i)

		// a*G+b*G*x+c *G *x*x
		fmt.Println("Phi_i.Evaluate(x): ", Phi_i.Evaluate(x))
		fmt.Println(i, "fx*G : ", fx.ActOnBase())
		if !fx.ActOnBase().Equal(Phi_i.Evaluate(x)) {
			break
		}
	}
}

func TestNewPolynomialExponent(t *testing.T)  {

	group := curve.TwistedEdwardsCurve{}
	x := group.NewScalar()


	coefficients := make([]curve.Scalar, 3)
	coefficients[0] = group.NewScalar()
	coefficients[1] = group.NewScalar()
	coefficients[2] = group.NewScalar()

	x.UnmarshalBinary(decode(""))
	coefficients[0].UnmarshalBinary(decode(""))
	coefficients[1].UnmarshalBinary(decode(""))
	coefficients[2].UnmarshalBinary(decode(""))

	f_i := polynomial.NewPolynomialV2(group, coefficients...)

	fx := f_i.Evaluate(x)
	fmt.Println("fx*G : ", fx.ActOnBase())
}

func decode (x string) []byte {
	xi, _ := hex.DecodeString(x)
	return xi
}
