package pow

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testChallenge = "1CBB4F7AEDC781484E5BDD7E28BAA91C12072E7467BB6DDFC2CA2E9BA805AC87"
	testAnswer    = "736F6D65416E73776572"
	testHash      = "64488590CAFE85726198A3B10DAE72DF232319EDF30282669C1CB762FD2EF1B8"
	testBody      = `{"testVector":"body"}`
)

func fromHex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPadWith0(t *testing.T) {
	one := []byte{1}
	assert.Equal(t, []byte{0, 0, 0, 1}, padWith0(3, one))
	// Ensure no allocations on no-ops
	padWith0(0, one)[0] = 2
	assert.Equal(t, byte(2), one[0])
}

func TestCalcHash(t *testing.T) {
	challenge := fromHex(testChallenge)
	answer := fromHex(testAnswer)
	hash := calcHash(answer, []byte(testBody), challenge)
	assert.Len(t, hash, hashLengthBytes)
	assert.Equal(t, testHash, toHex(hash))
}

func TestIsValidHash(t *testing.T) {
	testCases := []struct {
		desc     string
		hash     string
		largest  string
		expected bool
	}{
		{"happy", "01", "FF", true},
		{"equal", "FF", "FF", true},
		{"diff size", "FF", "0101", true},
		{"too large", "FF", "01", false},
		{"leading zeroes", "00000001", "FF", true},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			assert.Equal(t, tC.expected, isValidHash(fromHex(tC.hash), fromHex(tC.largest)))
		})
	}
}

func TestIsValidNonce(t *testing.T) {
	const largestAllowedHash = "04fedd721038ab8f64139ee48868a5c3ba7f36386762dfed7d203717f13d69dc"
	const challenge = "8f347148776672b9bf2514bb221c2fe7d0dc485e30b4a5fb543a104e5b0ba6a2"
	const nonce = "6f"
	const body = `{"type":"create","delta":{"patches":[{"action":"replace","document":{"publicKeys":[{"id":"key-1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"0xyiJvOQF8fLHDbqclgMCPC4g3o24z_E6mtJOxXp_B0"},"purposes":["authentication"],"type":"JsonWebKey2020"}],"services":[{"id":"schema-1","type":"schema","serviceEndpoint":"did:work:VS1wWC93J7TSwoKBCFYE9r;id=af4821e7-eb08-4e48-8552-04c06a4cc9cc;version=3.0"}]}}],"updateCommitment":"EiDmE3VrgNnH9ZLZdMF6qcsEaC8bEiKgK18kNAoP-Z9X1g"},"suffixData":{"deltaHash":"EiBvqFKWRb938tMFQs0N5aiqHUe8WJ-Se0PyCHTXyOrR2g","recoveryCommitment":"EiBdyLhRueAuL7U5xJuG_58sVVnrTeSYikf0uPaPi8ePxQ"}}`
	pow := powChallenge{[]byte(body), fromHex(challenge), fromHex(largestAllowedHash)}
	assert.True(t, pow.isValidNonce(fromHex(nonce)))
}

func TestProofOfWork(t *testing.T) {
	ctx := context.Background()
	pow := powChallenge{[]byte(testBody), fromHex(testChallenge), fromHex(testHash)}
	answerNonce := pow.proofOfWork(ctx, 10000)
	assert.Equal(t, []byte{0x37, 0x70, 0x74}, answerNonce)
}

func TestProofOfWorkParallel(t *testing.T) {
	ctx := context.Background()
	largestAllowedHash := fromHex("000F0000000000223ABD24098EFAB23409483573473773774375AABDCC224900")
	pow := powChallenge{[]byte(testBody), fromHex(testChallenge), largestAllowedHash}
	answerNonce := pow.proofOfWorkParallel(ctx, 0)
	assert.True(t, pow.isValidNonce(answerNonce))
}

func TestCalculateAnswerNonce(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		challenge := Challenge{
			ChallengeNonceHex:      testChallenge,
			LargestAllowedHashHex:  testHash,
			ValidDurationInMinutes: 1,
		}
		ctx := context.Background()
		answerNonce, err := CalculateAnswerNonce(ctx, challenge, []byte(testBody), 0)
		require.NoError(t, err)
		assert.NotEmpty(t, answerNonce)
		assert.NotEmpty(t, fromHex(answerNonce))
	})

	t.Run("invalid challengeNonce", func(t *testing.T) {
		challenge := Challenge{
			ChallengeNonceHex: "nothex",
		}
		ctx := context.Background()
		answerNonce, err := CalculateAnswerNonce(ctx, challenge, []byte(testBody), 0)
		require.EqualError(t, err, "invalid challengeNonce: encoding/hex: invalid byte: U+006E 'n'")
		assert.Empty(t, answerNonce)
	})

	t.Run("invalid largestAllowedHash", func(t *testing.T) {
		challenge := Challenge{
			LargestAllowedHashHex: "alsonothex",
		}
		ctx := context.Background()
		answerNonce, err := CalculateAnswerNonce(ctx, challenge, []byte(testBody), 0)
		require.EqualError(t, err, "invalid largestAllowedHash: encoding/hex: invalid byte: U+006C 'l'")
		assert.Empty(t, answerNonce)
	})

	t.Run("tiny largestAllowedHash", func(t *testing.T) {
		challenge := Challenge{
			LargestAllowedHashHex: "FF",
		}
		ctx := context.Background()
		answerNonce, err := CalculateAnswerNonce(ctx, challenge, []byte(testBody), 0)
		require.EqualError(t, err, "invalid largestAllowedHash")
		assert.Empty(t, answerNonce)
	})

	t.Run("deadline", func(t *testing.T) {
		challenge := Challenge{
			LargestAllowedHashHex:  testHash,
			ValidDurationInMinutes: 0,
		}
		ctx := context.Background()
		answer, err := CalculateAnswerNonce(ctx, challenge, []byte(testBody), 0)
		require.EqualError(t, err, "context deadline exceeded")
		assert.Empty(t, answer)
		assert.Nil(t, ctx.Err())
	})

	t.Run("parent context cancelled", func(t *testing.T) {
		challenge := Challenge{
			LargestAllowedHashHex:  "FFFFFFFFFFFFFFFFFF",
			ValidDurationInMinutes: 1,
		}
		ctx, cancel := context.WithCancel(context.Background())
		go cancel()
		answer, err := CalculateAnswerNonce(ctx, challenge, []byte(testBody), 0)
		require.EqualError(t, err, "context canceled")
		assert.Empty(t, answer)
	})
}

func BenchmarkChannelRace(b *testing.B) {
	ctx := context.Background()
	pow := powChallenge{
		largestAllowedHash: fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
	}
	for i := 0; i < b.N; i++ {
		pow.proofOfWorkParallel(ctx, 0)
	}
}
