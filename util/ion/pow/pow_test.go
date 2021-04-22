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
