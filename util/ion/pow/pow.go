package pow

import (
	"context"
	"encoding/hex"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

// Challenge is the body as returned from GET /api/v1.0/proof-of-work-challenge
type Challenge struct {
	ChallengeNonceHex      string `json:"challengeNonce"`
	ValidDurationInMinutes int64  `json:"validDurationInMinutes"`
	LargestAllowedHashHex  string `json:"largestAllowedHash"`
}

const (
	// These parameters are fixed and affect the calculated hash
	iterations      = 1
	memorySizeKB    = 1000
	hashLengthBytes = 32
	threads         = 1
)

func calcHash(answerNonce, body, challengeNonce []byte) []byte {
	pw := append(answerNonce, body...)
	return argon2.IDKey(pw, challengeNonce, iterations, memorySizeKB, threads, hashLengthBytes)
}

func padWith0(len int, array []byte) []byte {
	if len <= 0 {
		return array
	}
	return append(make([]byte, len), array...)
}

func isValidHash(hash, largestAllowedHash []byte) bool {
	// First make sure both hashes are of the same length by padding with 0
	padding := len(largestAllowedHash) - len(hash)
	hash = padWith0(padding, hash)
	largestAllowedHash = padWith0(-padding, largestAllowedHash)
	// BigEndian numbers start with the MSB at index 0
	for i, v := range hash {
		if v > largestAllowedHash[i] {
			return false
		}
		if v < largestAllowedHash[i] {
			break
		}
	}
	return true
}

type powChallenge struct {
	body, challengeNonce, largestAllowedHash []byte
}

const (
	invalidChallengeNonce     = "invalid challengeNonce"
	invalidLargestAllowedHash = "invalid largestAllowedHash"
)

func newPowChallenge(challenge Challenge, body []byte) (*powChallenge, error) {
	challengeNonce, err := hex.DecodeString(challenge.ChallengeNonceHex)
	if err != nil {
		return nil, errors.Wrap(err, invalidChallengeNonce)
	}

	largestAllowedHash, err := hex.DecodeString(challenge.LargestAllowedHashHex)
	if err != nil {
		return nil, errors.Wrap(err, invalidLargestAllowedHash)
	}

	// Bail now if the requested difficulty exceeds our search space (<2^64)
	if !isValidHash([]byte{255, 255, 255, 255, 255, 255, 255, 255}, largestAllowedHash) {
		return nil, errors.New(invalidLargestAllowedHash)
	}

	// Avoid allocations by making sure the largestAllowedHash matches the hash length
	largestAllowedHash = padWith0(hashLengthBytes-len(largestAllowedHash), largestAllowedHash)

	return &powChallenge{
		body:               body,
		challengeNonce:     challengeNonce,
		largestAllowedHash: largestAllowedHash,
	}, nil
}

func (pow powChallenge) isValidNonce(answerNonce []byte) bool {
	// Calculate the hash for this nonce, then compare with the limit
	hash := calcHash(answerNonce, pow.body, pow.challengeNonce)
	return isValidHash(hash, pow.largestAllowedHash)
}

func (pow powChallenge) proofOfWork(ctx context.Context, nonce uint64) []byte {
	var buffer [16]byte
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Convert the current nonce to a []byte (must be ASCII ¯\_(ツ)_/¯ )
			answerNonce := strconv.AppendUint(buffer[0:0], nonce, 36)
			// Return as soon as a valid nonce is found
			if pow.isValidNonce(answerNonce) {
				return answerNonce
			}
		}
		nonce++
	}
}

func (pow powChallenge) proofOfWorkParallel(ctx context.Context, parallelism int) []byte {
	if parallelism <= 0 {
		// Set default parallelism factor to number of CPUs
		parallelism = runtime.GOMAXPROCS(0)
	}

	// Create a channel for receiving the PoW answer (not closed to avoid panic)
	channel := make(chan []byte)

	// Divide the entire uint64 space up into equal parts for each CPU
	const maxNonce = ^uint64(0)
	noncesPerThread := maxNonce / uint64(parallelism)

	// Create N go-routines, each starting at a different nonce value
	for ii := 0; ii < parallelism; ii++ {
		go func(start uint64) {
			channel <- pow.proofOfWork(ctx, start)
		}(uint64(ii) * noncesPerThread)
	}

	// Wait for context cancellation or an answer from one of the go-routines, whichever comes first
	select {
	case <-ctx.Done():
		return nil
	case nonce := <-channel:
		return nonce
	}
}

// CalculateAnswerNonce returns the hex-encoded value for the `answer-nonce` header
func CalculateAnswerNonce(ctx context.Context, challenge Challenge, body []byte, parallelism int) (string, error) {
	pow, err := newPowChallenge(challenge, body)
	if err != nil {
		return "", err
	}

	// Create a cancellable context using the timeout from the challenge (cancelled on return)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(challenge.ValidDurationInMinutes)*time.Minute)
	defer cancel()

	nonce := pow.proofOfWorkParallel(ctx, parallelism)
	if nonce == nil {
		return "", ctx.Err()
	}
	return toHex(nonce), nil
}

func toHex(bytes []byte) string {
	return strings.ToUpper(hex.EncodeToString(bytes))
}
