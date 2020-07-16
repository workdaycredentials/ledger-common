package credential

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/go-playground/validator.v9"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestCredentialBuilder_BuildCredential(t *testing.T) {
	now := time.Now()

	inputs := []struct{
		// The type of signature to be used in the proof.
		SignatureType proof.SignatureType
		// We've always used Ed25519 keys, but we've called them by a variety of names.
		KeyType       proof.KeyType
		// Set to zero time for no expiration.
		Expiry        time.Time
	}{
		// Ed25519
		{SignatureType: proof.Ed25519SignatureType, KeyType: proof.Ed25519KeyType, Expiry: time.Time{}},
		{SignatureType: proof.Ed25519SignatureType, KeyType: proof.Ed25519KeyType, Expiry: now.Add(10 * time.Second)},
		// WorkEd25519
		{SignatureType: proof.WorkEdSignatureType, KeyType: proof.WorkEdKeyType, Expiry: time.Time{}},
		{SignatureType: proof.WorkEdSignatureType, KeyType: proof.WorkEdKeyType, Expiry: now.Add(10 * time.Second)},
		// JCSEd25519
		{SignatureType: proof.JCSEdSignatureType, KeyType: proof.Ed25519KeyType, Expiry: time.Time{}},
		{SignatureType: proof.JCSEdSignatureType, KeyType: proof.Ed25519KeyType, Expiry: now.Add(10 * time.Second)},
	}

	withOrWithout := func (v bool) string {
		if v {
			return "with"
		}
		return "without"
	}

	for _, input := range inputs {
		name := fmt.Sprintf("%s %s expiry", input.SignatureType, withOrWithout(input.Expiry.IsZero()))
		t.Run(name, func(t *testing.T) {
			pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			credID, issuerDID, schemaID := uuid.New().String(), uuid.New().String(), uuid.New().String()

			var metadata Metadata
			if input.Expiry.IsZero() {
				metadata = NewMetadataWithTimestamp(credID, issuerDID, schemaID, now)
			} else {
				metadata = NewMetadataWithTimestampAndExpiry(credID, issuerDID, schemaID, now, input.Expiry)
			}

			id := uuid.New().String()
			signer, err := proof.NewEd25519Signer(privKey, did.GenerateKeyID(issuerDID, did.InitialKey))
			require.NoError(t, err)

			builder := Builder{
				SubjectDID: id,
				Data: map[string]interface{}{
					"pet": "fido",
				},
				Metadata:      &metadata,
				Signer:        signer,
				SignatureType: input.SignatureType,
			}

			cred, err := builder.Build()
			require.NoError(t, err)
			require.NotNil(t, cred)
			assert.Equal(t, metadata, cred.Metadata)
			assert.Equal(t, input.SignatureType, cred.Proof.Type)

			expectedClaims := map[string]interface{}{
				SubjectIDAttribute: builder.SubjectDID,
				"pet":              "fido",
			}
			assert.Equal(t, expectedClaims, cred.CredentialSubject)

			for k, _ := range expectedClaims {
				require.NotNil(t, cred.ClaimProofs[k])
				assert.Equal(t, input.SignatureType, cred.ClaimProofs[k].Type)
			}

			assert.NoError(t, VerifyClaim(cred, SubjectIDAttribute, pubKey))
			assert.NoError(t, VerifyClaim(cred, "pet", pubKey))
			assert.EqualError(t, VerifyClaim(cred, "missing", pubKey), `missing claim proof for attribute "missing"`)

			suite, err := proof.SignatureSuites().GetSuiteForCredentialsProof(cred.Proof)
			assert.NoError(t, err)
			assert.Equal(t, input.SignatureType, suite.Type())

			verifier := &proof.Ed25519Verifier{PubKey: pubKey}
			assert.NoError(t, suite.Verify(cred, verifier))
		})
	}

	t.Run("required fields", func(t *testing.T) {
		_, err := Builder{}.Build()
		validationErrs, isValidationErrs := err.(validator.ValidationErrors)
		require.True(t, isValidationErrs)
		assert.Len(t, validationErrs, 4)
	})
}
