package credential

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/go-playground/validator.v9"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

func TestCredentialBuilder_BuildCredential(t *testing.T) {
	// setup
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	credID, issuerDID, schemaID := uuid.New().String(), uuid.New().String(), uuid.New().String()
	metadata := NewMetadataWithTimestamp(credID, issuerDID, schemaID, time.Now())

	t.Run("happy path with work ed", func(t *testing.T) {
		builder := Builder{
			SubjectDID: uuid.New().String(),
			Data: map[string]interface{}{
				"pet": "fido",
			},
			Metadata: &metadata,
			KeyRef:   did.InitialKey,
			Signer:   proof.WorkEd25519Signer{KeyID: did.InitialKey, PrivKey: privKey},
		}

		// test
		cred, err := builder.BuildCredential(context.Background())
		require.NoError(t, err)
		require.NotNil(t, cred)

		// verify
		assert.Equal(t, metadata, cred.Metadata)

		expectedClaims := map[string]interface{}{
			SubjectIDAttribute: builder.SubjectDID,
			"pet":              "fido",
		}
		assert.Equal(t, expectedClaims, cred.CredentialSubject)
		assert.NoError(t, VerifyClaim(cred, SubjectIDAttribute, pubKey))
		assert.NoError(t, VerifyClaim(cred, "pet", pubKey))

		assert.NoError(t, verifyClaimUsingSignatureSuite(cred, SubjectIDAttribute, pubKey))
		assert.NoError(t, verifyClaimUsingSignatureSuite(cred, "pet", pubKey))

		encodedCred, err := canonical.Marshal(cred.UnsignedVerifiableCredential)
		require.NoError(t, err)
		encodedCredBase64 := base64.StdEncoding.EncodeToString(encodedCred)
		assert.NoError(t, proof.VerifyWorkEd25519Proof(pubKey, *cred.Proof, []byte(encodedCredBase64)))
		assert.NoError(t, verifyCredUsingSignatureSuite(cred, pubKey))
	})

	t.Run("without optional expiry credential", func(t *testing.T) {
		builderNoExp := Builder{
			SubjectDID: uuid.New().String(),
			Data: map[string]interface{}{
				"pet": "fido",
			},
			Metadata:   &metadata,
			KeyRef:     "key-1",
			Signer: proof.JCSEd25519Signer{PrivKey: privKey},
		}

		// test
		cred, err := builderNoExp.BuildCredential(context.Background())
		require.NoError(t, err)
		require.NotNil(t, cred)

		// verify
		assert.Equal(t, metadata, cred.Metadata)
		assert.Equal(t, "", cred.ExpirationDate)
		credBytes, _ := json.Marshal(cred)
		assert.NotContains(t, string(credBytes), "expirationDate")
	})

	t.Run("with optional expiry credential", func(t *testing.T) {
		expiryDate := time.Now().Add(time.Hour * time.Duration(1))
		metadataWithExp := NewMetadataWithTimestampAndExpiry(credID, issuerDID, schemaID, time.Now(), expiryDate)
		builderNoExp := Builder{
			SubjectDID: uuid.New().String(),
			Data: map[string]interface{}{
				"pet": "fido",
			},
			Metadata:   &metadataWithExp,
			KeyRef:     "key-1",
			Signer: proof.JCSEd25519Signer{PrivKey: privKey},
		}

		// test
		cred, err := builderNoExp.BuildCredential(context.Background())
		require.NoError(t, err)
		require.NotNil(t, cred)

		// verify
		assert.Equal(t, metadataWithExp, cred.Metadata)
		expectedExp := expiryDate.Format(time.RFC3339)
		assert.Equal(t, expectedExp, cred.ExpirationDate)
		credBytes, _ := json.Marshal(cred)
		assert.Contains(t, string(credBytes), `expirationDate":"`+expectedExp)
	})

	t.Run("happy path with jcs", func(t *testing.T) {
		builder := Builder{
			SubjectDID: uuid.New().String(),
			Data: map[string]interface{}{
				"pet": "fido",
			},
			Metadata: &metadata,
			KeyRef:   did.InitialKey,
			Signer:   proof.JCSEd25519Signer{KeyID: did.InitialKey, PrivKey: privKey},
		}

		// test
		cred, err := builder.BuildCredential(context.Background())
		require.NoError(t, err)
		require.NotNil(t, cred)

		// verify
		assert.Equal(t, metadata, cred.Metadata)

		expectedClaims := map[string]interface{}{
			SubjectIDAttribute: builder.SubjectDID,
			"pet":              "fido",
		}
		assert.Equal(t, expectedClaims, cred.CredentialSubject)
		assert.NoError(t, VerifyClaim(cred, SubjectIDAttribute, pubKey))
		assert.NoError(t, VerifyClaim(cred, "pet", pubKey))

		assert.NoError(t, verifyClaimUsingSignatureSuite(cred, SubjectIDAttribute, pubKey))
		assert.NoError(t, verifyClaimUsingSignatureSuite(cred, "pet", pubKey))

		assert.NoError(t, proof.VerifyJCSEd25519Proof(cred, proof.JCSEd25519Verifier, pubKey))
		assert.NoError(t, verifyCredUsingSignatureSuite(cred, pubKey))
	})

	t.Run("required fields", func(t *testing.T) {
		_, err := Builder{}.BuildCredential(context.Background())
		validationErrs, isValidationErrs := err.(validator.ValidationErrors)
		require.True(t, isValidationErrs)
		assert.Len(t, validationErrs, 4)
	})
}

func verifyClaimUsingSignatureSuite(cred *VerifiableCredential, attribute string, pubKey ed25519.PublicKey) error {
	claimProof := cred.ClaimProofs[attribute]
	claim := &VerifiableCredential{
		UnsignedVerifiableCredential: UnsignedVerifiableCredential{
			Metadata:          cred.Metadata,
			CredentialSubject: map[string]interface{}{attribute: cred.CredentialSubject[attribute]},
		},
		Proof: &claimProof,
	}
	verifier := &proof.Ed25519Verifier{PubKey: pubKey}
	suite, err := proof.SignatureSuites().GetSuiteForCredentialProof(&claimProof)
	if err == nil {
		return suite.Verify(claim, verifier)
	}
	return err
}

func verifyCredUsingSignatureSuite(cred *VerifiableCredential, pubKey ed25519.PublicKey) error {
	verifier := &proof.Ed25519Verifier{PubKey: pubKey}
	suite, err := proof.SignatureSuites().GetSuiteForCredentialProof(cred.GetProof())
	if err == nil {
		return suite.Verify(cred, verifier)
	}
	return err
}
