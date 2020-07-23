package presentation

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

const (
	CredentialsLDContext = "https://w3.org/2018/credentials/v1"
	LDType               = "VerifiablePresentation"
)

// GenerateProof returns the given credential as a Presentation that is digitally signed using
// the provided key material. This method is intended to be called by mobile clients using Gomobile;
// therefore, the arguments and response are base64 encoded in accordance with Workday's
// Gomobile style guides.
func GenerateProof(b64Credential, b64KeyReference, b64SigningKey, b64PresentationID string) (string, error) {
	b64Enc := base64.StdEncoding
	credentialBytes, err := b64Enc.DecodeString(b64Credential)
	if err != nil {
		return "", err
	}

	var cred credential.VersionedCreds
	if err = json.Unmarshal(credentialBytes, &cred); err != nil {
		return "", err
	}

	keyRef, err := b64Enc.DecodeString(b64KeyReference)
	if err != nil {
		return "", err
	}

	keyBytes, err := b64Enc.DecodeString(b64SigningKey)
	if err != nil {
		return "", err
	}

	presentationID, err := b64Enc.DecodeString(b64PresentationID)
	if err != nil {
		return "", err
	}

	signingKey := ed25519.PrivateKey(keyBytes)
	signer, err := proof.NewEd25519Signer(signingKey, string(keyRef))
	if err != nil {
		return "", err
	}
	presentation, err := GeneratePresentationForVersionedCred(cred, signer, proof.JCSEdSignatureType, string(presentationID))
	if err != nil {
		return "", err
	}
	presBytes, err := canonical.Marshal(presentation)
	return b64Enc.EncodeToString(presBytes), err
}

// GeneratePresentationFromVC generates a Presentation from a Verifiable Credential, and digitally
// signs it using the key material provided.
func GeneratePresentationFromVC(cred credential.UnsignedVerifiableCredential, signer proof.Signer, signatureType proof.SignatureType, presentationID string) (*Presentation, error) {
	versionedCred := credential.VersionedCreds{
		UnsignedVerifiableCredential: cred,
	}
	return GeneratePresentationForVersionedCred(versionedCred, signer, signatureType, presentationID)
}

// GeneratePresentationForVersionedCred generates a Presentation from a Versioned Credential and
// digitally signs it using the key material provided.
func GeneratePresentationForVersionedCred(cred credential.VersionedCreds, signer proof.Signer, signatureType proof.SignatureType, presentationID string) (*Presentation, error) {
	pres := &Presentation{
		UnsignedPresentation: UnsignedPresentation{
			Context:     []string{CredentialsLDContext},
			ID:          presentationID,
			Type:        []string{LDType, util.ProofResponseTypeReference_v1_0},
			Created:     time.Now().UTC().Format(time.RFC3339),
			Credentials: []credential.VersionedCreds{cred},
		},
	}
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	err = suite.Sign(pres, signer)
	return pres, err
}
