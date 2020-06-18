package presentation

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

const (
	CredentialsLDContext = "https://w3.org/2018/credentials/v1"
	LDType               = "VerifiablePresentation"
)

// GenerateProof returns the given credential as a Presentation that is digitally signed using
// the provided key material.  This method is intended to be called by mobile clients using
// Gomobile; therefore, the arguments and response are base64 encoded in accordance with Workday's
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

	pid, err := b64Enc.DecodeString(b64PresentationID)
	if err != nil {
		return "", err
	}

	signingKey := ed25519.PrivateKey(keyBytes)
	presentation, err := GeneratePresentationForVersionedCred(cred, string(keyRef), signingKey, string(pid))
	if err != nil {
		return "", err
	}
	presBytes, err := canonical.Marshal(presentation)
	return b64Enc.EncodeToString(presBytes), err
}

// GeneratePresentationFromVC generates a Presentation from a Verifiable Credential, and digitally
// signs it using the key material provided.
func GeneratePresentationFromVC(cred credential.UnsignedVerifiableCredential, keyReference string, signingKey ed25519.PrivateKey, pid string) (*Presentation, error) {
	versionedCred := credential.VersionedCreds{
		UnsignedVerifiableCredential: cred,
	}
	return GeneratePresentationForVersionedCred(versionedCred, keyReference, signingKey, pid)
}

// GeneratePresentationForVersionedCred generates a Presentation from a Versioned Credential and
// digitally signs it using the key material provided.
func GeneratePresentationForVersionedCred(cred credential.VersionedCreds, keyReference string, signingKey ed25519.PrivateKey, pid string) (*Presentation, error) {
	unsignedPres := UnsignedPresentation{
		Context:     []string{CredentialsLDContext},
		ID:          pid,
		Type:        []string{LDType},
		Created:     time.Now().UTC().Format(time.RFC3339),
		Credentials: []credential.VersionedCreds{cred},
	}

	unsignedJSON, err := canonical.Marshal(unsignedPres)
	if err != nil {
		return nil, err
	}

	presProof, err := proof.CreateWorkEd25519Proof(unsignedJSON, keyReference, signingKey, uuid.New().String())
	if err != nil {
		return nil, err
	}

	return &Presentation{
		UnsignedPresentation: unsignedPres,
		Proof:                []proof.Proof{*presProof},
	}, nil
}
