package ledger

import (
	"encoding/base64"
	"fmt"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

// GenerateB64EncodedEd25519DeactivatedDIDDoc creates a deactivated DID Document and returns it as
// base64 encoded JSON.  Returns an error if the either the base64 encoded arguments cannot be
// decoded or if the key material is not a valid Ed25519 private key.
func GenerateB64EncodedEd25519DeactivatedDIDDoc(b64EncodedPrivKey string, b64EncDID string) (string, error) {
	b64Encoding := base64.StdEncoding
	decodeKeyBytes, err := b64Encoding.DecodeString(b64EncodedPrivKey)
	if err != nil {
		return "", err
	}
	signingKey := ed25519.PrivateKey(decodeKeyBytes)

	decodeDIDBytes, err := b64Encoding.DecodeString(b64EncDID)
	if err != nil {
		return "", err
	}
	id := string(decodeDIDBytes)

	keyID := fmt.Sprintf("%s#%s", id, did.InitialKey)
	signer := proof.WorkEd25519Signer{PrivKey: signingKey, KeyID: keyID}
	didDoc, err := GenerateDeactivatedDIDDocGeneric(signer, id)
	if err != nil {
		return "", err
	}
	jsonBytes, err := canonical.Marshal(didDoc)
	if err != nil {
		return "", err
	}
	b64EncDIDDoc := b64Encoding.EncodeToString(jsonBytes)
	return b64EncDIDDoc, err
}

// GenerateDeactivatedDIDDoc creates a deactivated DID Document.
// Returns an error if the key material is not a valid Ed25519 private key.
func GenerateDeactivatedDIDDoc(key ed25519.PrivateKey, id string) (*DIDDoc, error) {
	keyID := fmt.Sprintf("%s#%s", id, did.InitialKey)
	ps := proof.JCSEd25519Signer{KeyID: keyID, PrivKey: key}
	return GenerateDeactivatedDIDDocGeneric(ps, id)
}

// GenerateDeactivatedDIDDocGeneric creates a deactivated DID Document.
// Returns an error if the Signer fails to generate the digital signature.
func GenerateDeactivatedDIDDocGeneric(ps proof.Signer, id string) (*DIDDoc, error) {
	doc := did.UnsignedDIDDoc{
		ID: id,
	}

	fullyQualifiedKeyRef := fmt.Sprintf("%s#%s", id, did.InitialKey)
	signedDoc, err := did.SignDIDDocGeneric(ps, doc, fullyQualifiedKeyRef)
	if err != nil {
		return nil, err
	}

	ledgerDoc := DIDDoc{
		Metadata: &Metadata{
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           signedDoc.ID,
			Authored:     time.Now().UTC().Format(time.RFC3339),
			Author:       did.ExtractAuthorDID(fullyQualifiedKeyRef),
		},
		DIDDoc: signedDoc,
	}
	err = SignLedgerDocGeneric(ps, &ledgerDoc, fullyQualifiedKeyRef)
	return &ledgerDoc, err
}
