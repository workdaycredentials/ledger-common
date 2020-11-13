package ledger

import (
	"encoding/base64"
	"time"

	"golang.org/x/crypto/ed25519"

	didpkg "github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

// GenerateB64EncodedEd25519DeactivatedDIDDoc creates a deactivated DID Document and returns it as
// base64 encoded JSON.  Returns an error if the either the base64 encoded arguments cannot be
// decoded or if the key material is not a valid Ed25519 private key.
func GenerateB64EncodedEd25519DeactivatedDIDDoc(b64EncodedPrivKey, b64EncDID string) (string, error) {
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

	keyID := didpkg.GenerateKeyID(id, didpkg.InitialKey)
	signer, err := proof.NewEd25519Signer(signingKey, keyID)
	if err != nil {
		return "", err
	}
	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	if err != nil {
		return "", err
	}
	didDoc, err := GenerateDeactivatedDIDDoc(signer, suite, id)
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
// Returns an error if the Signer fails to generate the digital signature.
func GenerateDeactivatedDIDDoc(signer proof.Signer, suite proof.SignatureSuite, did string) (*DIDDoc, error) {
	doc := &didpkg.DIDDoc{UnsignedDIDDoc: didpkg.UnsignedDIDDoc{ID: did}}
	fullyQualifiedKeyRef := didpkg.GenerateKeyID(did, didpkg.InitialKey)
	if err := suite.Sign(doc, signer, nil); err != nil {
		return nil, err
	}

	ledgerDoc := DIDDoc{
		Metadata: &Metadata{
			Type:         util.DIDDocTypeReference_v1_0,
			ModelVersion: util.Version_1_0,
			ID:           doc.ID,
			Authored:     time.Now().UTC().Format(time.RFC3339),
			Author:       didpkg.ExtractDIDFromKeyRef(fullyQualifiedKeyRef),
		},
		DIDDoc: doc,
	}

	err := suite.Sign(&ledgerDoc, signer, nil)
	return &ledgerDoc, err
}
