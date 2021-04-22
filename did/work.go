package did

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"github.com/workdaycredentials/ledger-common/proof"
	"golang.org/x/crypto/ed25519"
)

const (
	WorkDIDMethod = "did:work:"
)

// GenerateDID generates a Decentralized ID in the form of "did:work:<id>" based on an Ed25519
// public key. Workday's DID method uses the first 16 bytes of the public key as a unique random
// value, assuming that the caller generates a new random key pair when creating a new ID.
func GenerateDID(publicKey ed25519.PublicKey) DID {
	return DID(WorkDIDMethod + base58.Encode(publicKey[0:16]))
}

// GenerateDIDFromB64PubKey converts a base64 encoded Ed25519 public key into a Decentralized ID.
// See GenerateDID.
func GenerateDIDFromB64PubKey(edBase64PubKey string) (DID, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(edBase64PubKey)
	if err != nil {
		return "", errors.Wrap(err, "unable to base64 decode ED key")
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)
	return GenerateDID(pubKey), nil
}

// AddKeyToDIDDoc takes a DID Doc, a key to add, and a signing key and its reference. The signing key must match the key
// that the current DID Doc is signed with, this is used to update the proof on the document and authenticate
// the update action. The check is based on the deterministic generation of the DID, which is only applicable for
// did:work DIDs. Conflict checking is done on the key reference.
func AddKeyToDIDDoc(doc DIDDoc, keyToAdd KeyDef, signingKey ed25519.PrivateKey, signingKeyRef string) (*DIDDoc, error) {
	// validate before updating the doc
	if keyToAdd.IsEmpty() {
		return nil, errors.New("cannot add empty key def")
	}
	if !strings.HasPrefix(doc.ID.String(), WorkDIDMethod) {
		return nil, errors.New("cannot add to non-did:work document")
	}
	// make sure the signing key matches the one used for the signature FIXME: it's a ref, not a DID
	if !strings.Contains(doc.Proof.GetVerificationMethod(), GenerateDID(signingKey.Public().(ed25519.PublicKey)).String()) {
		return nil, errors.New("signing key not found in DID Document")
	}
	// map of key id to index in document
	kids := make(map[string]int)
	for i, kid := range doc.PublicKey {
		kids[kid.ID] = i
	}
	// make sure the kid to add is unique
	newKID := keyToAdd.ID
	if _, ok := kids[keyToAdd.ID]; ok {
		return nil, fmt.Errorf("key id<%s> already present in DID Doc", newKID)
	}
	// resolve the signing key
	if _, ok := kids[signingKeyRef]; !ok {
		return nil, fmt.Errorf("key id<%s> is not present in DID Doc", signingKeyRef)
	}

	// update the doc
	doc.PublicKey = append(doc.PublicKey, keyToAdd)

	// sign using the same key and signing method as the present document
	signer, err := proof.NewEd25519Signer(signingKey, signingKeyRef)
	if err != nil {
		return nil, err
	}
	suite, err := proof.SignatureSuites().GetSuiteForProof(doc.Proof)
	if err != nil {
		return nil, err
	}
	doc.SetProof(nil)
	err = suite.Sign(&doc, signer, nil)
	return &doc, err
}
