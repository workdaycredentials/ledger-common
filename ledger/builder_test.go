package ledger

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/proof"
)

func TestVerifyDIDDocProof(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	keyRef := id + "#" + did.InitialKey
	docKeys := make(map[string]ed25519.PublicKey)
	publicKey := issuerPrivKey.Public().(ed25519.PublicKey)
	docKeys[did.InitialKey] = publicKey

	ledgerDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyRef,
		Signer:               proof.WorkEd25519Signer{PrivKey: issuerPrivKey},
		PublicKeys:           docKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()
	assert.NoError(t, err)

	pubK1Bytes, _ := base58.Decode(ledgerDoc.PublicKey[0].PublicKeyBase58)
	assert.NoError(t, VerifyLedgerProof(&*ledgerDoc, pubK1Bytes))
}

func TestED25519GenerateB64EncodedDIDDoc(t *testing.T) {
	b64EncPrivKey := base64.StdEncoding.EncodeToString(issuerPrivKey)
	b64didDoc, _ := GenerateB64EncodedEd25519DIDDoc(b64EncPrivKey)
	didDocBytes, _ := base64.StdEncoding.DecodeString(b64didDoc)

	var doc DIDDoc
	assert.NoError(t, json.Unmarshal(didDocBytes, &doc))

	// Generate did for
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", doc.ID)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1", doc.PublicKey[0].ID)
	assert.Equal(t, proof.WorkEdKeyType, doc.PublicKey[0].Type)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", doc.PublicKey[0].Controller)
	assert.Equal(t, doc.PublicKey[0].PublicKeyBase58, base58.Encode(issuerPubKey))
}

func TestED25519GenerateB64EncodedDeactivatedDIDDocMobile(t *testing.T) {
	b64EncPrivKey := base64.StdEncoding.EncodeToString(issuerPrivKey)
	b64didDoc, _ := GenerateB64EncodedEd25519DIDDoc(b64EncPrivKey)
	didDocBytes, _ := base64.StdEncoding.DecodeString(b64didDoc)

	var doc DIDDoc
	assert.NoError(t, json.Unmarshal(didDocBytes, &doc))

	b64DID := base64.StdEncoding.EncodeToString([]byte(doc.ID))

	b64DeactivatedDIDDoc, _ := GenerateB64EncodedEd25519DeactivatedDIDDoc(b64EncPrivKey, b64DID)

	deactivatedDIDDocBytes, _ := base64.StdEncoding.DecodeString(b64DeactivatedDIDDoc)

	var deactivatedDoc DIDDoc
	assert.NoError(t, json.Unmarshal(deactivatedDIDDocBytes, &deactivatedDoc))

	// Generate did for
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", deactivatedDoc.ID)
	assert.Equal(t, 0, len(deactivatedDoc.PublicKey))
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1", deactivatedDoc.DIDDoc.Proof.GetVerificationMethod())
}

func TestGenerateDIDDocForIssuerWithServices(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	keyRef := id + "#" + did.InitialKey
	publicKeys := make(map[string]ed25519.PublicKey)
	publicKeys[did.InitialKey] = issuerPubKey
	issuer := "fooIssuer"
	schemaID := "schemaID"
	serviceDef := []did.ServiceDef{{
		ID:              schemaID,
		Type:            "schema",
		ServiceEndpoint: schemaID,
	}}
	input := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyRef,
		Signer:               proof.WorkEd25519Signer{PrivKey: issuerPrivKey},
		PublicKeys:           publicKeys,
		Issuer:               issuer,
		Services:             serviceDef,
	}

	didDoc, err := input.GenerateLedgerDIDDoc()
	assert.NoError(t, err, "Error was not expected when creating did doc")
	assert.Equal(t, didDoc.ID, id)
	assert.Equal(t, didDoc.UnsignedDIDDoc.PublicKey[0].Controller, issuer)
	assert.Equal(t, didDoc.Service[0].ID, schemaID)
	assert.Equal(t, didDoc.PublicKey[0].PublicKeyBase58, base58.Encode(issuerPubKey))
	verifyDIDDoc(t, *didDoc.DIDDoc)
}

func TestGenerateDIDDocForKeys(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	keyRef := id + "#" + did.InitialKey
	docKeys := make(map[string]ed25519.PublicKey)
	publicKey := issuerPrivKey.Public().(ed25519.PublicKey)
	docKeys[did.InitialKey] = publicKey

	ledgerDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyRef,
		Signer:               proof.WorkEd25519Signer{PrivKey: issuerPrivKey},
		PublicKeys:           docKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()

	assert.NoError(t, err, "Error was not expected when creating id doc")
	assert.Equal(t, ledgerDoc.ID, id)
	assert.Equal(t, ledgerDoc.UnsignedDIDDoc.PublicKey[0].Controller, id)
	assert.Nil(t, ledgerDoc.Service)
	verifyLedgerDIDDoc(t, *ledgerDoc)
}

func TestGenerateKeyDIDDoc(t *testing.T) {
	id := did.GenerateDIDKey(issuerPubKey)
	keyRef := id + "#" + did.InitialKey
	publicKey := issuerPrivKey.Public().(ed25519.PublicKey)

	diddoc := GenerateKeyDIDDoc(issuerPubKey, did.InitialKey)
	assert.NotEmpty(t, diddoc)
	assert.Equal(t, diddoc.ID, id)
	assert.Nil(t, diddoc.Service)
	assert.Nil(t, diddoc.Authentication)
	assert.Empty(t, diddoc.SchemaContext)
	assert.Len(t, diddoc.PublicKey, 1)

	keyDef := diddoc.PublicKey[0]
	assert.Equal(t, keyDef.ID, keyRef)
	assert.Equal(t, keyDef.Type, proof.WorkEdKeyType)
	assert.Equal(t, keyDef.Controller, id)
	assert.Equal(t, keyDef.PublicKeyBase58, base58.Encode(publicKey))
}

func TestBase64EncodedParametersForGeneratingDIDDoc(t *testing.T) {
	b64EncPrivKey := base64.StdEncoding.EncodeToString(issuerPrivKey)
	b64EncDIDDoc, err := GenerateB64EncodedEd25519DIDDoc(b64EncPrivKey)
	assert.NoError(t, err)

	decodeDIDDocStr, err := base64.StdEncoding.DecodeString(b64EncDIDDoc)
	assert.NoError(t, err)
	ledgerDoc := &DIDDoc{}
	err = json.Unmarshal(decodeDIDDocStr, ledgerDoc)
	assert.NoError(t, err)
	verifyLedgerDIDDoc(t, *ledgerDoc)
}

func TestGenerateDeactivatedDIDDoc(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	deactivatedDIDDoc, err := GenerateDeactivatedDIDDoc(issuerPrivKey, id)
	assert.NoError(t, err)
	assert.Equal(t, id, deactivatedDIDDoc.ID)
	assert.Equal(t, id, deactivatedDIDDoc.DIDDoc.ID)
	assert.Equal(t, 0, len(deactivatedDIDDoc.DIDDoc.PublicKey))

	//nolint:staticcheck
	assert.Empty(t, deactivatedDIDDoc.DIDDoc.SchemaContext)
}

func verifyLedgerDIDDoc(t *testing.T, ledgerDoc DIDDoc) {
	assert.Len(t, ledgerDoc.PublicKey, 1)

	//nolint:staticcheck
	assert.Empty(t, ledgerDoc.DIDDoc.SchemaContext)

	assert.NoError(t, VerifyLedgerProof(&ledgerDoc, issuerPubKey))
	assert.NoError(t, did.VerifyDIDDocProof(*ledgerDoc.DIDDoc, issuerPubKey))

	pubK1Bytes, _ := base58.Decode(ledgerDoc.PublicKey[0].PublicKeyBase58)

	assert.Equal(t, ledgerDoc.ID, "did:work:"+base58.Encode(pubK1Bytes[:16]))
}

func verifyDIDDoc(t *testing.T, didDoc did.DIDDoc) {
	assert.Len(t, didDoc.PublicKey, 1)

	assert.NoError(t, did.VerifyDIDDocProof(didDoc, issuerPubKey))

	pubK1Bytes, _ := base58.Decode(didDoc.PublicKey[0].PublicKeyBase58)

	assert.Equal(t, didDoc.ID, "did:work:"+base58.Encode(pubK1Bytes[:16]))
}
