package ledger

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"go.wday.io/credentials-open-source/ledger-common/did"
	"go.wday.io/credentials-open-source/ledger-common/proof"
)

var (
	keySeed       = []byte("12345678901234567890123456789012")
	issuerPrivKey = ed25519.NewKeyFromSeed(keySeed) // this matches the public key in didDocJson
	issuerPubKey  = issuerPrivKey.Public().(ed25519.PublicKey)
)

func TestVerifyDIDDocProof(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	keyRef := did.GenerateKeyID(id, did.InitialKey)
	docKeys := make(map[string]ed25519.PublicKey)
	publicKey := issuerPrivKey.Public().(ed25519.PublicKey)
	docKeys[did.InitialKey] = publicKey

	signer, err := proof.NewEd25519Signer(issuerPrivKey, keyRef)
	assert.NoError(t, err)
	ledgerDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyRef,
		Signer:               signer,
		SignatureType:        proof.JCSEdSignatureType,
		PublicKeys:           docKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()
	assert.NoError(t, err)

	verifier := &proof.Ed25519Verifier{PubKey: publicKey}
	suite, err := proof.SignatureSuites().GetSuiteForProof(ledgerDoc.GetProof())
	assert.NoError(t, err)
	assert.NoError(t, suite.Verify(ledgerDoc, verifier))
}

func TestED25519GenerateB64EncodedDIDDoc(t *testing.T) {
	b64EncPrivKey := base64.StdEncoding.EncodeToString(issuerPrivKey)
	b64didDoc, _ := GenerateB64EncodedEd25519DIDDoc(b64EncPrivKey)
	didDocBytes, _ := base64.StdEncoding.DecodeString(b64didDoc)

	var doc DIDDoc
	assert.NoError(t, json.Unmarshal(didDocBytes, &doc))

	// Generate did for
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", doc.Metadata.ID)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1", doc.PublicKey[0].ID)
	assert.Equal(t, proof.Ed25519KeyType, doc.PublicKey[0].Type)
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", doc.PublicKey[0].Controller.String())
	assert.Equal(t, doc.PublicKey[0].PublicKeyBase58, base58.Encode(issuerPubKey))
}

func TestED25519GenerateB64EncodedDeactivatedDIDDocMobile(t *testing.T) {
	b64EncPrivKey := base64.StdEncoding.EncodeToString(issuerPrivKey)
	b64didDoc, _ := GenerateB64EncodedEd25519DIDDoc(b64EncPrivKey)
	didDocBytes, _ := base64.StdEncoding.DecodeString(b64didDoc)

	var doc DIDDoc
	assert.NoError(t, json.Unmarshal(didDocBytes, &doc))

	b64DID := base64.StdEncoding.EncodeToString([]byte(doc.Metadata.ID))

	b64DeactivatedDIDDoc, _ := GenerateB64EncodedEd25519DeactivatedDIDDoc(b64EncPrivKey, b64DID)

	deactivatedDIDDocBytes, _ := base64.StdEncoding.DecodeString(b64DeactivatedDIDDoc)

	var deactivatedDoc DIDDoc
	assert.NoError(t, json.Unmarshal(deactivatedDIDDocBytes, &deactivatedDoc))

	// Generate did for
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq", deactivatedDoc.Metadata.ID)
	assert.Equal(t, 0, len(deactivatedDoc.PublicKey))
	assert.Equal(t, "did:work:6sYe1y3zXhmyrBkgHgAgaq#key-1", deactivatedDoc.DIDDoc.Proof.GetVerificationMethod())
}

func TestGenerateDIDDocForIssuerWithServices(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	keyRef := did.GenerateKeyID(id, did.InitialKey)
	publicKeys := make(map[string]ed25519.PublicKey)
	publicKeys[did.InitialKey] = issuerPubKey
	issuer := did.DID("fooIssuer")
	schemaID := "schemaID"
	serviceDef := []did.ServiceDef{{
		ID:              schemaID,
		Type:            "schema",
		ServiceEndpoint: did.StringOrArray{schemaID},
	}}
	signer, err := proof.NewEd25519Signer(issuerPrivKey, keyRef)
	assert.NoError(t, err)
	input := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyRef,
		Signer:               signer,
		SignatureType:        proof.JCSEdSignatureType,
		PublicKeys:           publicKeys,
		Issuer:               issuer,
		Services:             serviceDef,
	}

	didDoc, err := input.GenerateLedgerDIDDoc()
	assert.NoError(t, err, "Error was not expected when creating did doc")

	assert.Equal(t, didDoc.Metadata.ID, id.String())
	assert.Equal(t, didDoc.PublicKey[0].Controller, issuer)
	assert.Equal(t, didDoc.Service[0].ID, schemaID)
	assert.Equal(t, didDoc.PublicKey[0].PublicKeyBase58, base58.Encode(issuerPubKey))
	verifyDIDDoc(t, *didDoc.DIDDoc, issuerPubKey)
}

func TestGenerateDIDDocForKeys(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	keyRef := did.GenerateKeyID(id, did.InitialKey)
	docKeys := make(map[string]ed25519.PublicKey)
	publicKey := issuerPrivKey.Public().(ed25519.PublicKey)
	docKeys[did.InitialKey] = publicKey

	signer, err := proof.NewEd25519Signer(issuerPrivKey, keyRef)
	assert.NoError(t, err)
	ledgerDoc, err := GenerateDIDDocInput{
		DID:                  id,
		FullyQualifiedKeyRef: keyRef,
		Signer:               signer,
		SignatureType:        proof.JCSEdSignatureType,
		PublicKeys:           docKeys,
		Issuer:               id,
	}.GenerateLedgerDIDDoc()

	assert.NoError(t, err, "Error was not expected when creating id doc")
	assert.Equal(t, ledgerDoc.Metadata.ID, id.String())
	assert.Equal(t, ledgerDoc.PublicKey[0].Controller, id)
	assert.Nil(t, ledgerDoc.Service)
	verifyLedgerDIDDoc(t, *ledgerDoc, issuerPubKey)
}

func TestGenerateKeyDIDDoc(t *testing.T) {
	id := did.GenerateDIDKey(issuerPubKey)
	keyRef := did.GenerateKeyID(id, did.InitialKey)
	publicKey := issuerPrivKey.Public().(ed25519.PublicKey)

	didDoc := GenerateKeyDIDDoc(issuerPubKey, did.InitialKey)
	assert.NotEmpty(t, didDoc)
	assert.Equal(t, didDoc.ID, id)
	assert.Nil(t, didDoc.Service)
	assert.Nil(t, didDoc.Authentication)
	assert.Empty(t, didDoc.SchemaContext)
	assert.Len(t, didDoc.PublicKey, 1)

	keyDef := didDoc.PublicKey[0]
	assert.Equal(t, keyDef.ID, keyRef)
	assert.Equal(t, keyDef.Type, proof.Ed25519KeyType)
	assert.Equal(t, keyDef.Controller, id)
	assert.Equal(t, keyDef.PublicKeyBase58, base58.Encode(publicKey))
}

func TestBase64EncodedParametersForGeneratingDIDDoc(t *testing.T) {
	b64EncPrivKey := base64.StdEncoding.EncodeToString(issuerPrivKey)
	b64EncDIDDoc, err := GenerateB64EncodedEd25519DIDDoc(b64EncPrivKey)
	assert.NoError(t, err)

	decodeDIDDocStr, err := base64.StdEncoding.DecodeString(b64EncDIDDoc)
	assert.NoError(t, err)
	var ledgerDoc DIDDoc
	err = json.Unmarshal(decodeDIDDocStr, &ledgerDoc)
	assert.NoError(t, err)

	verifyLedgerDIDDoc(t, ledgerDoc, issuerPubKey)
}

func TestGenerateDeactivatedDIDDoc(t *testing.T) {
	id := did.GenerateDID(issuerPubKey)
	signer, err := proof.NewEd25519Signer(issuerPrivKey, did.GenerateKeyID(id, did.InitialKey))
	assert.NoError(t, err)
	suite, err := proof.SignatureSuites().GetSuite(proof.JCSEdSignatureType, proof.V2)
	assert.NoError(t, err)

	deactivatedDIDDoc, err := GenerateDeactivatedDIDDoc(signer, suite, id)
	assert.NoError(t, err)
	assert.Equal(t, id.String(), deactivatedDIDDoc.Metadata.ID)
	assert.Equal(t, id, deactivatedDIDDoc.DIDDoc.ID)
	assert.Equal(t, 0, len(deactivatedDIDDoc.DIDDoc.PublicKey))

	assert.Empty(t, deactivatedDIDDoc.DIDDoc.SchemaContext)
}

func verifyLedgerDIDDoc(t *testing.T, ledgerDoc DIDDoc, key ed25519.PublicKey) {
	assert.Len(t, ledgerDoc.PublicKey, 1)
	assert.Empty(t, ledgerDoc.DIDDoc.SchemaContext)

	suite, err := proof.SignatureSuites().GetSuiteForProof(ledgerDoc.GetProof())
	assert.NoError(t, err)

	verifier := &proof.Ed25519Verifier{PubKey: key}
	assert.NoError(t, suite.Verify(&ledgerDoc, verifier))
	assert.NoError(t, suite.Verify(ledgerDoc.DIDDoc, verifier))

	pubK1Bytes, _ := base58.Decode(ledgerDoc.PublicKey[0].PublicKeyBase58)
	assert.Equal(t, ledgerDoc.Metadata.ID, "did:work:"+base58.Encode(pubK1Bytes[:16]))
}

func verifyDIDDoc(t *testing.T, didDoc did.DIDDoc, key ed25519.PublicKey) {
	assert.Len(t, didDoc.PublicKey, 1)

	suite, err := proof.SignatureSuites().GetSuiteForProof(didDoc.GetProof())
	assert.NoError(t, err)

	verifier := &proof.Ed25519Verifier{PubKey: key}
	assert.NoError(t, suite.Verify(&didDoc, verifier))

	pubK1Bytes, _ := base58.Decode(didDoc.PublicKey[0].PublicKeyBase58)
	assert.Equal(t, didDoc.ID.String(), "did:work:"+base58.Encode(pubK1Bytes[:16]))
}
