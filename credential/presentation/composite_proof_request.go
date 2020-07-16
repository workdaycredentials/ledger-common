package presentation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
	"github.com/workdaycredentials/ledger-common/util/canonical"
)

// ProofRequestHolder holds both the challenge issued by the Verifier and the set of
// proof responses that the user has selected to satisfy the request.
type ProofRequestHolder struct {
	SignedProofRequest    CompositeProofRequestInstanceChallenge
	ProofResponseElements map[int]FulfilledCriterion
}

// Populate sets the underlying SignedProofRequest to the base64 decoded argument.
func (p *ProofRequestHolder) Populate(proofRequestB64Encoded string) error {
	b64Encoding := base64.StdEncoding
	decodeKeyBytes, err := b64Encoding.DecodeString(proofRequestB64Encoded)
	if err != nil {
		return err
	}
	proofReq := &CompositeProofRequestInstanceChallenge{}
	if err = json.Unmarshal(decodeKeyBytes, proofReq); err == nil {
		p.SignedProofRequest = *proofReq
	}
	return err
}

// GetVerifierIdentity returns a base64 encoded decentralized identifier of the Verifier that issued the request.
func (p *ProofRequestHolder) GetVerifierIdentity() string {
	s := p.SignedProofRequest.ProofRequest.Verifier
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// GetNumberOfCriteria returns the number of data criteria requested.
// Each criterion represents a different data request against a particular schema.
func (p *ProofRequestHolder) GetNumberOfCriteria() int {
	return len(p.SignedProofRequest.ProofRequest.Criteria)
}

// GetCriteria returns the Criterion at a given index in the underlying Proof Request. The Criterion and the necessary
// variables for evaluating any predicate conditions will be returned in a CriteriaHolder. An error is returned if
// the index is outside of the range of the proof request, see GetNumberOfCriteria.
func (p *ProofRequestHolder) GetCriteria(index int) (*CriteriaHolder, error) {
	numberOfCriteria := len(p.SignedProofRequest.ProofRequest.Criteria)
	if index > (numberOfCriteria - 1) {
		err := fmt.Errorf("index out of bounds %d elements in the array", numberOfCriteria)
		return nil, err
	}

	holder := CriteriaHolder{
		Index:     index,
		Criterion: p.SignedProofRequest.ProofRequest.Criteria[index],
		Variables: p.SignedProofRequest.Variables,
	}
	return &holder, nil
}

// FulfillCriteriaMobile
// deprecated, call FulfillCriteria
func (p *ProofRequestHolder) FulfillCriteriaMobile(criteria *CriteriaHolder, credentialsB64Enc string, signingKeyRefB64Enc string, signingKeyB64Enc string) error {
	return p.FulfillCriteria(criteria, credentialsB64Enc, signingKeyRefB64Enc, signingKeyB64Enc)
}

// FulfillCriteria extracts the requested set of required and optional criterion attributes from the given set of credentials,
// signs them, and adds them to the proof response.
func (p *ProofRequestHolder) FulfillCriteria(criteria *CriteriaHolder, credentialsB64Enc string, signingKeyRefB64Enc string, signingKeyB64Enc string) error {
	b64Enc := base64.StdEncoding
	keyRefBytes, err := b64Enc.DecodeString(signingKeyRefB64Enc)
	if err != nil {
		return err
	}
	keyBytes, err := b64Enc.DecodeString(signingKeyB64Enc)
	if err != nil {
		return err
	}
	signingKey := ed25519.PrivateKey(keyBytes)

	creds, err := ExtractCreds(credentialsB64Enc)
	if err != nil {
		return err
	}

	signer, err := proof.NewEd25519Signer(signingKey, string(keyRefBytes))
	if err != nil {
		return err
	}
	fulfilledCriterion, err := FulfillCriterionForVCs(criteria.Criterion, criteria.Variables, creds, signer)
	if err != nil {
		return err
	}
	if p.ProofResponseElements == nil {
		p.ProofResponseElements = make(map[int]FulfilledCriterion)
	}
	p.ProofResponseElements[criteria.Index] = *fulfilledCriterion
	return nil
}

// ExtractCreds transforms the given base64 encoded JSON array of Verifiable Credentials into golang objects.
func ExtractCreds(credentialsB64Enc string) (submittedCredentials []credential.UnsignedVerifiableCredential, err error) {
	var untypedCreds []credential.VersionedCreds
	if err := decodeAndUnmarshal(credentialsB64Enc, &untypedCreds); err != nil {
		return nil, err
	}

	for _, cred := range untypedCreds {
		if !cred.UnsignedVerifiableCredential.IsEmpty() {
			submittedCredentials = append(submittedCredentials, cred.UnsignedVerifiableCredential)
		}
	}
	return submittedCredentials, nil
}

func isV1Credential(credStr string) bool {
	return strings.Contains(credStr, "claimProof")
}

// GenerateProofResponse digitally signs the accumulated array of Proof Response Elements and
// returns the base64 encoded canonical JSON representation.
func (p *ProofRequestHolder) GenerateProofResponse(signingKeyRefB64Enc string, signingKeyB64Enc string) (string, error) {
	// TODO check that each criteria is fulfilled, if not check if the criterion is totally optional
	b64Enc := base64.StdEncoding

	keyRef, err := b64Enc.DecodeString(signingKeyRefB64Enc)
	if err != nil {
		return "", err
	}
	keyBytes, err := b64Enc.DecodeString(signingKeyB64Enc)
	if err != nil {
		return "", err
	}
	signingKey := ed25519.PrivateKey(keyBytes)

	var fulfilledCriterion []FulfilledCriterion
	for _, resp := range p.ProofResponseElements {
		fulfilledCriterion = append(fulfilledCriterion, resp)
	}

	signer, err := proof.NewEd25519Signer(signingKey, string(keyRef))
	if err != nil {
		return "", err
	}
	submission, err := GenerateCompositeProofResponse(p.SignedProofRequest, fulfilledCriterion, signer)
	if err != nil {
		return "", err
	}

	respBytes, err := canonical.Marshal(submission)
	if err != nil {
		return "", err
	}

	return b64Enc.EncodeToString(respBytes), nil
}

func (p *ProofRequestHolder) CheckVerifierSignature(verifierDIDDocB64Encoded string) error {
	proofReq := p.SignedProofRequest

	decodeDIDDocBytes, err := base64.StdEncoding.DecodeString(verifierDIDDocB64Encoded)
	if err != nil {
		return err
	}

	var verifierDIDDoc ledger.DIDDoc
	if err = json.Unmarshal(decodeDIDDocBytes, &verifierDIDDoc); err != nil {
		return err
	}

	verifierDID := verifierDIDDoc.ID
	proofCreator := proofReq.ProofRequest.Verifier
	if verifierDID != proofCreator {
		return fmt.Errorf("DID Doc [%s] does not match Proof Request Creator [%s]", verifierDID, proofCreator)
	}

	// get pub key first
	publicKey, err := getPublicKeyUsedForSigning(verifierDIDDoc.PublicKey, proofReq.Proof.GetVerificationMethod())
	if err != nil {
		return err
	}
	decodedPublicKey, err := publicKey.GetDecodedPublicKey()
	if err != nil {
		return err
	}

	// build suite and verifier to check proof
	verifier := &proof.Ed25519Verifier{PubKey: decodedPublicKey}
	suite, err := proof.SignatureSuites().GetSuiteForProof(proofReq.GetProof())
	if err != nil {
		return err
	}

	return suite.Verify(&proofReq, verifier)
}

func getPublicKeyUsedForSigning(publicKeys []did.KeyDef, signingKeyRef string) (*did.KeyDef, error) {
	for _, publicKey := range publicKeys {
		if publicKey.ID == signingKeyRef {
			return &publicKey, nil
		}
	}
	return nil, fmt.Errorf("no keys match key ref %s", signingKeyRef)
}

// CriteriaHolder holds a Criterion, the index of that Criterion in the underlying
// CompositeProofRequest where the it was specified, and the set of variables used in any conditions.
type CriteriaHolder struct {
	Index     int
	Criterion Criterion
	Variables map[string]interface{}
}

// GetSchema returns a base64 encoding of the schema ID.
func (c *CriteriaHolder) GetSchema() string {
	s := c.Criterion.Schema.SchemaID
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// GetFields returns a base64 encoding of the requested attributes array in JSON format.
func (c *CriteriaHolder) GetFields() string {
	reqsAttr := c.Criterion.Schema.Attributes
	respBytes, err := canonical.Marshal(reqsAttr)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(respBytes)
}

// GetDescription returns a base64 encoding of the criterion description.
func (c *CriteriaHolder) GetDescription() string {
	description := c.Criterion.Description
	return base64.StdEncoding.EncodeToString([]byte(description))
}

// GetMaxCreds returns the maximum number of credentials that can be submitted for this criterion.
func (c *CriteriaHolder) GetMaxCreds() int {
	maxReq := c.Criterion.MaxRequired
	return maxReq
}

// GetMinCreds returns the minimum number of credentials that must be submitted for this criterion.
func (c *CriteriaHolder) GetMinCreds() int {
	minReq := c.Criterion.MinRequired
	return minReq
}

// CanFulfillMobile
// Deprecated: call CanFulfill
func (c *CriteriaHolder) CanFulfillMobile(credentialB64Enc string) bool {
	return c.CanFulfill(credentialB64Enc)
}

// CanFulfill returns true if the base64 encoded credential can satisfy the requirements of the criterion.
func (c *CriteriaHolder) CanFulfill(credentialB64Enc string) bool {
	b64Encoding := base64.StdEncoding
	decodeCredential, err := b64Encoding.DecodeString(credentialB64Enc)
	if err != nil {
		return false
	}

	var signedV1Credential credential.VerifiableCredential
	decodedCredAsString := string(decodeCredential)

	if err = json.Unmarshal(decodeCredential, &signedV1Credential); err != nil {
		logrus.WithField("credV1", decodedCredAsString).WithError(err).Warn("error marshaling V1 Credential")
		return false
	}

	criterion := c.Criterion
	if err := CheckVCMatchesCriterion(criterion, signedV1Credential.UnsignedVerifiableCredential, c.Variables); err != nil {
		return false
	}

	return true
}

// GetAuthorDID returns a base64 encoding of the schema author's decentralized identifier.
func (c *CriteriaHolder) GetAuthorDID() string {
	s := c.Criterion.Schema.AuthorDID
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// GetResourceID returns a base64 encoding of the schema resource ID.
func (c *CriteriaHolder) GetResourceID() string {
	s := c.Criterion.Schema.ResourceIdentifier
	return base64.StdEncoding.EncodeToString([]byte(s))
}
