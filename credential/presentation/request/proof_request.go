package request

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/credential/presentation"
	"github.com/workdaycredentials/ledger-common/credential/presentation/response"
	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
	"github.com/workdaycredentials/ledger-common/proof"
)

// ProofRequestHolder holds both the challenge issued by the Verifier and the set of
// proof responses that the user has selected to satisfy the request.
type ProofRequestHolder struct {
	SignedProofRequest    presentation.CompositeProofRequestInstanceChallenge
	ProofResponseElements map[int]presentation.FulfilledCriterion
}

// GetVerifierIdentity returns the decentralized identifier of the Verifier that issued the request.
func (p *ProofRequestHolder) GetVerifierIdentity() string {
	return p.SignedProofRequest.ProofRequest.Verifier
}

// GetNumberOfCriteria returns the number of data criteria requested.
// Each criterion represents a different data request against a particular schema.
func (p *ProofRequestHolder) GetNumberOfCriteria() int {
	return len(p.SignedProofRequest.ProofRequest.Criteria)
}

// GetCriteria returns the Criterion at a given index in the underlying Proof Request. The Criterion and the necessary
// variables for evaluating any predicate conditions will be returned in a CriteriaHolder. An error is returned if
// the index is outside of the range of the proof request, see GetNumberOfCriteria.
func (p *ProofRequestHolder) GetCriteria(index int) (*presentation.CriteriaHolder, error) {
	numberOfCriteria := len(p.SignedProofRequest.ProofRequest.Criteria)
	if index > (numberOfCriteria - 1) {
		err := fmt.Errorf("index out of bounds %d elements in the array", numberOfCriteria)
		return nil, err
	}

	holder := presentation.CriteriaHolder{
		Index:     index,
		Criterion: p.SignedProofRequest.ProofRequest.Criteria[index],
		Variables: p.SignedProofRequest.Variables,
	}
	return &holder, nil
}

func (p *ProofRequestHolder) FulfillCriteria(criteria *presentation.CriteriaHolder, creds []credential.UnsignedVerifiableCredential, keyRef string, signingKey ed25519.PrivateKey) error {
	signer, err := proof.NewEd25519Signer(signingKey, keyRef)
	if err != nil {
		return err
	}
	fulfilledCriterion, err := response.FulfillCriterionForVCs(criteria.Criterion, criteria.Variables, creds, signer)
	if err != nil {
		return err
	}
	if p.ProofResponseElements == nil {
		p.ProofResponseElements = make(map[int]presentation.FulfilledCriterion)
	}
	p.ProofResponseElements[criteria.Index] = *fulfilledCriterion
	return nil
}

func IsV1Credential(credStr string) bool {
	return strings.Contains(credStr, "claimProof")
}

func (p *ProofRequestHolder) GenerateProofResponse(keyRef string, signingKey ed25519.PrivateKey) (*presentation.CompositeProofResponseSubmission, error) {
	// TODO check that each criteria is fulfilled, if not check if the criterion is totally optional
	var fulfilledCriterion []presentation.FulfilledCriterion
	for _, resp := range p.ProofResponseElements {
		fulfilledCriterion = append(fulfilledCriterion, resp)
	}

	signer, err := proof.NewEd25519Signer(signingKey, keyRef)
	if err != nil {
		return nil, err
	}
	return response.GenerateCompositeProofResponse(p.SignedProofRequest, fulfilledCriterion, signer)
}

func (p *ProofRequestHolder) CheckVerifierSignature(verifierDIDDoc ledger.DIDDoc) error {
	proofReq := p.SignedProofRequest
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