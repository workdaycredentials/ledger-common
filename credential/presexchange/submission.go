package presexchange

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/submission"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/submission/verifiablepresentation"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/xeipuuv/gojsonschema"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/proof"
	utils "github.com/workdaycredentials/ledger-common/util"

	"github.com/PaesslerAG/jsonpath"
)

const (
	enUSLocale      = "en-US"
	credSubjectPath = "$.credentialSubject."

	Limited Disclosure = true
	Open    Disclosure = false
)

var (
	defaultVPContexts = []string{
		"https://www.w3.org/2018/credentials/v1",
		"https://identity.foundation/presentation-exchange/submission/v1",
	}
	defaultVPTypes    = []string{"VerifiablePresentation", "PresentationSubmission"}
	credSubjectIDPath = credSubjectPath + credential.SubjectIDAttribute
)

type (
	Disclosure bool

	PresentationSubmission struct {
		// The request being responded to
		request PresentationRequest

		// Public key wrapped for identity requesting credential data
		requesterVerifier proof.Verifier

		// Used to sign responding verifiable presentation by the target of the request
		responderSigner proof.Signer
	}

	// Holder type after JSON paths have been applied to a credential
	criterionToFilter struct {
		descriptorID string
		pathedData   interface{}
		cred         credential.VerifiableCredential
	}

	// Represents a credential and descriptors data for a fulfilled criterion
	fulfilledCriterion struct {
		DescriptorID string
		CredID       string
		Cred         credential.VerifiableCredential
	}
)

func NewPresentationSubmission(requesterPubKey ed25519.PublicKey, responderSigner proof.Signer, request PresentationRequest) (*PresentationSubmission, error) {
	if err := util.Validate(request.Definition); err != nil {
		logrus.WithError(err).Errorf("Invalid Presentation Request: %s", request.ID)
		return nil, err
	}
	var verifier proof.Verifier
	if requesterPubKey != nil {
		verifier = &proof.Ed25519Verifier{PubKey: requesterPubKey}
	}
	return &PresentationSubmission{
		request:           request,
		requesterVerifier: verifier,
		responderSigner:   responderSigner,
	}, nil
}

type requestFulfiller struct {
	responderID string
	descriptors []definition.InputDescriptor
	credentials []credential.VerifiableCredential
}

func (ps PresentationSubmission) FulfillPresentationRequestAsVP(creds []credential.VerifiableCredential) (*verifiablepresentation.VerifiablePresentation, error) {
	// First validate the proof on the request
	// NOTE: first iterations of this protocol do not require a verifier, which is why this check is here. It may be later removed.
	if ps.requesterVerifier != nil && ps.request.Proof != nil {
		suite, err := proof.SignatureSuites().GetSuiteForProof(ps.request.Proof)
		if err != nil {
			return nil, err
		}
		if err := suite.Verify(&ps.request, ps.requesterVerifier); err != nil {
			logrus.WithError(err).Errorf("The Presentation Submission's proof could not be validated: %s", ps.request.ID)
			return nil, err
		}
	} else {
		logrus.Warn("Requester's public key was not provided; presentation request signature could not be verified")
	}

	// Next, we build a verifiable presentation
	vpBuilder := verifiablepresentation.NewVerifiablePresentationBuilder()
	vpBuilder.SetContext(defaultVPContexts)
	vpBuilder.SetType(defaultVPTypes)

	// NOTE: there is an assumption that all VCs passed in are of the right format for the presentation definition
	// Do the fulfilling and handle case where there are optional submission requirements
	var fulfilledCriteria []fulfilledCriterion
	var err error
	requirements := ps.request.Definition.SubmissionRequirements
	descriptors := ps.request.Definition.InputDescriptors
	responderID := ps.responderSigner.ID()

	fulfiller := requestFulfiller{responderID: responderID, descriptors: descriptors, credentials: creds}
	// If there are submission requirements fulfilling them is sufficient to satisfy the request
	if len(requirements) > 0 {
		fulfilledCriteria, err = fulfiller.fulfillRequirements(requirements)
		if err != nil {
			logrus.WithError(err).Error("requirement(s) could not be fulfilled")
			return nil, err
		}
	} else {
		// If there are no submission requirements we fulfill all input descriptors.
		fulfilledCriteria, err = fulfiller.fulfillInputDescriptors()
		if err != nil {
			logrus.WithError(err).Error("input descriptor(s) could not be fulfilled")
			return nil, err
		}
	}

	// Merge attributes by credential
	mergedCriteria := mergeCriteria(fulfilledCriteria)

	// Next we build the descriptors map that corresponds to the verifiable presentation
	// Pull out the creds to add them all at once
	var fulfilledCreds []interface{}
	for _, criterion := range mergedCriteria {
		fulfilledCreds = append(fulfilledCreds, criterion.genericCred)
	}
	vpBuilder.AddVerifiableCredentials(fulfilledCreds...)

	// See which credentials fulfill the request and build the response
	builder := submission.NewPresentationSubmissionBuilder()
	builder.SetLocale(enUSLocale)

	// Add descriptors to the builder for each fulfilled credential
	for _, criterion := range mergedCriteria {
		for _, descriptor := range criterion.descriptors {
			if err := builder.AddDescriptor(descriptor); err != nil {
				logrus.WithError(err).Errorf("problem adding descriptor to map: %s", descriptor.ID)
				return nil, err
			}
		}
	}

	// set the presentation submission on the vp builder
	presSubmissionHolder, err := builder.Build()
	if err != nil {
		logrus.WithError(err).Error("could not build Presentation Submission")
		return nil, err
	}
	if err := vpBuilder.SetPresentationSubmission(presSubmissionHolder.PresentationSubmission); err != nil {
		logrus.WithError(err).Error("Presentation Submission could not be set")
		return nil, err
	}

	// build
	verifiablePres, err := vpBuilder.Build()
	if err != nil {
		logrus.WithError(err).Error("could not build presentation")
		return nil, err
	}

	// unset the empty proof, convert to our presentation for signing
	verifiablePres.Proof = nil

	// build suite and sign
	// TODO(gabe) variable signature types for presentations
	signatureType := proof.JCSEdSignatureType
	suite, err := proof.SignatureSuites().GetSuite(signatureType, proof.V2)
	if err != nil {
		return nil, err
	}
	vp := VerifiablePresentation(*verifiablePres)
	options := &proof.ProofOptions{ProofPurpose: proof.AssertionMethodPurpose}
	if err := suite.Sign(&vp, ps.responderSigner, options); err != nil {
		logrus.WithError(err).Error("Could not sign presentation")
		return nil, err
	}

	// convert back and return, making sure the original and pointer objects contain the same values
	*verifiablePres = verifiablepresentation.VerifiablePresentation(vp)
	return (*verifiablepresentation.VerifiablePresentation)(&vp), nil
}

// For a set of input descriptors and credentials, see which input descriptors can be fulfilled. if any cannot we have an error
func (rf requestFulfiller) fulfillInputDescriptors() ([]fulfilledCriterion, error) {
	var fulfilledCriteria []fulfilledCriterion
	for _, descriptor := range rf.descriptors {
		fulfilled, err := fulfillDescriptor(descriptor, rf.credentials, rf.responderID)
		if err != nil {
			logrus.WithError(err).Errorf("Presentation Request could not be fulfilled — descriptor could not be fulfilled: %s", descriptor.ID)
			return nil, err
		}
		fulfilledCriteria = append(fulfilledCriteria, fulfilled...)
	}
	return fulfilledCriteria, nil
}

func (rf requestFulfiller) fulfillRequirements(requirements []definition.SubmissionRequirement) ([]fulfilledCriterion, error) {
	var res []fulfilledCriterion
	originalDescriptors := rf.descriptors
	for _, requirement := range requirements {
		// find the input descriptor(s) that match the requirement and update fulfiller
		descriptorsForRequirement, err := gatherInputDescriptorsForRequirement(requirement, rf.descriptors)
		rf.descriptors = descriptorsForRequirement
		if err != nil {
			return nil, errors.Wrapf(err, "descriptors could not be found to fulfill the requirement: %+v", requirement)
		}
		fulfilled, err := rf.fulfillRequirement(requirement)
		if err != nil {
			logrus.WithError(err).Errorf("requirement could not be fulfilled: %+v", requirement)
			return nil, err
		}
		res = append(res, fulfilled...)

		// set back the descriptors after filtering
		rf.descriptors = originalDescriptors
	}
	return res, nil
}

// Filter the input descriptors to those that could possibly fulfill the requirement
func gatherInputDescriptorsForRequirement(requirement definition.SubmissionRequirement, descriptors []definition.InputDescriptor) ([]definition.InputDescriptor, error) {
	def, _, err := gatherInputDescriptorsForRequirementRec(requirement, descriptors, 0)
	return def, err
}

func gatherInputDescriptorsForRequirementRec(requirement definition.SubmissionRequirement, descriptors []definition.InputDescriptor, depth int) ([]definition.InputDescriptor, int, error) {
	// 3 cases: from or from nested or error
	hasFrom := requirement.From != ""
	hasFromNested := requirement.FromNested != nil
	if (hasFrom && hasFromNested) || (!hasFrom && !hasFromNested) {
		return nil, depth, errors.Errorf("invalid combination of From and From Nested exists in the requirement: %+v", requirement)
	}

	var filteredDescriptors []definition.InputDescriptor
	var filteredFromNested []definition.InputDescriptor
	var err error
	if hasFrom {
		group := requirement.From
		for _, desc := range descriptors {
			if utils.StringSliceContains(desc.Group, group) {
				filteredDescriptors = append(filteredDescriptors, desc)
			}
		}
	} else if hasFromNested {
		for _, fromRequirement := range requirement.FromNested {
			filteredFromNested, _, err = gatherInputDescriptorsForRequirementRec(fromRequirement, descriptors, depth+1)
			if err != nil {
				return nil, depth, errors.Wrapf(err, "could not gather input descriptors for nested requirement: %+v", fromRequirement)
			}
			filteredDescriptors = append(filteredDescriptors, filteredFromNested...)
		}
	}
	if len(filteredDescriptors) == 0 && depth == 0 {
		err = errors.Errorf("no input descriptors found to fulfill submission requirement")
	}
	return filteredDescriptors, depth, err
}

// Fulfill requirement has the precondition that the descriptors have been filtered properly to those that could
//  be fulfilled for the given requirement
func (rf requestFulfiller) fulfillRequirement(requirement definition.SubmissionRequirement) ([]fulfilledCriterion, error) {
	logrus.Debugf("fulfilling requirement: %+v", requirement)
	// assume the max = # of descriptors
	defaultMax := len(rf.descriptors)
	min, max, err := calculateRequirementMinMax(requirement, defaultMax)
	if err != nil {
		return nil, err
	}

	// now that we've calculated our min and max values, do the fulfilling
	var fulfilledCriteria []fulfilledCriterion
	for _, descriptor := range rf.descriptors {
		fulfilled, err := fulfillDescriptor(descriptor, rf.credentials, rf.responderID)
		if err != nil {
			// we warn here but do not error — the requirement could be fulfilled without each descriptor
			logrus.WithError(err).Warnf("Descriptor for submission requirement could not be fulfilled: %s", descriptor.ID)
		} else {
			fulfilledCriteria = append(fulfilledCriteria, fulfilled...)
		}
		// only fulfill up to max criteria
		if len(fulfilledCriteria) == max {
			break
		}
	}

	// determine if the requirement has been satisfied
	numFulfilled := len(fulfilledCriteria)
	if numFulfilled < min || numFulfilled > max {
		return nil, fmt.Errorf("requirement could not be satisfied: %+v", requirement)
	}

	return fulfilledCriteria, nil
}

// determine the lower and upper bounds of credentials to fulfill a requirement
func calculateRequirementMinMax(requirement definition.SubmissionRequirement, defaultMax int) (min, max int, err error) {
	rule := requirement.Rule
	count := requirement.Count
	minimum := requirement.Minimum
	maximum := requirement.Maximum

	switch rule {
	case definition.All:
		if count > 0 || minimum > 0 || maximum > 0 {
			err = errors.New("count, min, and/or max present for all rule")
			return
		}
		min = defaultMax
		max = defaultMax
	case definition.Pick:
		// first case is count present
		// error cases first
		if count < 0 || minimum < 0 || maximum < 0 || (maximum > 0 && minimum > maximum) {
			err = errors.New("invalid value for count, min, and/or max")
			return
		}
		if maximum > defaultMax {
			err = fmt.Errorf("maximum<%d> is greater than the number of descriptors<%d>", maximum, defaultMax)
			return
		}
		if count > 0 {
			if minimum > 0 || maximum > 0 {
				err = errors.New("count, min, and max present")
				return
			}
			min = count
			max = count
			// next case is min
		} else if minimum > 0 {
			min = minimum
			max = defaultMax
			// min && max
			if maximum > 0 {
				max = maximum
			}
			// next case is max without min
		} else if maximum > 0 {
			min = 0
			max = maximum
			// last case is no count, min, or max and we have an error!
		} else {
			err = fmt.Errorf("requirement uses pick rule but does not specify count, min, or max: %s", requirement.Name)
		}
	default:
		err = fmt.Errorf("unknown rule type: %s", rule)
	}
	return
}

// For a given input descriptors and set of credentials, return the criteria that fulfill the descriptors
func fulfillDescriptor(descriptor definition.InputDescriptor, creds []credential.VerifiableCredential, responderID string) ([]fulfilledCriterion, error) {
	// first filter the credentials based on the schemas associated with the descriptors & consider subject restrictions
	credsForSchema, err := filterApplicableCredentials(descriptor.Schema.URI, descriptor.Constraints, creds, responderID)
	if err != nil {
		return nil, errors.Wrapf(err, "could not filter credentials for descriptor: %s", descriptor.ID)
	}
	var fulfilled []fulfilledCriterion

	// Handle case where there are no constraints
	if descriptor.Constraints == nil {
		var fulfilled []fulfilledCriterion
		for _, cred := range creds {
			fulfilled = append(fulfilled, fulfilledCriterion{
				DescriptorID: descriptor.ID,
				CredID:       cred.ID,
				Cred:         cred,
			})
		}
		return fulfilled, nil
	}

	// For each constraint in the descriptors apply the JSON Path selector and then the filter itself
	for _, field := range descriptor.Constraints.Fields {
		if field.Predicate != nil {
			return nil, fmt.Errorf("predicates are not supported: %+v", field)
		}
		// first get the data using the JSON path
		toFilter, err := applyPaths(descriptor.ID, field.Path, Disclosure(descriptor.Constraints.LimitDisclosure), credsForSchema)
		if err != nil {
			return nil, errors.Wrap(err, "could not apply path to credentials")
		}

		// next apply the filter
		filtered, err := applyFilter(*field.Filter, toFilter)
		if err != nil {
			return nil, errors.Wrap(err, "could not apply filter to credentials")
		}
		fulfilled = append(fulfilled, filtered...)
	}

	// maps credential to number of applicable filters
	setOfCounters := map[string]int{}
	for i := range fulfilled {
		setOfCounters[fulfilled[i].CredID]++
	}

	var pos int
	for i := range fulfilled {
		// checks whether the number of applicable filters is equal to the number of all filters
		// if numbers are different than we will ignore the credential
		if setOfCounters[fulfilled[i].CredID] == len(descriptor.Constraints.Fields) {
			fulfilled[pos] = fulfilled[i]
			pos++
		}
	}

	return fulfilled[:pos], nil
}

// For a given set of schema IDs and credentials, return the credentials that have been issued against the listed schema(s)
func filterApplicableCredentials(schemaIDs []string, constraints *definition.Constraints, creds []credential.VerifiableCredential, responderID string) ([]credential.VerifiableCredential, error) {
	var subjectIsHolderRequired, subjectIsIssuerRequired bool
	if constraints != nil {
		subjectIsIssuerRequired, subjectIsHolderRequired = subjectConstraints(*constraints)
	}
	// build a map of schema ids for quick lookup
	schemaIDsMap := make(map[string]bool)
	for _, id := range schemaIDs {
		schemaIDsMap[id] = true
	}
	var result []credential.VerifiableCredential
	for _, cred := range creds {
		// if the id is in the map AND the subject constraint is met we've found a credential to return
		if _, ok := schemaIDsMap[cred.Schema.ID]; ok {
			if subjectIsHolderRequired || subjectIsIssuerRequired {
				subjectID, ok := cred.CredentialSubject[credential.SubjectIDAttribute]
				if !ok {
					return nil, errors.Errorf("credential<%s> subject id attribute not found", cred.ID)
				}
				if subjectIsHolderRequired && !strings.Contains(responderID, subjectID.(string)) {
					return nil, errors.Errorf("subject is holder required and subject (responder)<%s> not equal to holder<%s>", responderID, subjectID)
				}
				// the credential must be self attested
				if subjectIsIssuerRequired && subjectID != cred.Issuer {
					return nil, errors.Errorf("subject is issuer required and subject<%s> not equal to issuer<%s>", subjectID, cred.Issuer)
				}
			}
			result = append(result, cred)
		}
	}
	return result, nil
}

// We only care about required restrictions and making sure the constraints are valid.
func subjectConstraints(constraints definition.Constraints) (subjectIsIssuerRequired bool, subjectIsHolderRequired bool) {
	holder := constraints.SubjectIsHolder
	issuer := constraints.SubjectIsIssuer
	holderNil := holder == nil
	issuerNil := issuer == nil

	// if they're both nil we don't care
	if holderNil && issuerNil {
		return
	}
	if !holderNil && *holder == definition.Required {
		subjectIsHolderRequired = true
	}
	if !issuerNil && *issuer == definition.Required {
		subjectIsIssuerRequired = true
	}
	return
}

// Apply a set of JSON paths to a set of credentials. Return sets of <pathed data, credential>
func applyPaths(descriptorID string, paths []string, disclosure Disclosure, creds []credential.VerifiableCredential) ([]criterionToFilter, error) {
	var res []criterionToFilter
	for _, cred := range creds {
		for _, path := range paths {
			// apply path to credential
			pathed, err := applyPath(cred, path)
			if err != nil {
				logrus.WithError(err).Warnf("Could not apply path<%s> to cred<%s>", path, cred.ID)
			} else {
				// apply filtering if disclosure is being limited
				criterion, err := toCriterion(descriptorID, path, pathed, cred, disclosure)
				if err != nil {
					return nil, errors.Wrap(err, "error building criterion")
				}
				res = append(res, *criterion)
			}
		}
	}
	if len(res) == 0 {
		return nil, errors.New("no credentials fit paths")
	}
	return res, nil
}

func toCriterion(descriptorID string, path string, pathed interface{}, cred credential.VerifiableCredential, disclosure Disclosure) (*criterionToFilter, error) {
	if disclosure == Open {
		return &criterionToFilter{
			descriptorID: descriptorID,
			pathedData:   pathed,
			cred:         cred,
		}, nil
	}

	// we always include the subject's id attribute
	// we omit the proof, because it is no longer valuable with a subset of the attributes
	subject, ok := cred.CredentialSubject[credential.SubjectIDAttribute]
	if !ok {
		return nil, errors.New("cred is malformed: does not contain \"id\" attribute")
	}
	// subject proofs are optional for interoperability
	subjectProof, ok := cred.ClaimProofs[credential.SubjectIDAttribute]
	if !ok {
		logrus.Warn("cred is malformed: does not contain \"id\" attribute proof, omitting...")
	}
	filteredCred := credential.VerifiableCredential{
		UnsignedVerifiableCredential: credential.UnsignedVerifiableCredential{
			Metadata: cred.Metadata,
			CredentialSubject: map[string]interface{}{
				credential.SubjectIDAttribute: subject,
			},
			ClaimProofs: map[string]proof.Proof{
				credential.SubjectIDAttribute: subjectProof,
			},
		},
	}

	// if ID is the only attribute we can maintain the entire credential and return early
	if len(cred.CredentialSubject) == 1 {
		return &criterionToFilter{
			descriptorID: descriptorID,
			pathedData:   pathed,
			cred:         cred,
		}, nil
	}

	// if the pathed data is a credentialSubject we need need to append more attributes and their proofs
	// however, if the requested path is the id we do not need to proceed as we've already handled it
	if strings.Contains(path, credSubjectPath) && (path != credSubjectIDPath) {
		// check the separators: if more than 2 (three separate parts) we have a nested cred
		if len(strings.Split(path, ".")) > 3 {
			return nil, errors.Errorf("path contains nested reference which is not currently supported: %s", path)
		}

		// get the subject and add it to the filtered cred
		subject := path[strings.LastIndex(path, ".")+1:]
		subjectValue, ok := cred.CredentialSubject[subject]
		if !ok {
			return nil, errors.Errorf("cred does not contain the <%s> attribute", subject)
		}
		filteredCred.CredentialSubject[subject] = subjectValue

		// get the subject proof and add it to the filtered cred
		subjectValueProof, ok := cred.ClaimProofs[subject]
		if !ok {
			return nil, errors.Errorf("cred does not contain the <%s> attribute proof", subject)
		}
		filteredCred.ClaimProofs[subject] = subjectValueProof
	}

	return &criterionToFilter{
		descriptorID: descriptorID,
		pathedData:   pathed,
		cred:         filteredCred,
	}, nil
}

// turn a cred into its generic (interface) form for applying a json path, return the result
func applyPath(cred credential.VerifiableCredential, path string) (interface{}, error) {
	credBytes, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	var genericCred interface{}
	if err := json.Unmarshal(credBytes, &genericCred); err != nil {
		return nil, err
	}
	return jsonpath.Get(path, genericCred)
}

func applyFilter(filter definition.Filter, criteria []criterionToFilter) ([]fulfilledCriterion, error) {
	filterBytes, err := json.Marshal(filter)
	if err != nil {
		logrus.WithError(err).Error("Could not build criteria filter")
		return nil, err
	}
	var fulfilled []fulfilledCriterion
	filterSchema := gojsonschema.NewStringLoader(string(filterBytes))
	for _, criterion := range criteria {
		dataBytes, err := json.Marshal(criterion.pathedData)
		if err != nil {
			return nil, err
		}
		data := gojsonschema.NewStringLoader(string(dataBytes))
		// validate the data against the filter
		if err := schema.ValidateWithJSONLoader(filterSchema, data); err == nil {
			fulfilled = append(fulfilled, fulfilledCriterion{
				DescriptorID: criterion.descriptorID,
				CredID:       criterion.cred.ID,
				Cred:         criterion.cred,
			})
		}
	}
	return fulfilled, nil
}

// Wraps a credential that fulfills descriptor(s), with submission information
type credAndDescriptors struct {
	genericCred interface{}
	descriptors []submission.Descriptor
}

// Because of selective disclosure and the design of our filtering mechanism,
// multiple criteria may belong to the same credential. This process takes those disparate
// criteria and groups them by credential to limit the number of criteria returned.
func mergeCriteria(fulfilled []fulfilledCriterion) []credAndDescriptors {
	// build an index of criteria by credential id
	criteriaByCredID := make(map[string][]fulfilledCriterion)
	for _, criterion := range fulfilled {
		credID := criterion.CredID
		criteria, ok := criteriaByCredID[credID]
		// if no slice exists for the cred, create a new one
		if !ok {
			criteria = make([]fulfilledCriterion, 0)
		}
		criteria = append(criteria, criterion)
		criteriaByCredID[credID] = criteria
	}

	// use the built index to merge credentials by id
	var res []credAndDescriptors
	// track which descriptor ids have already been set
	descriptorIDs := make(map[string]bool)
	descriptorIndex := 0
	for _, criteria := range criteriaByCredID {
		// set the cred to the first value as a starting point
		cred := criteria[0].Cred
		var descriptors []submission.Descriptor
		for i := 0; i < len(criteria); i++ {
			currentCriterion := criteria[i]
			currentDescriptorID := currentCriterion.DescriptorID
			descriptor := submission.Descriptor{
				ID:     currentDescriptorID,
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", descriptorIndex),
				Format: definition.CredentialFormat(definition.LDPVP),
			}

			// if any of the creds have a proof we know the whole credential is present
			// and we can break early. selectively disclosed creds do not have this proof
			if currentCriterion.Cred.Proof != nil {
				cred = currentCriterion.Cred
			} else {
				// otherwise, add all claims and proofs from each criteria to the resulting cred
				for k, v := range currentCriterion.Cred.CredentialSubject {
					cred.CredentialSubject[k] = v
				}
				for k, v := range currentCriterion.Cred.ClaimProofs {
					cred.ClaimProofs[k] = v
				}
			}

			// if the current descriptor id is not set, add it
			if _, ok := descriptorIDs[currentDescriptorID]; !ok {
				descriptors = append(descriptors, descriptor)
				descriptorIDs[currentDescriptorID] = true
			}
		}

		// append the merged cred to the result slice along with the fulfilled descriptor and up the descriptor index
		res = append(res, credAndDescriptors{
			genericCred: cred,
			descriptors: descriptors,
		})
		descriptorIndex++
	}
	return res
}
