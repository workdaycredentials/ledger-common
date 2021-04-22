package presexchange

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PaesslerAG/jsonpath"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/definition"
	"github.com/decentralized-identity/presentation-exchange-implementations/pkg/submission"
	errs "github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/ledger/schema"
	"github.com/workdaycredentials/ledger-common/proof"
)

func VerifyVerifiablePresentation(verifier proof.Verifier, def definition.PresentationDefinition, vp VerifiablePresentation) error {
	// First check the signature on the VP
	if vp.IsEmpty() || vp.PresentationSubmission == nil {
		return errors.New("cannot verify empty presentation")
	}
	suite, err := proof.SignatureSuites().GetSuite(vp.GetProof().Type, proof.V2)
	if err != nil {
		return err
	}
	if err := suite.Verify(&vp, verifier); err != nil {
		return err
	}

	// Next, make sure the Request claims to satisfy the Presentation Definition
	if err := validateSubmissionMetadataAgainstDefinition(def, *vp.PresentationSubmission); err != nil {
		return err
	}

	// Build a map of input descriptors for quicker lookup
	inputDescriptors := make(map[string]definition.InputDescriptor)
	for _, descriptor := range def.InputDescriptors {
		inputDescriptors[descriptor.ID] = descriptor
	}

	// Marshal & unmarshal into an interface{} for JSON-path credential parsing
	vpBytes, err := json.Marshal(vp)
	if err != nil {
		return err
	}
	var vpGeneric interface{}
	if err := json.Unmarshal(vpBytes, &vpGeneric); err != nil {
		return err
	}

	// Keys are groups, values are descriptors
	groupedDescriptors := make(map[string][]string)
	// Check each input descriptor against the submitted credentials
	// Build a set from descriptor id to whether it was fulfilled by the submission
	var unfulfilledDescriptors []string
	// track # that were fulfilled
	for _, descriptor := range vp.PresentationSubmission.DescriptorMap {
		// TODO support for multiple formats and signature types
		if descriptor.Format != definition.CredentialFormat(definition.LDPVP) {
			return fmt.Errorf("unsupported descriptor format: %s", descriptor.Format)
		}
		inputDescriptor, ok := inputDescriptors[descriptor.ID]
		if !ok {
			return fmt.Errorf("could not find definition with input descriptor id<%s>", inputDescriptor.ID)
		}

		// Get credential that corresponds with the descriptor
		cred, err := jsonpath.Get(descriptor.Path, vpGeneric)
		if err != nil {
			return err
		} else if cred == nil {
			return fmt.Errorf("credential not found for descriptor<%s> path: %s", descriptor.ID, descriptor.Path)
		}

		// Validate the descriptor against the pathed credential
		if err := validateDescriptor(inputDescriptor, cred, vp.GetProof().GetVerificationMethod()); err != nil {
			logrus.Errorf("descriptor not fulfilled: %s", descriptor.ID)
			unfulfilledDescriptors = append(unfulfilledDescriptors, descriptor.ID)
		} else {
			// Track the fulfilled descriptors by group
			for _, group := range inputDescriptor.Group {
				currentGroup := groupedDescriptors[group]
				groupedDescriptors[group] = append(currentGroup, descriptor.ID)
			}
		}
	}

	// Now, check if there are submission requirements
	// If there are none, check if all input descriptors were fulfilled
	if len(def.SubmissionRequirements) > 0 {
		// build a map of how many input descriptors are in each group
		groupLengths := groupFrequency(def.InputDescriptors)
		return checkSubmissionRequirements(groupLengths, groupedDescriptors, def.SubmissionRequirements)
	} else if len(unfulfilledDescriptors) == 0 {
		return nil
	} else {
		// here, we have unfulfilled descriptors without submission requirements -- an error
		// collect unfulfilled descriptors to return as an error
		errMsg := fmt.Sprintf("submission not accepted, <%d>descriptors not able to be fulfilled: %s", len(unfulfilledDescriptors), strings.Join(unfulfilledDescriptors, ", "))
		logrus.Error(errMsg)
		return errors.New(errMsg)
	}
}

// get how many input descriptors there are in each group
func groupFrequency(descriptors []definition.InputDescriptor) map[string]int {
	freqMap := make(map[string]int)
	for _, desc := range descriptors {
		for _, g := range desc.Group {
			freqMap[g] += 1
		}
	}
	return freqMap
}

func checkSubmissionRequirements(groupLengths map[string]int, groupedDescriptors map[string][]string, requirements []definition.SubmissionRequirement) error {
	// since each requirement needs to be fulfilled, we check each requirement
	for _, req := range requirements {
		if err := checkSubmissionRequirement(groupLengths, groupedDescriptors, req); err != nil {
			return err
		}
	}
	return nil
}

func checkSubmissionRequirement(groupLengths map[string]int, groupedDescriptors map[string][]string, requirement definition.SubmissionRequirement) error {
	// base case: from, not from nested
	from := requirement.From
	if from != "" {
		lower, upper, err := setBoundsForFromGroup(from, groupedDescriptors, requirement)
		if err != nil {
			return err
		}
		fulfilled, ok := groupedDescriptors[from]
		if !ok {
			return fmt.Errorf("no descriptors fulfilled for group<%s>", from)
		}
		numFulfilled := len(fulfilled)
		// TODO: should we fail if we get too many, or just exclude extras?
		if numFulfilled < lower || numFulfilled > upper {
			return fmt.Errorf("needed between<%d> and <%d> descriptors fulfilled from<%s> and received <%d>", lower, upper, from, numFulfilled)
		}
	} else {
		return checkSubmissionRequirements(groupLengths, groupedDescriptors, requirement.FromNested)
	}
	return nil
}

// set the lower and upper bounds for how many descriptors are needed from a given group
func setBoundsForFromGroup(from string, groupedDescriptors map[string][]string, requirement definition.SubmissionRequirement) (lower int, upper int, err error) {
	// set upper and lower bounds for how many groups need to be fulfilled
	if requirement.Rule == definition.All {
		descriptors, ok := groupedDescriptors[from]
		if !ok {
			err = fmt.Errorf("no descriptors fulfilled for group<%s>", from)
			return
		}
		count := len(descriptors)
		lower = count
		upper = count
	} else if requirement.Count != 0 {
		// see how many descriptors are needed (these are all optional fields)
		lower = requirement.Count
		upper = requirement.Count
	} else {
		lower = requirement.Minimum
		upper = requirement.Maximum
	}
	return
}

// This does not validate any of the credentials. Instead, we do cursory checking on identifiers between the
// definition and the submission as the first line of validations.
func validateSubmissionMetadataAgainstDefinition(def definition.PresentationDefinition, sub submission.PresentationSubmission) error {
	// simple descriptor checks first
	if def.ID != sub.DefinitionID {
		return fmt.Errorf("definition ID<%s> does not match the definition ID in the submission<%s>", def.ID, sub.DefinitionID)
	}

	// NOTE: this could be improved to check if each submission requirement could be met
	// in some cases it's okay to have unfulfilled input descriptors if all submission requirements
	// can be satisfied without these input descriptors being satisfied. if there are submission requirements
	// we skip this check to save some time
	if len(def.SubmissionRequirements) > 0 {
		logrus.Warn("submission requirements present; did not verify input descriptors could fulfill the request")
		return nil
	}

	// build a set of all input descriptor ids in the definition to match them up with those in the submission
	ids := make(map[string]bool)
	for _, descriptor := range def.InputDescriptors {
		ids[descriptor.ID] = true
	}
	for _, descriptor := range sub.DescriptorMap {
		id := descriptor.ID
		if _, ok := ids[id]; !ok {
			return fmt.Errorf("could not find descriptor<%s> in definition<%s>", id, def.ID)
		}
		// delete so we can see if all have been met
		delete(ids, id)
	}
	if len(ids) > 0 {
		var remainingIDs []string
		for id := range ids {
			remainingIDs = append(remainingIDs, id)
		}
		return fmt.Errorf("descriptors in the definition were unfulfilled: %s", strings.Join(remainingIDs, ", "))
	}
	return nil
}

func validateDescriptor(descriptor definition.InputDescriptor, genericCred interface{}, verificationMethod string) error {
	credBytes, err := json.Marshal(genericCred)
	if err != nil {
		return err
	}
	var cred credential.VerifiableCredential
	if err := json.Unmarshal(credBytes, &cred); err != nil {
		return err
	}
	// TODO(gabe) this is where we should verify the signature of the provided credential
	if cred.IsEmpty() {
		return fmt.Errorf("cannot validate descriptor<%s> against empty credential", descriptor.ID)
	}
	logrus.Debugf("validating cred<%s> against descriptor<%+v>", cred.ID, descriptor)

	// Check the schemas match
	for _, s := range descriptor.Schema {
		if s.URI != cred.Schema.ID && s.Required {
			return fmt.Errorf("required s<%s> does not match credential s<%s>", s.URI, cred.Schema.ID)
		}
	}

	// Check each constraint
	sub, ok := cred.CredentialSubject[credential.SubjectIDAttribute]
	subject := sub.(string)
	if !ok {
		return errors.New("credential did not have `id` subject")
	}
	if descriptor.Constraints.SubjectIsIssuer != nil &&
		*descriptor.Constraints.SubjectIsIssuer == definition.Required &&
		subject != cred.Issuer.String() {
		return fmt.Errorf("subject is issuer required and subject<%s> does not match issuer<%s>", subject, cred.Issuer)
	}
	if descriptor.Constraints.SubjectIsHolder != nil &&
		*descriptor.Constraints.SubjectIsHolder == definition.Required &&
		!strings.Contains(verificationMethod, subject) {
		return fmt.Errorf("subject is holder required and subject<%s> does not match holder<%s>", subject, verificationMethod)
	}
	// Check each field in the constraint
	for _, field := range descriptor.Constraints.Fields {
		if err := checkField(cred.ID, genericCred, field); err != nil {
			return err
		}
	}
	return nil
}

func checkField(credID string, genericCred interface{}, field definition.Field) error {
	// NOTE: predicate proofs are not currently supported
	if field.Predicate != nil {
		return errors.New("predicate field filtering not supported")
	}

	// Apply the field path(s) to the credential JSON
	// There may be multiple path, but we only need one to succeed
	var pathedData []string
	for _, path := range field.Path {
		pathed, err := jsonpath.Get(path, genericCred)
		if err != nil {
			return err
		}
		pathedString := pathed.(string)
		if pathedString != "" {
			pathedData = append(pathedData, pathed.(string))
		}
	}
	if len(pathedData) < 1 {
		return errors.New("no data was extracted from the credential using the provided path(s)")
	}

	// Turn the filter into a json schema, make sure it's a valid json schema,
	// then validate the pathed data from the credential against it
	filterBytes, err := json.Marshal(field.Filter)
	if err != nil {
		return err
	}
	filterSchema := string(filterBytes)
	if err := schema.ValidateJSONSchemaString(filterSchema); err != nil {
		return errs.Wrap(err, "filter is not a valid json schema")
	}
	for _, pathed := range pathedData {
		// if one works, the filter is fulfilled
		if err := schema.Validate(filterSchema, jsonify(pathed)); err == nil {
			return nil
		}
	}
	err = fmt.Errorf("unable to validate credential<%s> against filter<%+v>", credID, field.Filter)
	logrus.WithError(err).Error()
	return err
}

func jsonify(data string) string {
	if schema.IsJSON(data) {
		return data
	}
	// try to wrap it
	return fmt.Sprintf("\"%s\"", data)
}
