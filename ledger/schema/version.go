package schema

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/workdaycredentials/ledger-common/did"
	"github.com/workdaycredentials/ledger-common/ledger"
)

const (
	VersionRxStr           = `^[0-9]+\.[0-9]+$`
	VersionPathResource    = "version"
	ResourceIDPathResource = "id"
	FragSep                = ";"
	FragAssignment         = "="
)

// VersionFromStr parses a version string into a Version object. Returns an error if the version
// string does not match the VersionRxStr regular expression, i.e. "<major>.<minor>", where major
// and minor are integers.
func VersionFromStr(versionStr string) (Version, error) {
	schemaVersionRx := regexp.MustCompile(VersionRxStr)
	if !schemaVersionRx.MatchString(versionStr) {
		return Version{}, UnRecognisedVersionError{versionStr}
	}

	vnums := strings.Split(versionStr, ".")
	major, err := strconv.Atoi(vnums[0])
	if err != nil {
		return Version{}, err
	}
	minor, err := strconv.Atoi(vnums[1])
	if err != nil {
		return Version{}, err
	}
	return Version{
		Major: major,
		Minor: minor,
	}, nil
}

// ValidateSchemaUpdate compares two schemas using schemaver rules and returns a summary
// of the update, which includes whether it's a major or minor change and a proposed version
// for the schema update.
func ValidateSchemaUpdate(schemaUpdateInput *UpdateInput) (*UpdateResult, error) {
	schemaUpdateResult, err := schemaUpdateInputValidation(schemaUpdateInput)
	if err != nil {
		return schemaUpdateResult, err
	}

	schemaUpdateResult.Valid = true

	isMajorChange := hasEditOrRemovalOfExistingFields(schemaUpdateInput)
	if isMajorChange {
		schemaUpdateResult.MajorChange = true
	}

	isMajorChange = hasRequiredPropertyBecomeOptional(schemaUpdateInput)
	if isMajorChange {
		schemaUpdateResult.MajorChange = true
	}

	isMajorChange = haveAdditionalPropertiesBeenDisallowed(schemaUpdateInput)
	if isMajorChange {
		schemaUpdateResult.MajorChange = true
	}

	isMinorChange := haveAdditionalPropertiesBeenAllowed(schemaUpdateInput)
	if isMinorChange {
		schemaUpdateResult.MinorChange = true
	}

	// check for addition of fields
	isMinorChange = haveNewFieldsBeenAdded(schemaUpdateInput)
	if isMinorChange {
		schemaUpdateResult.MinorChange = true
	}

	// is the schema name or description updated? -> MINOR
	if schemaUpdateInput.UpdatedSchema.Name != schemaUpdateInput.PreviousSchema.Name {
		schemaUpdateResult.MinorChange = true
	}

	if schemaUpdateInput.UpdatedSchema.Schema.Description() != schemaUpdateInput.PreviousSchema.Schema.Description() {
		schemaUpdateResult.MinorChange = true
	}

	// addition to list of required fields -> MINOR
	isMinorChange = areThereNewRequiredFields(schemaUpdateInput)
	if isMinorChange {
		schemaUpdateResult.MinorChange = true
	}

	if !schemaUpdateResult.MajorChange && !schemaUpdateResult.MinorChange {
		message := fmt.Sprintf("Schema has not been updated")
		schemaUpdateResult.Message = message
		schemaUpdateResult.Valid = false
		return schemaUpdateResult, fmt.Errorf(message)
	}

	return deriveVersionNumber(schemaUpdateInput, schemaUpdateResult)
}

func areThereNewRequiredFields(schemaUpdateInput *UpdateInput) bool {
	for _, requiredFieldInUpdated := range schemaUpdateInput.UpdatedSchema.Schema.RequiredFields() {
		if !ledger.Contains(requiredFieldInUpdated, schemaUpdateInput.PreviousSchema.Schema.RequiredFields()) {
			return true
		}
	}
	return false
}

func haveNewFieldsBeenAdded(schemaUpdateInput *UpdateInput) bool {
	updatedProperties := schemaUpdateInput.UpdatedSchema.JSONSchema.Schema.Properties()
	previousProperties := schemaUpdateInput.PreviousSchema.JSONSchema.Schema.Properties()

	for propertyNameInUpdated := range updatedProperties {
		_, propertyExistsInPrevious := previousProperties[propertyNameInUpdated]
		if !propertyExistsInPrevious {
			return true
		}
	}

	return false
}

func haveAdditionalPropertiesBeenAllowed(schemaUpdateInput *UpdateInput) bool {
	previousJSONSchemaMap := schemaUpdateInput.PreviousSchema.JSONSchema.Schema
	updatedJSONSchemaMap := schemaUpdateInput.UpdatedSchema.JSONSchema.Schema

	return !previousJSONSchemaMap.AllowsAdditionalProperties() && updatedJSONSchemaMap.AllowsAdditionalProperties()
}

func haveAdditionalPropertiesBeenDisallowed(schemaUpdateInput *UpdateInput) bool {
	previousJSONSchemaMap := schemaUpdateInput.PreviousSchema.JSONSchema.Schema
	updatedJSONSchemaMap := schemaUpdateInput.UpdatedSchema.JSONSchema.Schema

	return previousJSONSchemaMap.AllowsAdditionalProperties() && !updatedJSONSchemaMap.AllowsAdditionalProperties()
}

func hasRequiredPropertyBecomeOptional(schemaUpdateInput *UpdateInput) bool {
	isMajorChange := false

	previousJSONSchemaMap := schemaUpdateInput.PreviousSchema.JSONSchema.Schema
	updatedJSONSchemaMap := schemaUpdateInput.UpdatedSchema.JSONSchema.Schema

	previousRequired := previousJSONSchemaMap.RequiredFields()
	updatedRequired := updatedJSONSchemaMap.RequiredFields()
	for _, requiredFieldName := range previousRequired {
		if !ledger.Contains(requiredFieldName, updatedRequired) {
			isMajorChange = true
		}
	}

	return isMajorChange
}

func hasEditOrRemovalOfExistingFields(schemaUpdateInput *UpdateInput) bool {
	isMajorChange := false

	previousJSONSchemaMap := schemaUpdateInput.PreviousSchema.JSONSchema.Schema
	previousProperties := previousJSONSchemaMap.Properties()
	updatedJSONSchemaMap := schemaUpdateInput.UpdatedSchema.JSONSchema.Schema
	updatedProperties := updatedJSONSchemaMap.Properties()
	for propertyNameInPrevious, propertyInPrevious := range previousProperties {
		propertyInUpdated, propertyExistsInUpdated := updatedProperties[propertyNameInPrevious]
		if !propertyExistsInUpdated {
			isMajorChange = true
		} else {
			if ledger.Type(propertyInUpdated) != ledger.Type(propertyInPrevious) {
				isMajorChange = true
			}
			if ledger.Format(propertyInUpdated) != ledger.Format(propertyInPrevious) {
				isMajorChange = true
			}
		}
	}

	return isMajorChange
}

func deriveVersionNumber(schemaUpdateInput *UpdateInput, schemaUpdateResult *UpdateResult) (*UpdateResult, error) {
	previousVersion, err := schemaUpdateInput.PreviousSchema.Version()
	if err != nil {
		schemaUpdateResult.Valid = false
		return schemaUpdateResult, err
	}

	if schemaUpdateResult.MajorChange {
		derivedVersionNumber, err := incrementMajorVersion(previousVersion)
		if err != nil {
			return nil, err
		}
		schemaUpdateResult.DerivedVersion = derivedVersionNumber
		return schemaUpdateResult, nil
	}

	derivedVersionNumber, err := incrementMinorVersion(previousVersion)
	if err != nil {
		return nil, err
	}
	schemaUpdateResult.DerivedVersion = derivedVersionNumber
	return schemaUpdateResult, nil
}

func schemaUpdateInputValidation(schemaUpdateInput *UpdateInput) (*UpdateResult, error) {
	schemaUpdateResult := &UpdateResult{
		Valid: false,
	}

	if schemaUpdateInput == nil {
		message := fmt.Sprintf("Input is not valid")
		schemaUpdateResult.Message = message
		return schemaUpdateResult, fmt.Errorf(message)
	}
	if schemaUpdateInput.UpdatedSchema == nil || schemaUpdateInput.UpdatedSchema.Metadata == nil || schemaUpdateInput.UpdatedSchema.JSONSchema == nil {
		message := fmt.Sprintf("Updated Schema is missing from input")
		schemaUpdateResult.Message = message
		return schemaUpdateResult, fmt.Errorf(message)
	}
	if schemaUpdateInput.PreviousSchema == nil || schemaUpdateInput.PreviousSchema.Metadata == nil || schemaUpdateInput.PreviousSchema.JSONSchema == nil {
		message := fmt.Sprintf("Previous Schema is missing from input")
		schemaUpdateResult.Message = message
		return schemaUpdateResult, fmt.Errorf(message)
	}

	updatedAuthor := schemaUpdateInput.UpdatedSchema.Author
	previousAuthor := schemaUpdateInput.PreviousSchema.Author
	if len(updatedAuthor) == 0 || updatedAuthor != previousAuthor {
		message := fmt.Sprintf("Schema Author is invalid")
		schemaUpdateResult.Message = message
		return schemaUpdateResult, fmt.Errorf(message)
	}

	if len(schemaUpdateInput.UpdatedSchemaCategoryID) != 0 && schemaUpdateInput.UpdatedSchemaCategoryID != schemaUpdateInput.PreviousSchemaCategoryID {
		message := fmt.Sprintf("Schema Category cannot be updated")
		schemaUpdateResult.Message = message
		return schemaUpdateResult, fmt.Errorf(message)
	}

	return schemaUpdateResult, nil
}

func incrementMajorVersion(previousVersion string) (string, error) {
	majorMinor := strings.Split(previousVersion, ".")
	if len(majorMinor) != 2 {
		return "", fmt.Errorf("Input not as expected for previous version: %s", previousVersion)
	}

	major := majorMinor[0]

	i, err := incrementIntAsString(major)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", i, "0"), nil
}

func incrementMinorVersion(previousVersion string) (string, error) {
	majorMinor := strings.Split(previousVersion, ".")
	if len(majorMinor) != 2 {
		return "", fmt.Errorf("input not as expected for previous version: %s", previousVersion)
	}

	major := majorMinor[0]
	minor := majorMinor[1]

	i, err := incrementIntAsString(minor)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s", major, i), nil
}

func incrementIntAsString(input string) (string, error) {
	i, err := strconv.Atoi(input)
	if err != nil {
		return "", fmt.Errorf("Could not parse input %s to int", input)
	}
	return strconv.Itoa(i + 1), nil
}

// ExtractSchemaAuthorDID parses the schema URI (did:work:<authorDID>;id=<uuid>;version=<version>)
// and returns the author's DID.
func ExtractSchemaAuthorDID(schemaID string) (did.DID, error) {
	if !ledger.IDRx.MatchString(schemaID) {
		idFormatErr := IDFormatErr{schemaID}
		return "", idFormatErr
	}
	didStr := schemaID[:strings.Index(schemaID, FragSep+ResourceIDPathResource)]
	return did.DID(didStr), nil
}

// ExtractSchemaResourceID parses the schema URI (did:work:<authorDID>;id=<uuid>;version=<version>)
// and returns the resource ID.
func ExtractSchemaResourceID(schemaID string) (string, error) {
	if !ledger.IDRx.MatchString(schemaID) {
		idFormatErr := IDFormatErr{schemaID}
		return "", idFormatErr
	}

	idIdentifier := ResourceIDPathResource + FragAssignment
	rid := schemaID[strings.Index(schemaID, idIdentifier)+len(idIdentifier) : strings.Index(schemaID, FragSep+VersionPathResource)]
	return rid, nil
}

// ExtractSchemaVersionFromID parses the schema URI (did:work:<authorDID>;id=<uuid>;version=<version>)
// and returns the schema version.
func ExtractSchemaVersionFromID(schemaID string) (Version, error) {
	if !ledger.IDRx.MatchString(schemaID) {
		idFormatErr := IDFormatErr{schemaID}
		return Version{}, idFormatErr
	}
	vpr := VersionPathResource + FragAssignment
	vstr := schemaID[strings.Index(schemaID, vpr)+len(vpr):]
	return VersionFromStr(vstr)
}
