package schema

import (
	"context"
	"encoding/json"
	"fmt"

	goversion "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"github.com/xeipuuv/gojsonschema"

	"github.com/workdaycredentials/ledger-common/ledger"
)

type VersionInfo struct {
	Version         string
	ValidRangeLower string
	ValidRangeUpper string
	Description     string
	Validator       Validator
}

type Validator int

const (
	InValidator Validator = 0
	V0          Validator = 1
	V1          Validator = 2
)

type Comparator int

const (
	LessThan Comparator = iota
	LessThanOrEqualTo
	GreaterThan
	GreaterThanOrEqualTo
	Equals
)

// Compare allows the comparison of two semantic versions with a given comparator
// defined by the Comparator enumeration
func Compare(v1 string, comparator Comparator, v2 string) (bool, error) {
	// Convert version to comparable version
	version1, err := goversion.NewVersion(v1)
	if err != nil {
		logrus.WithError(err).Errorf("invalid semantic version: %s", v1)
		return false, err
	}
	version2, err := goversion.NewVersion(v2)
	if err != nil {
		logrus.WithError(err).Errorf("invalid semantic version: %s", v2)
		return false, err
	}

	// Do the comparator
	switch comparator {
	case LessThan:
		return version1.LessThan(version2), nil
	case LessThanOrEqualTo:
		return version1.LessThan(version2) || version1.Equal(version2), nil
	case GreaterThan:
		return version1.GreaterThan(version2), nil
	case GreaterThanOrEqualTo:
		return version1.GreaterThan(version2) || version1.Equal(version2), nil
	case Equals:
		return version1.Equal(version2), nil
	default:
		err := fmt.Errorf("invalid comparator<%d>", comparator)
		logrus.WithError(err).Error("unable to compare versions with provided comparator")
		return false, err
	}
}

// InRangeInclusive determines whether the provided version is in the inclusive range of the provided version bounds
func InRangeInclusive(version string, lower string, upper string) (bool, error) {
	lowerBound, err := Compare(version, GreaterThanOrEqualTo, lower)
	if err != nil {
		logrus.WithError(err).Error("Unable to check range lower bound inclusivity")
		return false, err
	}
	if !lowerBound {
		return false, nil
	}

	upperBound, err := Compare(version, LessThanOrEqualTo, upper)
	if err != nil {
		logrus.Error("Unable to check range upper bound inclusivity")
		return false, err
	}
	if !upperBound {
		return false, nil
	}

	return true, nil
}

// Version logic

// Store all currently supported versions in reverse priority (ascending) order
var versions = [...]VersionInfo{Version0, Version1} //nolint:gochecknoglobals

var Version0 = VersionInfo{ //nolint:gochecknoglobals
	Version:         "0.0",
	ValidRangeLower: "0.0",
	ValidRangeUpper: "0.0",
	Description:     "Supports JSON Objects for Metadata and Schema Definitions, both validated against JSON schemas",
	Validator:       V0,
}

var Version1 = VersionInfo{ //nolint:gochecknoglobals
	Version:         "1.0",
	ValidRangeLower: "1.0",
	ValidRangeUpper: "1.0",
	Description:     "Supports JSON Objects for Metadata and Schema Definitions, both validated against JSON schemas",
	Validator:       V1,
}

// Find the most recently created validator the supports the provided version
func FindValidatorForVersion(ctx context.Context, version string) (Validator, error) {
	for i := len(versions) - 1; i >= 0; i-- {
		inRange, err := InRangeInclusive(version, versions[i].ValidRangeLower, versions[i].ValidRangeUpper)
		if err != nil {
			logrus.WithError(err).Errorf("Could not find validator for version<%s>", version)
			return InValidator, err
		}
		if inRange {
			return versions[i].Validator, nil
		}
	}
	return InValidator, fmt.Errorf("could not find validator for version<%s>", version)
}

func ValidateLedgerSchemaV1(ctx context.Context, document interface{}) error {
	// Make sure we have the right type for this version
	documentTyped, ok := document.(ledger.Schema)
	if !ok {
		err := fmt.Errorf("invalid type for version, got: %T", document)
		logrus.WithError(err).Error("unsupported type for version 1 schema validation")
		return err
	}

	logrus.Debugf("Validating the schema against version 1: %s", Version1.Description)

	// Do the validation
	// Validate meta schema
	metadataLoader := gojsonschema.NewStringLoader(ledger.MetadataSchema)
	metadataJSONBytes, err := json.Marshal(&documentTyped.Metadata)
	if err != nil {
		logrus.WithError(err).Error("Unable to marshal meta s")
		return err
	}
	metadataJSONLoader := gojsonschema.NewStringLoader(string(metadataJSONBytes))
	if err = ValidateWithJSONLoader(metadataLoader, metadataJSONLoader); err != nil {
		logrus.WithError(err).Error("Unable to validate provided metadata for schema")
		return err
	}

	// Validate the schema as a valid JSON schema
	if err = ValidateJSONSchema(documentTyped.JSONSchema.Schema); err != nil {
		logrus.WithError(err).Error("Provided schema is not a valid JSON schema")
		return err
	}

	return nil
}
