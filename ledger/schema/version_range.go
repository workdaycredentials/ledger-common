package schema

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Syntax for the schema range is a subset of npm range specification
// SEE https://docs.npmjs.com/about-semantic-versioning & https://semver.npmjs.com/
// dont need ~ as there are no patch versions to operate over and it is counter-fitted by 3.x to wild card

const (
	// include everything greater than a particular version in the same major range
	caratRxStr = `^\^[0-9]+\.[0-9]+$`

	wildMinorXRxStr    = `^[0-9]+\.x$`
	wildMinorStarRxStr = `^[0-9]+\.\*$`

	wildMajorXRxStr    = `^x$`
	wildMajorStarRxStr = `^\*$`

	// Note specific version VersionRxStr
)

// Note uses Prefix range https://docs.gradle.org/current/userguide/single_versions.html
type Range struct {
	MajorRange RangeBounded
	MinorRange RangeBounded
}

// RangeFromStr parses a string into a Range object. Returns an error if the string does not match
// any of the following:
//
// 1) Exact match. This looks like a version string.
// For example, "1.0" is a range that only matches version "1.0".
//
// 2) Major range. This looks like a carrot "^" prefixed to a version.
// For example, "^2.1" matches everything greater than or equal to a particular version ("2.1")
// in the same major range ("2.x").
//
// 3) Wild minor. This looks like a version string where the minor version has been replaced with
// either an "x" or an "*". This is equivalent to Major range with minor version "0".
// For example, "3.x" is includes everything with a major version of "3".
//
// 4) Wild. This is either "x" or "*". This matches any version.
func RangeFromStr(bound string) (Range, error) {
	schemaVersionRx := regexp.MustCompile(VersionRxStr)
	if schemaVersionRx.MatchString(bound) {
		version, e := VersionFromStr(bound)
		if e != nil {
			return Range{}, e
		}
		return Range{
			MajorRange: singleValueBoundedRange(version.Major),
			MinorRange: singleValueBoundedRange(version.Minor),
		}, nil

	}

	caratRx := regexp.MustCompile(caratRxStr)
	if caratRx.MatchString(bound) {
		version, e := VersionFromStr(strings.Trim(bound, "^"))
		if e != nil {
			return Range{}, e
		}
		return Range{
			MajorRange: singleValueBoundedRange(version.Major),
			MinorRange: lowerBoundedRange(version.Minor),
		}, nil

	}

	wildMinorXRx := regexp.MustCompile(wildMinorXRxStr)
	wildMinorStarRx := regexp.MustCompile(wildMinorStarRxStr)
	if wildMinorXRx.MatchString(bound) || wildMinorStarRx.MatchString(bound) {
		majorV, e := strconv.Atoi(strings.Split(bound, ".")[0])
		if e != nil {
			return Range{}, e
		}
		return Range{
			MajorRange: singleValueBoundedRange(majorV),
			MinorRange: unBoundedRange,
		}, nil
	}

	wildMajorXRx := regexp.MustCompile(wildMajorXRxStr)
	wildMajorStarRx := regexp.MustCompile(wildMajorStarRxStr)
	if wildMajorXRx.MatchString(bound) || wildMajorStarRx.MatchString(bound) {
		return Range{
			MajorRange: unBoundedRange,
			MinorRange: unBoundedRange,
		}, nil
	}
	return Range{}, UnRecognisedRangeError{bound}
}

// FallsInRange returns true if the given version falls within this Range.
func (rng Range) FallsInRange(schemaVersion Version) bool {
	if rng.MajorRange(schemaVersion.Major) && rng.MinorRange(schemaVersion.Minor) {
		return true
	}
	return false
}

// IDIsInVersionRange checks if the schema version falls within the given range.
// Returns an error if either the schema ID or range cannot be parsed.
func IDIsInVersionRange(schemaID string, versionRange string) (bool, error) {
	version, err := ExtractSchemaVersionFromID(schemaID)
	if err != nil {
		return false, err
	}
	schemaRange, err := RangeFromStr(versionRange)
	if err != nil {
		return false, err
	}

	return schemaRange.FallsInRange(version), nil
}

type RangeBounded func(subject int) bool

// inclusive lower bounded value
func lowerBoundedRange(lowerBound int) RangeBounded {
	return func(subject int) bool {
		return subject >= lowerBound
	}
}

func singleValueBoundedRange(value int) RangeBounded {
	return func(subject int) bool {
		return subject == value
	}
}

func unBoundedRange(_ int) bool {
	return true
}

// UnRecognisedRangeError is returned when encountering an invalid range string.
type UnRecognisedRangeError struct {
	rangeStr string
}

func (e UnRecognisedRangeError) Error() string {
	return fmt.Sprintf("unrecognized range format '%s'", e.rangeStr)
}
