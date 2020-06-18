package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompare(t *testing.T) {
	testConfigs := []struct {
		name          string
		version1      string
		comparator    Comparator
		version2      string
		validExpected bool
		errorExpected bool
	}{
		{
			name:          "Valid test versions equal",
			version1:      "0.0.0",
			comparator:    Equals,
			version2:      "0.0.0",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid test versions not equal",
			version1:      "1.0.0",
			comparator:    Equals,
			version2:      "0.0.0",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Valid test less than",
			version1:      "1.1.0",
			comparator:    LessThan,
			version2:      "2.4.2",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid test not less than",
			version1:      "1.0.0",
			comparator:    LessThan,
			version2:      "0.5.0",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Valid test less than or equal to",
			version1:      "1.0.0",
			comparator:    LessThanOrEqualTo,
			version2:      "1.0.0",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid test not less than or equal to",
			version1:      "5.0.0",
			comparator:    LessThanOrEqualTo,
			version2:      "2.0.0",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Valid test greater than",
			version1:      "2.3.2",
			comparator:    GreaterThan,
			version2:      "2.3.1",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid test not greater than",
			version1:      "4.4.4",
			comparator:    GreaterThan,
			version2:      "4.4.4",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Valid test greater than or equal to",
			version1:      "4.4.4",
			comparator:    GreaterThanOrEqualTo,
			version2:      "4.4.4",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid test not greater than or equal to",
			version1:      "1.2.1",
			comparator:    GreaterThanOrEqualTo,
			version2:      "2.0.0",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Invalid semantic version",
			version1:      ".144",
			comparator:    GreaterThanOrEqualTo,
			version2:      "4.4.4",
			validExpected: false,
			errorExpected: true,
		},
		{
			name:          "Invalid comparator",
			version1:      "1.2.1",
			comparator:    99,
			version2:      "2.0.0",
			validExpected: false,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			valid, err := Compare(testConfig.version1, testConfig.comparator, testConfig.version2)
			if !testConfig.errorExpected && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			} else {
				assert.Equal(t, testConfig.validExpected, valid)
			}
		})
	}
}

func TestInRangeInclusive(t *testing.T) {

	testConfigs := []struct {
		name          string
		version       string
		lower         string
		upper         string
		validExpected bool
		errorExpected bool
	}{
		{
			name:          "Valid in range inclusive",
			version:       "1.5.4",
			lower:         "1.0.0",
			upper:         "2.0.0",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid in range inclusive 2",
			version:       "5.5.1",
			lower:         "5.4.0",
			upper:         "5.5.1",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid in range inclusive 3",
			version:       "0.1.2",
			lower:         "0.0.1",
			upper:         "2.3.4",
			validExpected: true,
			errorExpected: false,
		},
		{
			name:          "Valid not in range inclusive",
			version:       "0.5.4",
			lower:         "1.0.0",
			upper:         "2.0.0",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Valid not in range inclusive 2",
			version:       "5.3.9",
			lower:         "5.4.0",
			upper:         "5.5.1",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Valid not in range inclusive 3",
			version:       "2.4.2",
			lower:         "0.0.1",
			upper:         "2.3.4",
			validExpected: false,
			errorExpected: false,
		},
		{
			name:          "Invalid semantic version",
			version:       "0.5.4",
			lower:         "1.0.0",
			upper:         "2.00",
			validExpected: false,
			errorExpected: true,
		},
		{
			name:          "Invalid semantic version 2",
			version:       "53",
			lower:         "5.4.0",
			upper:         "5.5.1",
			validExpected: false,
			errorExpected: true,
		},
		{
			name:          "Invalid semantic version 3",
			version:       "2.4.2",
			lower:         "00.1",
			upper:         "2.3.4",
			validExpected: false,
			errorExpected: true,
		},
	}

	for _, testConfig := range testConfigs {
		testConfig := testConfig // pin the variable to quiet the linter
		t.Run(testConfig.name, func(_ *testing.T) {
			valid, err := InRangeInclusive(testConfig.version, testConfig.lower, testConfig.upper)
			if !testConfig.errorExpected && err != nil {
				t.Errorf("Unexpected error: %s", err.Error())
			}
			assert.Equal(t, testConfig.validExpected, valid)
		})
	}
}
