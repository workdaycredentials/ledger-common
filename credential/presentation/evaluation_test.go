package presentation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/workdaycredentials/ledger-common/credential"
	"github.com/workdaycredentials/ledger-common/util"
)

var unsignedAddressV1Cred = credential.UnsignedVerifiableCredential{
	Metadata: credential.Metadata{
		ModelVersion: util.Version_1_0,
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "422ab006-063e-48f1-91b4-dc09dc512b40",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:work:28RB9jAy9HtVet3zFhdWaM",
		IssuanceDate: "2019-03-28T11:11:49.456858506Z",
		Schema: credential.Schema{
			ID:   "did:work:DvRUw55c9dDkkHgA2PW2Wi",
			Type: "AddressSchema",
		},
		ExpirationDate: "2021-01-01T00:00:00.000000000Z",
	},
	CredentialSubject: map[string]interface{}{
		"city":                        "San Francisco",
		"country":                     "United States of America",
		"postalCode":                  "CA 94117",
		"state":                       "California",
		"street1":                     "940 Grove St",
		"street2":                     "Steiner St",
		"timeOfPurchase":              "2020-04-24T17:28:29+00:00",
		"compositeScore":              21.45557802910,
		"meanScore":                   23.00,
		credential.SubjectIDAttribute: "did:work:51wzdn5u7nPp944zpDo7b2",
	},
}

func TestConditionOperation_Eval(t *testing.T) {

	tests := []struct {
		name      string
		condition string
		values    string
		want      bool
		wantErr   bool
	}{
		{
			name: "Simple",
			condition: `{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "San Francisco" },
	"failureMessage": "City must be San Fran"
}`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Simple Miss",
			condition: `{
	"op": "notEquals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "San Francisco" },
	"failureMessage": "City must not be San Fran"
}`,
			want:    false,
			wantErr: false,
		},
		{
			name: "Simple Type mismatch",
			condition: `{
	"op": "notEquals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": 1996 },
	"failureMessage": "City must not be mid 90s"
}`,
			wantErr: true,
		},
		{
			name: "contains",
			condition: `{
	"op": "contains",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "Frisco" },
	"failureMessage": "City must be Frisco"
}`,
			want:    false,
			wantErr: false,
		},
		{
			name: "begins with",
			condition: `{
	"op": "beginsWith",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "San Fran" },
	"failureMessage": "City must be San Fran"
}`,
			want:    true,
			wantErr: false,
		},
		{
			name: "ends with",
			condition: `{
	"op": "endsWith",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "cisco" },
	"failureMessage": "City must be 'cisco"
}`,
			want:    true,
			wantErr: false,
		},
		{
			name: "bad operation",
			condition: `{
	"op": "endWith",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "cisco" },
	"failureMessage": "City must be 'cisco"
}`,
			wantErr: true,
		},
		{
			name: "Simple Variable",
			condition: `{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "city" },
	"failureMessage": "City must be San Fran"
}`,
			values:  `{"city": "San Francisco"}`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Variable Miss",
			condition: `{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "unset" },
	"failureMessage": "City must be San Fran"
}`,
			values:  `{"city": "San Francisco"}`,
			wantErr: true,
		},
		{
			name: "Metadata Comparison",
			condition: `{
	"op": "greaterThan",
	"credentialValue": { "metadata": "expirationDate" },
	"comparisonValue": { "variable": "%today%" },
	"failureMessage": "Must not be expired"
}`,
			values:  `{"%today%": "2020-12-01T00:00:00.000000000Z"}`,
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		//noinspection GoShadowedVar
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var conditionOperation condition
			var values map[string]interface{}
			assert.NoError(t, json.Unmarshal([]byte(tt.condition), &conditionOperation))
			if tt.values != "" {
				assert.NoError(t, json.Unmarshal([]byte(tt.values), &values))
			}
			result, err := conditionOperation.Eval(Scope{
				Credential:     unsignedAddressV1Cred,
				VariableValues: values,
			}).unpackBool()
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					println(err.Error())
				}
			} else {
				assert.Equal(t, tt.want, result)
				assert.NoError(t, err)
			}
		})
	}
}

func TestEvalConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions string
		values     string
		want       bool
		wantErr    bool
	}{
		{
			name:       "None",
			conditions: `[]`,
			want:       true,
			wantErr:    false,
		},
		{
			name: "Simple",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "constant": "San Francisco" },
	"failureMessage": "City must be San Fran"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Single variable, UI mangling.",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "city", "constant": "" },
	"failureMessage": "City must be"
}]`,
			values:  `{"city": "San Francisco"}`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Single constant, UI mangling.",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "", "constant": "San Francisco" },
	"failureMessage": "City must be"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Multiple",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "city" },
	"failureMessage": "City must be"
},
{
	"op": "equals",
	"credentialValue": { "data": "country" },
	"comparisonValue": { "variable": "country" },
	"failureMessage": "Country must be"
}]`,
			values:  `{"city": "San Francisco", "country": "United States of America"}`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Multiple, One Miss",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "city" },
	"failureMessage": "City must be"
},
{
	"op": "notEquals",
	"credentialValue": { "data": "country" },
	"comparisonValue": { "variable": "country" },
	"failureMessage": "Country must be"
}]`,
			values:  `{"city": "San Francisco", "country": "United States of America"}`,
			want:    false,
			wantErr: false,
		},
		{
			name: "Multiple, One Error",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "city" },
	"comparisonValue": { "variable": "city" },
	"failureMessage": "City must be"
},
{
	"op": "not_valid",
	"credentialValue": { "data": "country" },
	"comparisonValue": { "variable": "country" },
	"failureMessage": "Country must be"
}]`,
			values:  `{"city": "San Francisco", "country": "United States of America"}`,
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		//noinspection GoShadowedVar
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var conditions []Condition
			var values map[string]interface{}
			assert.NoError(t, json.Unmarshal([]byte(tt.conditions), &conditions))
			if tt.values != "" {
				assert.NoError(t, json.Unmarshal([]byte(tt.values), &values))
			}
			result, err := EvalConditions(Scope{
				Credential:     unsignedAddressV1Cred,
				VariableValues: values,
			}, conditions)
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					println(err.Error())
				}
			} else {
				assert.Equal(t, tt.want, result)
				assert.NoError(t, err)
			}
		})
	}
}

func TestTimeSpecificConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions string
		values     string
		want       bool
		wantErr    bool
	}{
		{
			name: "Time is equal",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T17:28:29+00:00" },
	"failureMessage": "4:00PM does not equal 5:28PM"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Time is unequal - second difference",
			conditions: `[{
	"op": "notEquals",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T17:28:28+00:00" },
	"failureMessage": "Unix Timestamp 4:48 & RFC 3339 5:28 do not match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Time is unequal - day difference",
			conditions: `[{
	"op": "notEquals",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-08-04T01:12:28+00:00" },
	"failureMessage": "Unix Timestamp 4:48 & RFC 3339 5:28 do not match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Before moment in time",
			conditions: `[{
	"op": "lessThan",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T17:28:31+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Before moment in time - time is after",
			conditions: `[{
	"op": "lessThan",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T19:28:21+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "After moment in time",
			conditions: `[{
	"op": "greaterThan",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T17:28:21+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "After moment in time - time is before",
			conditions: `[{
	"op": "greaterThan",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-03-24T17:28:21+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "<= moment",
			conditions: `[{
	"op": "lessThanOrEqualTo",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T18:28:29+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
},
{
	"op": "lessThanOrEqualTo",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T17:28:29+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: ">= moment",
			conditions: `[{
	"op": "greaterThanOrEqualTo",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T16:28:29+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
},
{
	"op": "greaterThanOrEqualTo",
	"credentialValue": { "data": "timeOfPurchase" },
	"comparisonValue": { "constant": "2020-04-24T17:28:29+00:00" },
	"failureMessage": "Timestamps RFC 822, RFC 3339 must match"
}]`,
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		//noinspection GoShadowedVar
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var conditions []Condition
			var values map[string]interface{}
			assert.NoError(t, json.Unmarshal([]byte(tt.conditions), &conditions))
			if tt.values != "" {
				assert.NoError(t, json.Unmarshal([]byte(tt.values), &values))
			}
			result, err := EvalConditions(Scope{
				Credential:     unsignedAddressV1Cred,
				VariableValues: values,
			}, conditions)
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					println(err.Error())
				}
			} else {
				assert.Equal(t, tt.want, result)
				assert.NoError(t, err)
			}
		})
	}
}

func TestNumberSpecificConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions string
		values     string
		want       bool
		wantErr    bool
	}{
		{
			name: "Float equals int of same  value",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "meanScore" },
	"comparisonValue": { "constant": 23 },
	"failureMessage": "23.00 must equal 23"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Float equals float",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "compositeScore" },
	"comparisonValue": { "constant": 21.45557802910 },
	"failureMessage": "23.00 must equal 23"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "Float does not equal int of different value",
			conditions: `[{
	"op": "notEquals",
	"credentialValue": { "data": "meanScore" },
	"comparisonValue": { "constant": 24 },
	"failureMessage": "23.00 must equal 24"
}]`,
			want:    true,
			wantErr: false,
		},
		{
			name: "String cannot equal int",
			conditions: `[{
	"op": "equals",
	"credentialValue": { "data": "meanScore" },
	"comparisonValue": { "constant": "23.00" },
	"failureMessage": "constant of string 23.00 must fail to parse as int"
}]`,
			want:    true,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		//noinspection GoShadowedVar
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var conditions []Condition
			var values map[string]interface{}
			assert.NoError(t, json.Unmarshal([]byte(tt.conditions), &conditions))
			if tt.values != "" {
				assert.NoError(t, json.Unmarshal([]byte(tt.values), &values))
			}
			result, err := EvalConditions(Scope{
				Credential:     unsignedAddressV1Cred,
				VariableValues: values,
			}, conditions)
			if tt.wantErr {
				assert.Error(t, err)
				if err != nil {
					println(err.Error())
				}
			} else {
				assert.Equal(t, tt.want, result)
				assert.NoError(t, err)
			}
		})
	}
}
