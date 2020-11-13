package conditions

import (
	"github.com/pkg/errors"

	"github.com/workdaycredentials/ledger-common/credential"
)

type Evaler interface {
	Eval(scope Scope) value
}

// Scope represents all of the context needed to evaluate the condition.
type Scope struct {
	Credential     credential.UnsignedVerifiableCredential
	VariableValues map[string]interface{}
}

type condition Condition

func (c condition) Eval(scope Scope) value {
	lhs := credentialValue(c.CredentialValue).Eval(scope)
	rhs := comparisonValue(c.ComparisonValue).Eval(scope)
	var result value
	switch {
	case lhs.String != "":
		opLookup, ok := stringComparisons[c.Op]
		if !ok {
			return fromError(c.Op, errors.New("unknown operation"))
		}
		result = liftStringStringBool(opLookup)(lhs, rhs)
	case lhs.Number != nil:
		opLookup, ok := numberComparisons[c.Op]
		if !ok {
			return fromError(c.Op, errors.New("unknown operation"))
		}
		result = liftNumberNumberBool(opLookup)(lhs, rhs)
	case lhs.Date != nil:
		opLookup, ok := dateComparisons[c.Op]
		if !ok {
			return fromError(c.Op, errors.New("unknown operation"))
		}
		result = liftDateBool(opLookup)(lhs, rhs)
	}

	return result
}

type andCondition []Condition

func (receiver andCondition) Eval(scope Scope) value {
	result := true
	var err error
	for _, cond := range receiver {
		value := condition(cond).Eval(scope)
		resultC, errC := value.unpackBool()
		result = result && resultC
		if errC != nil {
			err = combineErrors(err, errC)
		}
	}
	return value{source: "list of conditions", Err: err, Bool: &result}
}

func EvalConditions(scope Scope, conditions []Condition) (bool, error) {
	return andCondition(conditions).Eval(scope).unpackBool()
}
