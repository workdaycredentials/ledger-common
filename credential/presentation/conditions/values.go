package conditions

import (
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// value is an implementation of a sum type wrapped in an error and a source context.
//
// The context we're maintaining is the "source" of the data, used to provide better
// error messages, and the actual value itself (or an error).   Since Go doesn't have "sum" types,
// the value and its type is managed by a set of mutually exclusive fields named after the type.
type value struct {
	source string
	Err    error
	Bool   *bool
	String string
	Number *float64
	Date   *time.Time
}

// typesMatch is a utility function that, given two values, ensures they are wrapping the same type.
// If not, an error value to return is provided.
func typesMatch(lhs, rhs value) (value, bool) {
	if lhs.Err != nil || rhs.Err != nil {
		return value{Err: combineErrors(lhs.Err, rhs.Err)}, false
	}
	if lhs.Bool != nil && rhs.Bool == nil {
		return typeMismatchError("boolean", lhs, rhs), false
	}
	if lhs.String != "" && rhs.String == "" {
		return typeMismatchError("string", lhs, rhs), false
	}
	if lhs.Number != nil && rhs.Number == nil {
		return typeMismatchError("number", lhs, rhs), false
	}
	if lhs.Date != nil && rhs.Date == nil {
		return typeMismatchError("date", lhs, rhs), false
	}
	return value{}, true
}

func typeMismatchError(typeName string, lhs value, rhs value) value {
	return value{Err: errors.Errorf("%s field (%s) compared to non-%s value (%s)", typeName, lhs.source, typeName, rhs.source)}
}

// fromString and friends are convenience methods for value{} construction.
func fromString(source string, s string) value { return value{source: source, String: s} }
func fromError(source string, err error) value { return value{source: source, Err: err} }
func fromBool(source string, b bool) value     { return value{source: source, Bool: &b} }

// unpackBool (and friends?) return an (underlying) value, err pair.
func (v value) unpackBool() (bool, error) { return v.Bool != nil && *v.Bool, v.Err }

// asValue constructs a value{} from an interface.  If the type is known, use a fromType function.
func asValue(source string, i interface{}) (result value) {
	switch v := i.(type) {
	case string:
		isTime, err := maybeTime(v)
		if err != nil {
			result = value{String: v}
		} else {
			result = value{Date: isTime}
		}
	case bool:
		result = value{Bool: &v}
	case error:
		result = value{Err: v}
	case float64:
		result = value{Number: &v}
	default:
		result = value{Err: errors.Errorf("unknown type in condition evaluation: %T", i)}
	}
	result.source = source
	return
}

func maybeTime(i string) (*time.Time, error) {
	maybeTime, err := time.Parse(time.RFC3339, i)
	if err == nil {
		return &maybeTime, nil
	}

	return nil, errors.New("unable to format into a supported timestamp")
}

// liftStringStringBool and friends "lift" a function operating on an underlying values
// to operate on wrapped values in a value{} container
func liftStringStringBool(fn func(s, r string) bool) func(lhs value, rhs value) value {
	return func(lhs value, rhs value) value {
		matchErrValue, ok := typesMatch(lhs, rhs)
		if !ok {
			return matchErrValue
		}
		return fromBool(fmt.Sprintf("%s and %s", lhs.source, rhs.source), fn(lhs.String, rhs.String))
	}
}

func liftNumberNumberBool(fn func(s, r float64) bool) func(lhs value, rhs value) value {
	return func(lhs value, rhs value) value {
		matchErrValue, ok := typesMatch(lhs, rhs)
		if !ok {
			return matchErrValue
		}
		return fromBool(fmt.Sprintf("%s and %s", lhs.source, rhs.source), fn(*lhs.Number, *rhs.Number))
	}
}

func liftDateBool(fn func(s, r *time.Time) bool) func(lhs value, rhs value) value {
	return func(lhs value, rhs value) value {
		matchErrValue, ok := typesMatch(lhs, rhs)
		if !ok {
			return matchErrValue
		}
		return fromBool(fmt.Sprintf("%s and %s", lhs.source, rhs.source), fn(lhs.Date, rhs.Date))
	}
}

// combineErrors combines two errors into a single error.
func combineErrors(err error, err2 error) error {
	switch {
	case err == nil:
		return err2
	case err2 == nil:
		return err
	default:
		return errors.Errorf("%s; %s", err.Error(), err2.Error())
	}
}

// credentialValue is an AST node that represents data on the credential.
type credentialValue CredentialValue

// Eval of a credentialValue actually retrieves data from the credential into a value{} wrapper
func (cv credentialValue) Eval(scope Scope) value {
	switch {
	case cv.Data != "":
		val, ok := scope.Credential.CredentialSubject[cv.Data]
		if !ok {
			return fromError(cv.Data, errors.New("missing data field in credentialValue"))
		}
		return asValue(cv.Data, val)
	case cv.Metadata == "modelVersion":
		return fromString(cv.Metadata, scope.Credential.Metadata.ModelVersion)
	case cv.Metadata == "id":
		return fromString(cv.Metadata, scope.Credential.Metadata.ID)
	// case cv.Metadata == "type":
	// 	return scope.Credential.Metadata.Type
	case cv.Metadata == "issuer":
		return fromString(cv.Metadata, scope.Credential.Metadata.Issuer)
	case cv.Metadata == "issuanceDate":
		return fromString(cv.Metadata, scope.Credential.Metadata.IssuanceDate)
	case cv.Metadata == "credentialSchema.id":
		return fromString(cv.Metadata, scope.Credential.Metadata.Schema.ID)
	case cv.Metadata == "credentialSchema.type":
		return fromString(cv.Metadata, scope.Credential.Metadata.Schema.Type)
	case cv.Metadata == "expirationDate":
		return asValue(cv.Metadata, scope.Credential.Metadata.ExpirationDate)
	default:
		return fromError(cv.Metadata, errors.New("invalid metadata field in credentialValue"))
	}
}

// comparisonValue is an AST node representing a value we're going to compare with:
// a constant, a variable, a moment in time or a calendar date.
type comparisonValue ComparisonValue

// Eval of a comparisonValue returns the actual value:
// constant, calculated, or looked up in the scope's variable values
func (cv comparisonValue) Eval(scope Scope) value {
	switch {
	case cv.Variable != "":
		val, ok := scope.VariableValues[cv.Variable]
		if !ok {
			return fromError("variable", errors.Errorf("missing variable value for %s", cv.Variable))
		}
		return asValue(cv.Variable, val)
	case cv.Constant != nil:
		return asValue(fmt.Sprintf("%v", cv.Constant), cv.Constant)
	default:
		return fromError("", errors.New("invalid comparisonValue"))
	}
}
