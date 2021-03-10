package did

import "encoding/json"

// StringOrArray is a string or an ordered set of strings
type StringOrArray []string

func (s *StringOrArray) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		// data starts with double quote, so try to unmarshal as a (single) string
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		*s = []string{str}
		return nil
	}
	// Try to unmarshal as an array of strings
	var strings []string
	if err := json.Unmarshal(data, &strings); err != nil {
		return err
	}
	*s = strings
	return nil
}

func (s StringOrArray) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}
