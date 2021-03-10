package did

import "encoding/json"

// KeyRef is either a string or an embedded KeyDef
type KeyRef struct {
	Ref *string
	Def *KeyDef
}

func (o *KeyRef) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		// data starts with double quote, so try to unmarshal as a (single) string
		if err := json.Unmarshal(data, &o.Ref); err != nil {
			return err
		}
		o.Def = nil
		return nil
	}
	// Try to unmarshal as KeyDef next
	if err := json.Unmarshal(data, &o.Def); err != nil {
		return err
	}
	o.Ref = nil
	return nil
}

func (o KeyRef) MarshalJSON() ([]byte, error) {
	if o.Ref != nil {
		return json.Marshal(*o.Ref)
	}
	return json.Marshal(o.Def)
}
