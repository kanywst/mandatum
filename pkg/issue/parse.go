package issue

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// unmarshalStrict decodes JSON and refuses unknown fields and trailing data.
//
// Both refusals matter for an assertion. An unknown claim may be one a newer
// issuer expects to be honoured, and silently dropping it would mean
// enforcing weaker terms than were granted. Trailing data after the JSON
// object is how one payload gets read two ways by two implementations.
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decoding claims: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("decoding claims: trailing data after the claims object")
	}
	return nil
}
