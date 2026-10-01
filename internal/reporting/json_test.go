package reporting

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEmptyJSONLists(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, Report{}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"findings", "access_points", "clients"} {
		if _, ok := m[k].([]any); !ok {
			t.Fatalf("%s should be an array: %T", k, m[k])
		}
	}
}
