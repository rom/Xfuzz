package campaign

import "gopkg.in/yaml.v3"

// yamlUnmarshal is the package's single point of contact with the YAML decoder
// outside loading, so a test or a caller reading a fragment does not have to
// import the library itself.
func yamlUnmarshal(b []byte, v any) error { return yaml.Unmarshal(b, v) }
