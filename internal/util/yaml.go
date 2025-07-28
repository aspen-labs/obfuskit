package util

import (
	"gopkg.in/yaml.v3"
)

// YamlUnmarshal is a helper to unmarshal YAML config
func YamlUnmarshal(data []byte, out interface{}) error {
	return yaml.Unmarshal(data, out)
}
