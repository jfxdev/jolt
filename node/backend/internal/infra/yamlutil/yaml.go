// Package yamlutil implements the deliberately small YAML dialect used by the node.
package yamlutil

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

func Decode(data []byte, value any) error {
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if err := validate(&document); err != nil {
		return err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("only one YAML document is allowed")
	}
	decoder = yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(value)
}

// DecodeConfiguration rejects scalar coercions (for example a numeric ID or
// yes/no as a boolean) before decoding into a configuration with defaults.
func DecodeConfiguration(data []byte, value any) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if err := checkType(&doc, reflect.TypeOf(value), ""); err != nil {
		return err
	}
	return Decode(data, value)
}

func checkType(n *yaml.Node, typ reflect.Type, field string) error {
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return checkType(n.Content[0], typ, field)
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	want := ""
	if typ == reflect.TypeOf(time.Duration(0)) {
		want = "!!str"
	} else {
		switch typ.Kind() {
		case reflect.String:
			want = "!!str"
		case reflect.Bool:
			want = "!!bool"
		case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint, reflect.Uint64:
			want = "!!int"
		case reflect.Struct:
			want = "!!map"
			if n.Kind == yaml.MappingNode {
				for i := 0; i < len(n.Content); i += 2 {
					for j := 0; j < typ.NumField(); j++ {
						f := typ.Field(j)
						name := strings.Split(f.Tag.Get("yaml"), ",")[0]
						if name == "" {
							name = strings.ToLower(f.Name)
						}
						if name == "-" || name != n.Content[i].Value {
							continue
						}
						if err := checkType(n.Content[i+1], f.Type, strings.TrimPrefix(field+"."+name, ".")); err != nil {
							return err
						}
					}
				}
			}
		case reflect.Slice:
			want = "!!seq"
			if n.Kind == yaml.SequenceNode {
				for i, item := range n.Content {
					if err := checkType(item, typ.Elem(), fmt.Sprintf("%s[%d]", field, i)); err != nil {
						return err
					}
				}
			}
		}
	}
	if want != "" && n.Tag != want {
		return fmt.Errorf("line %d: %s: expected %s", n.Line, field, strings.TrimPrefix(want, "!!"))
	}
	return nil
}

func validate(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return fmt.Errorf("line %d: YAML anchors and aliases are not supported", n.Line)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value == "<<" {
				return fmt.Errorf("line %d: invalid mapping key", key.Line)
			}
			if seen[key.Value] {
				return fmt.Errorf("line %d: duplicate field %s", key.Line, key.Value)
			}
			seen[key.Value] = true
		}
	}
	for _, child := range n.Content {
		if err := validate(child); err != nil {
			return err
		}
	}
	return nil
}
