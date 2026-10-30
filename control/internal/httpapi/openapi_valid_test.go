package httpapi

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestControlOpenAPIDocumentsRegisteredRoutes(t *testing.T) {
	serverSource, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	specSource, err := os.ReadFile("../../../docs/openapi/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(specSource), "\t") {
		t.Fatal("OpenAPI contains tab indentation")
	}
	operations := documentedOperations(t, string(specSource))
	routePattern := regexp.MustCompile(`mux\.Handle(?:Func)?\("(?:(GET|POST|PUT|PATCH|DELETE) )?([^"]+)"`)
	matches := routePattern.FindAllStringSubmatch(string(serverSource), -1)
	if len(matches) < 50 {
		t.Fatalf("route extraction found only %d registrations", len(matches))
	}
	for _, match := range matches {
		method, route := strings.ToLower(match[1]), match[2]
		if route == "/" {
			continue
		}
		route = strings.ReplaceAll(route, "{resource...}", "{resource}")
		documented, ok := operations[route]
		if !ok {
			t.Errorf("registered route %s is absent from OpenAPI", route)
			continue
		}
		if method != "" && !documented[method] {
			t.Errorf("registered operation %s %s is absent from OpenAPI", strings.ToUpper(method), route)
		}
		if method == "" && len(documented) == 0 {
			t.Errorf("registered wildcard route %s has no OpenAPI operation", route)
		}
	}
}

func TestControlOpenAPIInternalReferencesResolve(t *testing.T) {
	specSource, err := os.ReadFile("../../../docs/openapi/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	spec := string(specSource)
	components := map[string]bool{}
	section := ""
	for _, line := range strings.Split(spec, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(line, ":") {
			section = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		if section != "" && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			name, _, found := strings.Cut(strings.TrimSpace(line), ":")
			if found {
				components["components/"+section+"/"+name] = true
			}
		}
	}
	referencePattern := regexp.MustCompile(`\$ref:\s*'#/([^']+)'`)
	for _, match := range referencePattern.FindAllStringSubmatch(spec, -1) {
		if !components[match[1]] {
			t.Errorf("unresolved OpenAPI reference #/%s", match[1])
		}
	}
	externalPattern := regexp.MustCompile(`\$ref:\s*'([^']+\.yaml)#/[^']+'`)
	for _, match := range externalPattern.FindAllStringSubmatch(spec, -1) {
		if _, err := os.Stat(filepath.Join("../../../docs/openapi", match[1])); err != nil {
			t.Errorf("external OpenAPI reference %s: %v", match[1], err)
		}
	}
}

func documentedOperations(t *testing.T, spec string) map[string]map[string]bool {
	t.Helper()
	result := map[string]map[string]bool{}
	current := ""
	for _, line := range strings.Split(spec, "\n") {
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(line, ":") {
			current = strings.TrimSuffix(strings.TrimSpace(line), ":")
			if result[current] != nil {
				t.Fatalf("duplicate OpenAPI path %s", current)
			}
			result[current] = map[string]bool{}
			continue
		}
		if line != "" && !strings.HasPrefix(line, " ") {
			current = ""
		}
		if current == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") && trimmed == method+":" {
				result[current][method] = true
			}
		}
	}
	return result
}
