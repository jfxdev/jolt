package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// paramType says how an argument is checked and encoded.
type paramType int

const (
	// typeID is a path segment such as a node, mount or job ID.
	typeID paramType = iota
	// typePath is a mount-relative path.
	typePath
	typeString
	typeInteger
	typeBoolean
	typeStrings
	typeObject
	typeArray
)

// location is where an argument goes in the request.
type location int

const (
	inPath location = iota
	inQuery
	inBody
)

// param is one argument of a route tool. A typeObject param named "body" is
// the whole request body, for routes whose body is passed through.
type param struct {
	name        string
	typ         paramType
	in          location
	required    bool
	description string
	// enum restricts a string to these values.
	enum []string
}

// routeTool maps a tool to one Control Tower route. The Control Tower decides
// whether the caller may use it; the tool only shapes the request.
type routeTool struct {
	toolset     string
	name        string
	description string
	kind        toolKind
	method      string
	// path holds {name} placeholders filled from path params.
	path   string
	params []param
	// text expects a UTF-8 text response instead of JSON.
	text bool
}

func routeTools() []routeTool {
	var tools []routeTool
	tools = append(tools, inspectRoutes()...)
	tools = append(tools, fileWriteRoutes()...)
	tools = append(tools, jobRoutes()...)
	return tools
}

func groupTools() []groupTool {
	return append(jobGroups(), adminGroups()...)
}

const bodyParam = "body"

// Shared params. IDs and mount-relative paths carry no description: their
// names and the server instructions say what they are, and every byte here is
// paid by each agent that loads the tools.
var (
	nodeParam  = param{name: "node_id", typ: typeID, in: inPath, required: true}
	mountParam = param{name: "mount_id", typ: typeID, in: inPath, required: true}
	jobParam   = param{name: "job_id", typ: typeID, in: inPath, required: true}
)

func pathID(name string) param {
	return param{name: name, typ: typeID, in: inPath, required: true}
}

func body(description string) param {
	return param{name: bodyParam, typ: typeObject, in: inBody, required: true, description: description}
}

func (p param) property() map[string]any {
	property := map[string]any{}
	if p.description != "" {
		property["description"] = p.description
	}
	switch p.typ {
	case typeID, typePath, typeString:
		property["type"] = "string"
	case typeInteger:
		property["type"] = "integer"
	case typeBoolean:
		property["type"] = "boolean"
	case typeStrings:
		property["type"] = "array"
		property["items"] = map[string]any{"type": "string"}
	case typeObject:
		property["type"] = "object"
	case typeArray:
		property["type"] = "array"
	}
	if len(p.enum) > 0 {
		property["enum"] = p.enum
	}
	return property
}

// mutates reports whether the route changes state, so it takes an
// idempotency_key.
func (route routeTool) mutates() bool {
	return route.kind != kindRead && route.method != http.MethodGet
}

// idempotencyProperty is described once, in the server instructions.
var idempotencyProperty = map[string]any{"type": "string"}

// schema leaves out additionalProperties: unknown arguments are refused when
// the request is built, so the schema does not need to say it.
func (route routeTool) schema() map[string]any {
	properties := map[string]any{}
	required := []string{}
	for _, p := range route.params {
		properties[p.name] = p.property()
		if p.required {
			required = append(required, p.name)
		}
	}
	if route.mutates() {
		properties["idempotency_key"] = idempotencyProperty
	}
	schema := map[string]any{"type": "object", "properties": properties}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func (s *Server) addRoute(server *mcp.Server, route routeTool) {
	tool := &mcp.Tool{Name: route.name, Description: route.description, Annotations: route.kind.annotations(), InputSchema: route.schema()}
	server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := arguments(req)
		if err != nil {
			return toolError(err), nil
		}
		return s.runRoute(ctx, req, route, args), nil
	})
}

func arguments(req *mcp.CallToolRequest) (map[string]any, error) {
	var args map[string]any
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, errors.New("arguments must be a JSON object")
		}
	}
	return args, nil
}

func (s *Server) runRoute(ctx context.Context, req *mcp.CallToolRequest, route routeTool, args map[string]any) *mcp.CallToolResult {
	built, err := route.build(args)
	if err != nil {
		return toolError(err)
	}
	res, _, err := s.run(ctx, req, built)
	if err != nil {
		return toolError(err)
	}
	return res
}

// groupTool puts several routes on one resource behind an action argument.
// Rarely used routes cost far fewer tokens this way: one schema and one line
// per action instead of a whole tool each.
type groupTool struct {
	toolset     string
	name        string
	description string
	actions     []groupAction
}

// groupAction is one action of a group; route.description is its summary.
type groupAction struct {
	name  string
	route routeTool
}

// offered returns the actions a server may expose.
func (g groupTool) offered(readOnly bool) []groupAction {
	var actions []groupAction
	for _, action := range g.actions {
		if !readOnly || action.route.kind == kindRead {
			actions = append(actions, action)
		}
	}
	return actions
}

func groupKind(actions []groupAction) toolKind {
	kind := kindRead
	for _, action := range actions {
		kind = max(kind, action.route.kind)
	}
	return kind
}

// describe lists each action with its own arguments, optional ones marked
// with ?. Arguments every action takes are in the schema's required list.
func describe(description string, actions []groupAction) string {
	common := shared(actions)
	var text strings.Builder
	text.WriteString(description)
	text.WriteString(" Actions:")
	for _, action := range actions {
		var args []string
		for _, p := range action.route.params {
			if common[p.name] {
				continue
			}
			name := p.name
			if p.name == bodyParam && p.description != "" {
				name = "body" + p.description
			}
			if !p.required {
				name += "?"
			}
			args = append(args, name)
		}
		fmt.Fprintf(&text, "\n- %s(%s)", action.name, strings.Join(args, ", "))
		if action.route.description != "" {
			text.WriteString(": " + action.route.description)
		}
	}
	return text.String()
}

// shared returns the params every action requires.
func shared(actions []groupAction) map[string]bool {
	counts := map[string]int{}
	for _, action := range actions {
		for _, p := range action.route.params {
			if p.required {
				counts[p.name]++
			}
		}
	}
	common := map[string]bool{}
	for name, count := range counts {
		if count == len(actions) {
			common[name] = true
		}
	}
	return common
}

func groupSchema(actions []groupAction) map[string]any {
	properties := map[string]any{}
	mutates := false
	for _, action := range actions {
		mutates = mutates || action.route.mutates()
		for _, p := range action.route.params {
			if _, seen := properties[p.name]; seen {
				continue
			}
			// Per-action details are in the description, not repeated here.
			property := p.property()
			delete(property, "description")
			properties[p.name] = property
		}
	}
	properties["action"] = map[string]any{"type": "string", "enum": groupNames(actions)}
	if mutates {
		properties["idempotency_key"] = idempotencyProperty
	}
	required := []string{"action"}
	for _, p := range actions[0].route.params {
		if shared(actions)[p.name] {
			required = append(required, p.name)
		}
	}
	return map[string]any{"type": "object", "properties": properties, "required": required}
}

func (s *Server) addGroup(server *mcp.Server, group groupTool, actions []groupAction) {
	tool := &mcp.Tool{Name: group.name, Description: describe(group.description, actions), Annotations: groupKind(actions).annotations(), InputSchema: groupSchema(actions)}
	server.AddTool(tool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := arguments(req)
		if err != nil {
			return toolError(err), nil
		}
		name, _ := args["action"].(string)
		for _, action := range actions {
			if action.name == name {
				delete(args, "action")
				return s.runRoute(ctx, req, action.route, args), nil
			}
		}
		return toolError(fmt.Errorf("action must be one of %s", strings.Join(groupNames(actions), ", "))), nil
	})
}

func groupNames(actions []groupAction) []string {
	names := make([]string, 0, len(actions))
	for _, action := range actions {
		names = append(names, action.name)
	}
	return names
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}
}

// build checks the arguments and turns them into the request.
func (route routeTool) build(args map[string]any) (request, error) {
	known := map[string]bool{"idempotency_key": true}
	for _, p := range route.params {
		known[p.name] = true
	}
	for name := range args {
		if !known[name] {
			return request{}, fmt.Errorf("unknown argument %q", name)
		}
	}
	built := request{method: route.method, text: route.text}
	if key, ok := args["idempotency_key"]; ok {
		value, isString := key.(string)
		if !isString || !identifier(value) {
			return request{}, errors.New("invalid idempotency_key")
		}
		built.idempotencyKey = value
	}
	path := route.path
	query := url.Values{}
	var fields map[string]any
	for _, p := range route.params {
		value, present := args[p.name]
		if !present || value == nil {
			if p.required {
				return request{}, fmt.Errorf("%s is required", p.name)
			}
			continue
		}
		if err := p.check(value); err != nil {
			return request{}, err
		}
		switch p.in {
		case inPath:
			path = strings.Replace(path, "{"+p.name+"}", url.PathEscape(value.(string)), 1)
		case inQuery:
			query.Set(p.name, queryValue(value))
		case inBody:
			if p.name == bodyParam {
				object := value.(map[string]any)
				if fields == nil {
					fields = map[string]any{}
				}
				for key, field := range object {
					fields[key] = field
				}
				continue
			}
			if fields == nil {
				fields = map[string]any{}
			}
			fields[p.name] = value
		}
	}
	if strings.Contains(path, "{") {
		return request{}, errors.New("missing path argument")
	}
	built.path = path
	if len(query) > 0 {
		built.query = query
	}
	if fields != nil {
		built.body = fields
	} else if route.method == http.MethodPost || route.method == http.MethodPut || route.method == http.MethodPatch {
		built.body = map[string]any{}
	}
	return built, nil
}

func (p param) check(value any) error {
	invalid := fmt.Errorf("invalid %s", p.name)
	switch p.typ {
	case typeID:
		text, ok := value.(string)
		if !ok || !identifier(text) {
			return invalid
		}
	case typePath:
		text, ok := value.(string)
		if !ok || !relativePath(text) {
			return invalid
		}
	case typeString:
		text, ok := value.(string)
		if !ok || len(text) > 4096 {
			return invalid
		}
		if len(p.enum) > 0 && !slices.Contains(p.enum, text) {
			return fmt.Errorf("%s must be one of %s", p.name, strings.Join(p.enum, ", "))
		}
	case typeInteger:
		number, ok := value.(float64)
		if !ok || number != float64(int64(number)) {
			return invalid
		}
	case typeBoolean:
		if _, ok := value.(bool); !ok {
			return invalid
		}
	case typeStrings:
		items, ok := value.([]any)
		if !ok {
			return invalid
		}
		for _, item := range items {
			if _, ok := item.(string); !ok {
				return invalid
			}
		}
	case typeObject:
		if _, ok := value.(map[string]any); !ok {
			return invalid
		}
	case typeArray:
		if _, ok := value.([]any); !ok {
			return invalid
		}
	}
	return nil
}

func queryValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return fmt.Sprint(typed)
	}
}
