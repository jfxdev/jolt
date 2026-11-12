package tfprovider

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/jfxdev/jolt/control/internal/filetypes"
	"github.com/jfxdev/jolt/control/internal/rbac"
)

// policyModel is the state of a jolt_policy resource and data source.
type policyModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Rules       types.List   `tfsdk:"rules"`
	CreatedAt   types.String `tfsdk:"created_at"`
	UpdatedAt   types.String `tfsdk:"updated_at"`
}

type ruleModel struct {
	Path          types.String `tfsdk:"path"`
	Capabilities  types.Set    `tfsdk:"capabilities"`
	FileTypes     types.Object `tfsdk:"file_types"`
	Visibility    types.String `tfsdk:"visibility"`
	NeedsApproval types.Set    `tfsdk:"needs_approval"`
}

type fileTypesModel struct {
	Classes    types.Set `tfsdk:"classes"`
	Extensions types.Set `tfsdk:"extensions"`
	Names      types.Set `tfsdk:"names"`
}

var objectAsOptions = basetypes.ObjectAsOptions{}

var stringSet = types.SetType{ElemType: types.StringType}

var fileTypesAttrTypes = map[string]attr.Type{
	"classes":    stringSet,
	"extensions": stringSet,
	"names":      stringSet,
}

var ruleAttrTypes = map[string]attr.Type{
	"path":           types.StringType,
	"capabilities":   stringSet,
	"file_types":     types.ObjectType{AttrTypes: fileTypesAttrTypes},
	"visibility":     types.StringType,
	"needs_approval": stringSet,
}

var capabilities = []string{"read", "list", "create", "update", "delete", "write", "execute", "sudo", "deny"}

// setPolicy writes what the Control Tower returned into the model. Empty
// optional values become null, the way they are left out of the configuration.
func (m *policyModel) setPolicy(ctx context.Context, policy Policy) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ID = types.StringValue(policy.ID)
	m.Name = types.StringValue(policy.Name)
	m.Description = types.StringValue(policy.Description)
	m.CreatedAt = types.StringValue(policy.CreatedAt.UTC().Format(time.RFC3339))
	m.UpdatedAt = types.StringValue(policy.UpdatedAt.UTC().Format(time.RFC3339))
	rules := make([]ruleModel, 0, len(policy.Rules))
	for _, rule := range policy.Rules {
		model := ruleModel{
			Path:          types.StringValue(rule.Path),
			Capabilities:  setOf(ctx, rule.Capabilities, false, &diags),
			FileTypes:     types.ObjectNull(fileTypesAttrTypes),
			Visibility:    types.StringNull(),
			NeedsApproval: setOf(ctx, rule.NeedsApproval, true, &diags),
		}
		if rule.Visibility != "" {
			model.Visibility = types.StringValue(rule.Visibility)
		}
		if rule.FileTypes != nil {
			value, d := types.ObjectValueFrom(ctx, fileTypesAttrTypes, fileTypesModel{
				Classes:    setOf(ctx, rule.FileTypes.Classes, true, &diags),
				Extensions: setOf(ctx, rule.FileTypes.Extensions, true, &diags),
				Names:      setOf(ctx, rule.FileTypes.Names, true, &diags),
			})
			diags.Append(d...)
			model.FileTypes = value
		}
		rules = append(rules, model)
	}
	value, d := types.ListValueFrom(ctx, types.ObjectType{AttrTypes: ruleAttrTypes}, rules)
	diags.Append(d...)
	m.Rules = value
	return diags
}

func setOf(ctx context.Context, values []string, nullWhenEmpty bool, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 && nullWhenEmpty {
		return types.SetNull(types.StringType)
	}
	value, d := types.SetValueFrom(ctx, types.StringType, values)
	diags.Append(d...)
	return value
}

// input builds the request body from a fully known plan.
func (m policyModel) input(ctx context.Context) (PolicyInput, diag.Diagnostics) {
	var diags diag.Diagnostics
	rules, d := m.rules(ctx)
	diags.Append(d...)
	input := PolicyInput{Name: m.Name.ValueString(), Description: m.Description.ValueString(), Rules: make([]rbac.Rule, 0, len(rules))}
	for _, model := range rules {
		rule, d := model.rule(ctx)
		diags.Append(d...)
		input.Rules = append(input.Rules, rule)
	}
	return input, diags
}

func (m policyModel) rules(ctx context.Context) ([]ruleModel, diag.Diagnostics) {
	var rules []ruleModel
	if m.Rules.IsNull() || m.Rules.IsUnknown() {
		return nil, nil
	}
	// A rule still unknown at plan time cannot be decoded; it is checked
	// once its value is known.
	for _, element := range m.Rules.Elements() {
		if element.IsUnknown() {
			return nil, nil
		}
	}
	diags := m.Rules.ElementsAs(ctx, &rules, false)
	return rules, diags
}

// rule converts one rule. Unknown values come out empty, so callers that
// validate must skip what is unknown first.
func (m ruleModel) rule(ctx context.Context) (rbac.Rule, diag.Diagnostics) {
	var diags diag.Diagnostics
	rule := rbac.Rule{
		Path:          m.Path.ValueString(),
		Capabilities:  stringsOf(ctx, m.Capabilities, &diags),
		Visibility:    m.Visibility.ValueString(),
		NeedsApproval: stringsOf(ctx, m.NeedsApproval, &diags),
	}
	if !m.FileTypes.IsNull() && !m.FileTypes.IsUnknown() {
		var model fileTypesModel
		diags.Append(m.FileTypes.As(ctx, &model, objectAsOptions)...)
		rule.FileTypes = &filetypes.Selector{
			Classes:    stringsOf(ctx, model.Classes, &diags),
			Extensions: stringsOf(ctx, model.Extensions, &diags),
			Names:      stringsOf(ctx, model.Names, &diags),
		}
	}
	return rule, diags
}

func stringsOf(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	if set.IsNull() || set.IsUnknown() {
		return nil
	}
	var values []string
	diags.Append(set.ElementsAs(ctx, &values, false)...)
	return values
}

// validate refuses, before any call, what the Control Tower would refuse or
// silently rewrite. A value it rewrites would show as a change on every plan,
// so only its canonical form is accepted. Rules the server checks against its
// own feature flags (file types, approvals) are left to it.
func (m policyModel) validate(ctx context.Context) diag.Diagnostics {
	var diags diag.Diagnostics
	if known(m.Description) && m.Description.ValueString() != strings.TrimSpace(m.Description.ValueString()) {
		diags.AddAttributeError(path.Root("description"), "Description has surrounding spaces",
			"The Control Tower trims the description; write it without leading or trailing spaces.")
	}
	rules, d := m.rules(ctx)
	diags.Append(d...)
	for index, model := range rules {
		at := path.Root("rules").AtListIndex(index)
		rule, d := model.rule(ctx)
		diags.Append(d...)
		if known(model.Path) {
			if canonical := rbac.NormalizePath(rule.Path); canonical != rule.Path {
				diags.AddAttributeError(at.AtName("path"), "Path is not in canonical form",
					fmt.Sprintf("The Control Tower stores this path as %q; write it that way.", canonical))
			} else if !rbac.ValidPath(rule.Path) {
				diags.AddAttributeError(at.AtName("path"), "Invalid path",
					"Segments may not be empty, . or .., * matches one whole segment and ** is only allowed as the last segment.")
			}
		}
		capabilitiesKnown := allKnown(model.Capabilities)
		fileTypesKnown := !model.FileTypes.IsUnknown()
		if capabilitiesKnown && fileTypesKnown && model.FileTypes.IsNull() && len(rule.Capabilities) > 1 && slices.Contains(rule.Capabilities, "deny") {
			diags.AddAttributeError(at.AtName("capabilities"), "deny stands alone",
				"A path rule with deny takes no other capability. To take capabilities away from some file types, add file_types.")
		}
		if fileTypesKnown && !model.FileTypes.IsNull() && fileTypesFullyKnown(ctx, model.FileTypes) {
			if _, err := rule.FileTypes.Compile(); err != nil {
				diags.AddAttributeError(at.AtName("file_types"), "Invalid file types", err.Error()+".")
			}
		}
		if known(model.Visibility) && fileTypesKnown && model.FileTypes.IsNull() {
			diags.AddAttributeError(at.AtName("visibility"), "visibility needs file_types",
				"visibility only applies to a rule restricted by file_types.")
		}
		if !model.NeedsApproval.IsNull() && allKnown(model.NeedsApproval) && capabilitiesKnown && fileTypesKnown && !model.Visibility.IsUnknown() {
			if !rbac.ValidNeedsApproval(rule) {
				diags.AddAttributeError(at.AtName("needs_approval"), "Invalid needs_approval",
					"needs_approval lists destructive capabilities the rule grants, on a rule without deny, file_types or visibility.")
			}
		}
	}
	return diags
}

func known(value types.String) bool { return !value.IsNull() && !value.IsUnknown() }

func allKnown(set types.Set) bool {
	if set.IsUnknown() {
		return false
	}
	for _, element := range set.Elements() {
		if element.IsUnknown() {
			return false
		}
	}
	return true
}

func fileTypesFullyKnown(ctx context.Context, object types.Object) bool {
	var model fileTypesModel
	if object.As(ctx, &model, objectAsOptions).HasError() {
		return false
	}
	return allKnown(model.Classes) && allKnown(model.Extensions) && allKnown(model.Names)
}
