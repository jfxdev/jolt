package tfprovider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// importByName is the prefix of an import id that names the policy.
const importByName = "name:"

type policyResource struct {
	client *Client
}

var (
	_ resource.ResourceWithConfigure      = (*policyResource)(nil)
	_ resource.ResourceWithImportState    = (*policyResource)(nil)
	_ resource.ResourceWithValidateConfig = (*policyResource)(nil)
)

func newPolicyResource() resource.Resource { return &policyResource{} }

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

var policyName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func setStrings(description string, required bool, validators ...validator.Set) schema.SetAttribute {
	return schema.SetAttribute{
		Description: description,
		ElementType: stringSet.ElemType,
		Required:    required,
		Optional:    !required,
		Validators:  validators,
	}
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nonEmpty := setvalidator.SizeAtLeast(1)
	resp.Schema = schema.Schema{
		Description: "An RBAC policy: rules granting capabilities on node and Control Tower paths. Changing or deleting a policy stops the agent streams that relied on it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "Policy id.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "Unique name: 3 to 64 letters, digits, dots, underscores or hyphens.",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(3, 64),
					stringvalidator.RegexMatches(policyName, "must hold only letters, digits, dots, underscores or hyphens"),
				},
			},
			"description": schema.StringAttribute{
				Description: "Up to 512 bytes.",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Validators:  []validator.String{stringvalidator.LengthAtMost(512)},
			},
			"rules": schema.ListNestedAttribute{
				Description: "1 to 100 rules. deny takes precedence over every grant.",
				Required:    true,
				Validators:  []validator.List{listvalidator.SizeBetween(1, 100)},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"path": schema.StringAttribute{
							Description: "Path the rule covers, without leading or trailing slash, such as nodes/<node>/files/mounts/<mount>/**. * matches one segment; a final ** matches the path and everything under it.",
							Required:    true,
						},
						"capabilities": setStrings("Capabilities granted, or denied with deny: "+strings.Join(capabilities, ", ")+".", true,
							setvalidator.SizeBetween(1, 9), setvalidator.ValueStringsAre(stringvalidator.OneOf(capabilities...))),
						"file_types": schema.SingleNestedAttribute{
							Description: "Restricts the rule to these file types. Needs typed policies enabled on the Control Tower.",
							Optional:    true,
							Attributes: map[string]schema.Attribute{
								"classes":    setStrings("File classes: video, audio, image, document, archive, executable or secret.", false, nonEmpty),
								"extensions": setStrings("File extensions without the dot.", false, nonEmpty),
								"names":      setStrings("Exact file names.", false, nonEmpty),
							},
						},
						"visibility": schema.StringAttribute{
							Description: "When a read or list is denied by this typed rule: hidden (the Control Tower default when unset) drops the entry, visible shows it blocked.",
							Optional:    true,
							Validators:  []validator.String{stringvalidator.OneOf("hidden", "visible")},
						},
						"needs_approval": setStrings("Capabilities of this rule, delete or update, that run only once a person approves each request. Needs approvals enabled on the Control Tower.", false, nonEmpty),
					},
				},
			},
			"created_at": schema.StringAttribute{
				Description:   "Creation time, RFC 3339.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"updated_at": schema.StringAttribute{
				Description: "Time of the last change, RFC 3339.",
				Computed:    true,
			},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *policyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config policyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(config.validate(ctx)...)
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	input, diags := plan.input(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, err := r.client.CreatePolicy(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError("Could not create policy "+input.Name, err.Error())
		return
	}
	resp.Diagnostics.Append(plan.setPolicy(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, err := r.client.GetPolicy(ctx, state.ID.ValueString())
	if isStatus(err, http.StatusNotFound) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Could not read policy "+state.ID.ValueString(), err.Error())
		return
	}
	resp.Diagnostics.Append(state.setPolicy(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	input, diags := plan.input(ctx)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	policy, err := r.client.UpdatePolicy(ctx, state.ID.ValueString(), input)
	if err != nil {
		resp.Diagnostics.AddError("Could not update policy "+state.ID.ValueString(), err.Error())
		return
	}
	resp.Diagnostics.Append(plan.setPolicy(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeletePolicy(ctx, state.ID.ValueString()); err != nil && !isStatus(err, http.StatusNotFound) {
		resp.Diagnostics.AddError("Could not delete policy "+state.ID.ValueString(), err.Error())
	}
}

// ImportState takes a policy id, or name:<name>.
func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := req.ID
	if name, ok := strings.CutPrefix(id, importByName); ok {
		policy, err := r.client.FindPolicyByName(ctx, name)
		if err != nil {
			resp.Diagnostics.AddError("Could not import policy "+name, err.Error())
			return
		}
		id = policy.ID
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
