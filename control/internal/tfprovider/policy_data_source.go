package tfprovider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

type policyDataSource struct {
	client *Client
}

var (
	_ datasource.DataSourceWithConfigure        = (*policyDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*policyDataSource)(nil)
)

func newPolicyDataSource() datasource.DataSource { return &policyDataSource{} }

func (d *policyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func computedStrings(description string) schema.SetAttribute {
	return schema.SetAttribute{Description: description, ElementType: stringSet.ElemType, Computed: true}
}

func (d *policyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads an RBAC policy by id or by name, such as one managed outside this configuration.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Description: "Policy id. Set id or name.", Optional: true, Computed: true},
			"name":        schema.StringAttribute{Description: "Exact policy name. Set id or name.", Optional: true, Computed: true},
			"description": schema.StringAttribute{Computed: true},
			"rules": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"path":         schema.StringAttribute{Computed: true},
						"capabilities": computedStrings("Capabilities granted, or denied with deny."),
						"file_types": schema.SingleNestedAttribute{
							Computed: true,
							Attributes: map[string]schema.Attribute{
								"classes":    computedStrings("File classes."),
								"extensions": computedStrings("File extensions without the dot."),
								"names":      computedStrings("Exact file names."),
							},
						},
						"visibility":     schema.StringAttribute{Computed: true},
						"needs_approval": computedStrings("Capabilities that need a person's approval."),
					},
				},
			},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

func (d *policyDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
	}
}

func (d *policyDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *Client, got %T", req.ProviderData))
		return
	}
	d.client = client
}

func (d *policyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config policyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var policy Policy
	var err error
	if !config.ID.IsNull() {
		policy, err = d.client.GetPolicy(ctx, config.ID.ValueString())
	} else {
		policy, err = d.client.FindPolicyByName(ctx, config.Name.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Could not read policy", err.Error())
		return
	}
	resp.Diagnostics.Append(config.setPolicy(ctx, policy)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}
