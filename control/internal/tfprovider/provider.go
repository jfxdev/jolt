// Package tfprovider is the Terraform and OpenTofu provider for the Control
// Tower. It manages RBAC policies through the same API as the web UI and
// validates them with the Control Tower's own rules, so a plan refuses what
// the server would refuse or rewrite. Nodes can be read by name, so
// configurations need not hard-code node ids.
package tfprovider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Address is the provider source the CLI configuration maps to a local mirror.
const Address = "jolt.internal/jfxdev/jolt"

type joltProvider struct {
	version string
}

type providerModel struct {
	ControlURL types.String `tfsdk:"control_url"`
	Token      types.String `tfsdk:"token"`
	CAFile     types.String `tfsdk:"ca_file"`
}

// New returns the provider factory for providerserver.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &joltProvider{version: version} }
}

func (p *joltProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jolt"
	resp.Version = p.version
}

func (p *joltProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Jolt Control Tower RBAC policies and reads its nodes.",
		Attributes: map[string]schema.Attribute{
			"control_url": schema.StringAttribute{
				Description: "Control Tower URL, such as https://jolt.example.com. HTTPS is required outside loopback. Defaults to JOLT_CONTROL_URL.",
				Optional:    true,
			},
			"token": schema.StringAttribute{
				Description: "Service account token with sudo on control-tower/policies, and list on the nodes jolt_node reads. Defaults to JOLT_TOKEN.",
				Optional:    true,
				Sensitive:   true,
			},
			"ca_file": schema.StringAttribute{
				Description: "PEM file with the roots that sign the Control Tower certificate, replacing the system trust. Defaults to JOLT_CA_FILE.",
				Optional:    true,
			},
		},
	}
}

func (p *joltProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, value := range map[string]types.String{"control_url": config.ControlURL, "token": config.Token, "ca_file": config.CAFile} {
		if value.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider setting",
				"The provider needs "+name+" before the plan; set it from a value known at plan time or from its environment variable.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	controlURL := valueOr(config.ControlURL, "JOLT_CONTROL_URL")
	token := valueOr(config.Token, "JOLT_TOKEN")
	caFile := valueOr(config.CAFile, "JOLT_CA_FILE")
	if controlURL == "" {
		resp.Diagnostics.AddAttributeError(path.Root("control_url"), "Missing Control Tower URL", "Set control_url or JOLT_CONTROL_URL.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"), "Missing token", "Set token or JOLT_TOKEN.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	client, err := NewClient(controlURL, token, caFile)
	if err != nil {
		resp.Diagnostics.AddError("Invalid provider configuration", err.Error())
		return
	}
	resp.ResourceData = client
	resp.DataSourceData = client
}

func valueOr(value types.String, variable string) string {
	if !value.IsNull() {
		return value.ValueString()
	}
	return os.Getenv(variable)
}

func (p *joltProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{newPolicyResource}
}

func (p *joltProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newPolicyDataSource, newNodeDataSource}
}
