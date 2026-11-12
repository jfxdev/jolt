package tfprovider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type nodeDataSource struct {
	client *Client
}

var (
	_ datasource.DataSourceWithConfigure        = (*nodeDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*nodeDataSource)(nil)
)

func newNodeDataSource() datasource.DataSource { return &nodeDataSource{} }

type nodeModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Endpoint      types.String `tfsdk:"endpoint"`
	State         types.String `tfsdk:"state"`
	Configuration types.Object `tfsdk:"configuration"`
	LastSeenAt    types.String `tfsdk:"last_seen_at"`
	CreatedAt     types.String `tfsdk:"created_at"`
	UpdatedAt     types.String `tfsdk:"updated_at"`
}

var nodeConfigurationAttrTypes = map[string]attr.Type{
	"source":         types.StringType,
	"apply_mode":     types.StringType,
	"mounts_mutable": types.BoolType,
	"grants_mutable": types.BoolType,
}

func (d *nodeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node"
}

func (d *nodeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a node registered in the Control Tower by id or by name, so policies can name nodes without hard-coding ids. " +
			"The token only sees nodes in one of its access groups that a policy grants list on nodes/<id>, such as a rule on nodes/* with list.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Description: "Node id. Set id or name.", Optional: true, Computed: true},
			"name":     schema.StringAttribute{Description: "Node name. Set id or name. Names are not unique: a name held by more than one visible node is an error.", Optional: true, Computed: true},
			"endpoint": schema.StringAttribute{Description: "Node API endpoint.", Computed: true},
			"state":    schema.StringAttribute{Description: "online, offline, degraded or untrusted, from the probe the Control Tower makes when the node is read.", Computed: true},
			"configuration": schema.SingleNestedAttribute{
				Description: "How the node's mounts and grants are managed, as the node last reported it. Null when the node did not answer.",
				Computed:    true,
				Attributes: map[string]schema.Attribute{
					"source":         schema.StringAttribute{Computed: true},
					"apply_mode":     schema.StringAttribute{Computed: true},
					"mounts_mutable": schema.BoolAttribute{Computed: true},
					"grants_mutable": schema.BoolAttribute{Computed: true},
				},
			},
			"last_seen_at": schema.StringAttribute{Description: "Last successful probe, RFC 3339. Null if never seen.", Computed: true},
			"created_at":   schema.StringAttribute{Description: "Registration time, RFC 3339.", Computed: true},
			"updated_at":   schema.StringAttribute{Description: "Time of the last change, RFC 3339.", Computed: true},
		},
	}
}

func (d *nodeDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
	}
}

func (d *nodeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *nodeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config nodeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	nodes, err := d.client.ListNodes(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not list nodes", err.Error())
		return
	}
	node, err := findNode(nodes, config.ID.ValueString(), config.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read node", err.Error())
		return
	}
	config.ID = types.StringValue(node.ID)
	config.Name = types.StringValue(node.Name)
	config.Endpoint = types.StringValue(node.Endpoint)
	config.State = types.StringValue(node.State)
	config.CreatedAt = types.StringValue(node.CreatedAt.UTC().Format(time.RFC3339Nano))
	config.UpdatedAt = types.StringValue(node.UpdatedAt.UTC().Format(time.RFC3339Nano))
	config.LastSeenAt = types.StringNull()
	if node.LastSeenAt != nil {
		config.LastSeenAt = types.StringValue(node.LastSeenAt.UTC().Format(time.RFC3339Nano))
	}
	config.Configuration = types.ObjectNull(nodeConfigurationAttrTypes)
	if c := node.Configuration; c != nil {
		value, diags := types.ObjectValue(nodeConfigurationAttrTypes, map[string]attr.Value{
			"source":         types.StringValue(c.Source),
			"apply_mode":     types.StringValue(c.ApplyMode),
			"mounts_mutable": types.BoolValue(c.MountsMutable),
			"grants_mutable": types.BoolValue(c.GrantsMutable),
		})
		resp.Diagnostics.Append(diags...)
		config.Configuration = value
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}

// findNode picks the node by id, or the only node with the name. A node the
// token cannot list is indistinguishable from one that does not exist.
func findNode(nodes []Node, id, name string) (Node, error) {
	const visibility = "the token sees only nodes in one of its access groups with list on nodes/<id>"
	if id != "" {
		for _, node := range nodes {
			if node.ID == id {
				return node, nil
			}
		}
		return Node{}, fmt.Errorf("no node with id %q; %s", id, visibility)
	}
	var matches []Node
	for _, node := range nodes {
		if node.Name == name {
			matches = append(matches, node)
		}
	}
	switch len(matches) {
	case 0:
		return Node{}, fmt.Errorf("no node named %q; %s", name, visibility)
	case 1:
		return matches[0], nil
	}
	ids := make([]string, 0, len(matches))
	for _, node := range matches {
		ids = append(ids, node.ID)
	}
	return Node{}, fmt.Errorf("%d nodes are named %q (%s); select one by id", len(matches), name, strings.Join(ids, ", "))
}
