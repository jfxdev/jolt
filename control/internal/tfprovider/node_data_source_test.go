package tfprovider

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestClientListsOnlyTheNodesTheTokenMayList(t *testing.T) {
	controlURL, _ := newControl(t)
	client, err := NewClient(controlURL, testToken, "")
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := client.ListNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, node := range nodes {
		ids = append(ids, node.ID)
		if node.State != "offline" {
			t.Errorf("node %s state %q, want offline", node.ID, node.State)
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"n1", "n2", "n3"}) {
		t.Fatalf("listed %v", ids)
	}
}

func TestFindNode(t *testing.T) {
	nodes := []Node{{ID: "n1", Name: "media"}, {ID: "n2", Name: "backup"}, {ID: "n3", Name: "media"}}
	for _, test := range []struct {
		id, name, want, fails string
	}{
		{id: "n3", want: "n3"},
		{name: "backup", want: "n2"},
		{name: "media", fails: "2 nodes are named \"media\" (n1, n3)"},
		{name: "Backup", fails: "no node named"},
		{id: "n9", fails: "no node with id"},
	} {
		node, err := findNode(nodes, test.id, test.name)
		if test.fails != "" {
			if err == nil || !strings.Contains(err.Error(), test.fails) {
				t.Errorf("%+v: err %v, want %q", test, err, test.fails)
			}
			continue
		}
		if err != nil || node.ID != test.want {
			t.Errorf("%+v: got %+v %v", test, node, err)
		}
	}
}

func TestAccNodeDataSource(t *testing.T) {
	controlURL, _ := newControl(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			// Refusals first: the post-test destroy runs the last configuration.
			{
				Config:      providerBlock(controlURL) + `data "jolt_node" "media" { name = "media" }`,
				ExpectError: regexp.MustCompile(`2 nodes are named "media" \(n1, n3\)`),
			},
			{
				Config:      providerBlock(controlURL) + `data "jolt_node" "hidden" { name = "hidden" }`,
				ExpectError: regexp.MustCompile(`no node named "hidden"`),
			},
			{
				Config: providerBlock(controlURL) + `
data "jolt_node" "both" {
  id   = "n1"
  name = "media"
}
`,
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination`),
			},
			{
				Config: providerBlock(controlURL) + `
data "jolt_node" "backup" {
  name = "backup"
}

data "jolt_node" "by_id" {
  id = "n1"
}

resource "jolt_policy" "backup" {
  name  = "backup-read"
  rules = [{ path = "nodes/${data.jolt_node.backup.id}/files/**", capabilities = ["list", "read"] }]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.jolt_node.backup", "id", "n2"),
					resource.TestCheckResourceAttr("data.jolt_node.backup", "endpoint", "https://127.0.0.1:1/n2"),
					resource.TestCheckResourceAttr("data.jolt_node.backup", "state", "offline"),
					resource.TestCheckNoResourceAttr("data.jolt_node.backup", "configuration"),
					resource.TestCheckNoResourceAttr("data.jolt_node.backup", "last_seen_at"),
					resource.TestCheckResourceAttr("data.jolt_node.by_id", "name", "media"),
					resource.TestCheckResourceAttr("jolt_policy.backup", "rules.0.path", "nodes/n2/files/**"),
				),
			},
		},
	})
}
