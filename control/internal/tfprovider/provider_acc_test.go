package tfprovider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// These tests run the real terraform (or tofu, through TF_ACC_TERRAFORM_PATH)
// against an in-process Control Tower. They need TF_ACC=1.

var testProviders = map[string]func() (tfprotov6.ProviderServer, error){
	"jolt": providerserver.NewProtocol6WithError(New("test")()),
}

func providerBlock(controlURL string) string {
	return fmt.Sprintf(`
provider "jolt" {
  control_url = %q
  token       = %q
}
`, controlURL, testToken)
}

func TestAccPolicyLifecycle(t *testing.T) {
	controlURL, storage := newControl(t)
	created := providerBlock(controlURL) + `
resource "jolt_policy" "media" {
  name = "media-team"
  rules = [
    {
      path         = "nodes/n1/files/mounts/media/**"
      capabilities = ["list", "read"]
    },
    {
      path         = "nodes/n1/files/mounts/media/**"
      capabilities = ["deny", "read"]
      file_types   = { classes = ["secret"], extensions = ["pem"] }
      visibility   = "visible"
    },
    {
      path           = "nodes/n1/files/mounts/media/inbox/**"
      capabilities   = ["write", "delete"]
      needs_approval = ["delete"]
    },
  ]
}
`
	updated := providerBlock(controlURL) + `
resource "jolt_policy" "media" {
  name        = "media-team"
  description = "Media team"
  rules = [
    {
      path         = "nodes/n1/files/mounts/media/**"
      capabilities = ["read", "list", "create"]
    },
  ]
}

data "jolt_policy" "by_name" {
  name = jolt_policy.media.name
}
`
	var firstID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: created,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("jolt_policy.media", "id"),
					resource.TestCheckResourceAttr("jolt_policy.media", "description", ""),
					resource.TestCheckResourceAttr("jolt_policy.media", "rules.#", "3"),
					resource.TestCheckTypeSetElemAttr("jolt_policy.media", "rules.1.file_types.extensions.*", "pem"),
					resource.TestCheckNoResourceAttr("jolt_policy.media", "rules.0.file_types"),
					resource.TestCheckTypeSetElemAttr("jolt_policy.media", "rules.2.needs_approval.*", "delete"),
					func(s *terraform.State) error {
						firstID = s.RootModule().Resources["jolt_policy.media"].Primary.ID
						policy, err := storage.GetPolicy(context.Background(), firstID)
						if err != nil || len(policy.Rules) != 3 || policy.Rules[1].Visibility != "visible" {
							return fmt.Errorf("stored policy: %+v %v", policy, err)
						}
						return nil
					},
				),
			},
			{
				ResourceName:      "jolt_policy.media",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "jolt_policy.media",
				ImportState:       true,
				ImportStateId:     "name:media-team",
				ImportStateVerify: true,
			},
			{
				Config: updated,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jolt_policy.media", "description", "Media team"),
					resource.TestCheckResourceAttr("jolt_policy.media", "rules.#", "1"),
					resource.TestCheckResourceAttr("jolt_policy.media", "rules.0.capabilities.#", "3"),
					resource.TestCheckResourceAttrPair("data.jolt_policy.by_name", "id", "jolt_policy.media", "id"),
					resource.TestCheckResourceAttr("data.jolt_policy.by_name", "rules.0.path", "nodes/n1/files/mounts/media/**"),
					func(s *terraform.State) error {
						if id := s.RootModule().Resources["jolt_policy.media"].Primary.ID; id != firstID {
							return fmt.Errorf("update replaced the policy: %s became %s", firstID, id)
						}
						return nil
					},
				),
			},
			{
				// Deleted outside Terraform: the plan creates it again.
				PreConfig: func() {
					if err := storage.DeletePolicy(context.Background(), firstID); err != nil {
						t.Fatal(err)
					}
				},
				Config: updated,
				Check: func(s *terraform.State) error {
					id := s.RootModule().Resources["jolt_policy.media"].Primary.ID
					if id == firstID {
						return fmt.Errorf("policy was not created again")
					}
					_, err := storage.GetPolicy(context.Background(), id)
					return err
				},
			},
		},
		CheckDestroy: func(s *terraform.State) error {
			policies, err := storage.SearchPolicies(context.Background(), "media-team")
			if err != nil {
				return err
			}
			if len(policies) != 0 {
				return fmt.Errorf("policy left after destroy: %+v", policies)
			}
			return nil
		},
	})
}

func TestAccPolicyPlanRefusesNonCanonicalValues(t *testing.T) {
	controlURL, _ := newControl(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: providerBlock(controlURL) + `
resource "jolt_policy" "bad" {
  name  = "bad"
  rules = [{ path = "/nodes/n1/**", capabilities = ["read"] }]
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`stores this path as "nodes/n1/\*\*"`),
			},
			{
				Config: providerBlock(controlURL) + `
resource "jolt_policy" "bad" {
  name  = "bad"
  rules = [{ path = "nodes/n1", capabilities = ["READ"] }]
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`value must be one of`),
			},
		},
	})
}

func TestAccPolicyServerRefusalIsReported(t *testing.T) {
	controlURL, _ := newControl(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviders,
		Steps: []resource.TestStep{{
			// The fixture's own policy already holds this name.
			Config: providerBlock(controlURL) + `
resource "jolt_policy" "taken" {
  name  = "terraform"
  rules = [{ path = "nodes/n1", capabilities = ["read"] }]
}
`,
			ExpectError: regexp.MustCompile(`409 policy_conflict`),
		}},
	})
}
