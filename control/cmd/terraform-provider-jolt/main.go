// Command terraform-provider-jolt is the Terraform and OpenTofu provider for
// the Jolt Control Tower. It is installed from a local filesystem mirror; see
// docs/TERRAFORM.md.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/jfxdev/jolt/control/internal/tfprovider"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "run with support for debuggers such as delve")
	flag.Parse()
	err := providerserver.Serve(context.Background(), tfprovider.New(version), providerserver.ServeOpts{
		Address: tfprovider.Address,
		Debug:   *debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
