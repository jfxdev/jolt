package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/jfxdev/jolt/control/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	server, err := mcpserver.New(os.Getenv("JOLT_MCP_CONTROL_URL"), os.Getenv("JOLT_MCP_CREDENTIAL_FILE"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "jolt-mcp: invalid configuration")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := server.MCP().Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "jolt-mcp: server stopped")
		os.Exit(1)
	}
}
