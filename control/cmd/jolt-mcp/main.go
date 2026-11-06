package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/jfxdev/jolt/control/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "trust" {
		os.Exit(runTrust(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	}
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: jolt-mcp [trust <url> --fingerprint <sha256>]")
		os.Exit(2)
	}
	server, err := mcpserver.New(os.Getenv("JOLT_MCP_CONTROL_URL"), os.Getenv("JOLT_MCP_CREDENTIAL_FILE"), caOptions(os.Getenv)...)
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

// caFile is the store of roots the server trusts: JOLT_MCP_CA_FILE, or the file
// `trust` writes by default.
func caFile(getenv func(string) string) string {
	if value := getenv("JOLT_MCP_CA_FILE"); value != "" {
		return value
	}
	return mcpserver.DefaultCAFile()
}

// caOptions makes the server trust only the stored roots. An explicit
// JOLT_MCP_CA_FILE always applies, even before the file exists, so a typo fails
// loudly. The default file applies once `trust` has created it, and until then
// the system's trust is used, as before.
func caOptions(getenv func(string) string) []mcpserver.Option {
	if value := getenv("JOLT_MCP_CA_FILE"); value != "" {
		return []mcpserver.Option{mcpserver.WithCAFile(value)}
	}
	if value := mcpserver.DefaultCAFile(); value != "" {
		if _, err := os.Stat(value); err == nil {
			return []mcpserver.Option{mcpserver.WithCAFile(value)}
		}
	}
	return nil
}

// runTrust implements `jolt-mcp trust <url> --fingerprint <sha256>`. The URL
// may come before or after the flags.
func runTrust(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	flags := flag.NewFlagSet("trust", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fingerprint := flags.String("fingerprint", "", "SHA-256 of the root, as shown by the Control Tower (required)")
	file := flags.String("ca-file", "", "where to store the roots (default: JOLT_MCP_CA_FILE, or the user config directory)")
	next := flags.Bool("next", false, "fetch the root a rotation is about to promote, keeping the current one")
	replace := flags.Bool("replace", false, "drop the roots already stored")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "usage: jolt-mcp trust <url> --fingerprint <sha256> [--ca-file path] [--next] [--replace]")
		flags.PrintDefaults()
	}
	var rest []string
	for len(args) > 0 {
		if err := flags.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		args = flags.Args()
		if len(args) == 0 {
			break
		}
		rest = append(rest, args[0])
		args = args[1:]
	}
	if len(rest) != 1 || *fingerprint == "" {
		flags.Usage()
		return 2
	}
	target := *file
	if target == "" {
		target = caFile(getenv)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := mcpserver.Trust(ctx, mcpserver.TrustOptions{URL: rest[0], Fingerprint: *fingerprint, CAFile: target, Next: *next, Replace: *replace})
	if err != nil {
		fmt.Fprintln(stderr, "jolt-mcp trust:", err)
		return 1
	}
	verb := "already trusted"
	if result.Added {
		verb = "trusted"
	}
	fmt.Fprintf(stdout, "%s %s (%s, valid until %s)\nstored in %s (%d root%s)\n", verb, result.Fingerprint, result.Subject, result.NotAfter.UTC().Format("2006-01-02"), result.CAFile, result.Roots, strings.Repeat("s", min(result.Roots-1, 1)))
	return 0
}
