package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jfxdev/jolt/control/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "trust" {
		os.Exit(runTrust(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" {
		os.Exit(runServe(os.Args[2:], os.Stderr, os.Getenv))
	}
	if len(os.Args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: jolt-mcp [serve [--address host:port] | trust <url> --fingerprint <sha256>]")
		os.Exit(2)
	}
	options, err := serverOptions(os.Getenv, []string{mcpserver.ToolsetFiles})
	if err != nil {
		fmt.Fprintln(os.Stderr, "jolt-mcp:", err)
		os.Exit(1)
	}
	server, err := mcpserver.New(os.Getenv("JOLT_MCP_CONTROL_URL"), os.Getenv("JOLT_MCP_CREDENTIAL_FILE"), options...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "jolt-mcp: invalid configuration:", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.MCP().Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "jolt-mcp: server stopped")
		os.Exit(1)
	}
}

// serverOptions reads the settings both transports share: trust, toolsets,
// read-only mode and plain HTTP to the Control Tower.
func serverOptions(getenv func(string) string, toolsets []string) ([]mcpserver.Option, error) {
	options := caOptions(getenv)
	if value := strings.TrimSpace(getenv("JOLT_MCP_TOOLSETS")); value != "" {
		toolsets = splitList(value)
	}
	options = append(options, mcpserver.WithToolsets(toolsets...))
	for _, setting := range []struct {
		name   string
		option mcpserver.Option
	}{
		{"JOLT_MCP_READ_ONLY", mcpserver.WithReadOnly()},
		{"JOLT_MCP_INSECURE_CONTROL_URL", mcpserver.WithInsecureControlURL()},
	} {
		value := strings.TrimSpace(getenv(setting.name))
		if value == "" {
			continue
		}
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("%s must be true or false", setting.name)
		}
		if enabled {
			options = append(options, setting.option)
		}
	}
	return options, nil
}

func splitList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// runServe implements `jolt-mcp serve`: MCP over Streamable HTTP, where every
// request carries the bearer token of the agent making it.
func runServe(args []string, stderr io.Writer, getenv func(string) string) int {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	defaultAddress := getenv("JOLT_MCP_HTTP_ADDRESS")
	if defaultAddress == "" {
		defaultAddress = ":8092"
	}
	address := flags.String("address", defaultAddress, "listen address (default: JOLT_MCP_HTTP_ADDRESS, or :8092)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: jolt-mcp serve [--address host:port]")
		return 2
	}
	handler, err := httpHandler(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "jolt-mcp serve:", err)
		return 1
	}
	certFile, keyFile := getenv("JOLT_MCP_TLS_CERT_FILE"), getenv("JOLT_MCP_TLS_KEY_FILE")
	if (certFile == "") != (keyFile == "") {
		fmt.Fprintln(stderr, "jolt-mcp serve: set both JOLT_MCP_TLS_CERT_FILE and JOLT_MCP_TLS_KEY_FILE, or neither")
		return 1
	}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		fmt.Fprintln(stderr, "jolt-mcp serve: cannot listen on", *address)
		return 1
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	if certFile == "" {
		fmt.Fprintln(stderr, "jolt-mcp serve: no TLS configured; bearer tokens travel in plain text, so keep the port on loopback or a private network behind a TLS proxy")
	}
	fmt.Fprintln(stderr, "jolt-mcp serve: listening on", listener.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failed := make(chan error, 1)
	go func() {
		if certFile != "" {
			failed <- server.ServeTLS(listener, certFile, keyFile)
			return
		}
		failed <- server.Serve(listener)
	}()
	select {
	case err := <-failed:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(stderr, "jolt-mcp serve: server stopped:", err)
			return 1
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			fmt.Fprintln(stderr, "jolt-mcp serve: shutdown incomplete")
			return 1
		}
	}
	return 0
}

// httpHandler builds the HTTP transport from the environment. A credential
// file is never used here: each agent sends its own token.
func httpHandler(getenv func(string) string) (http.Handler, error) {
	options, err := serverOptions(getenv, mcpserver.DefaultHTTPToolsets)
	if err != nil {
		return nil, err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	options = append(options, mcpserver.WithRequestCredential(), mcpserver.WithLogger(logger))
	if getenv("JOLT_MCP_CREDENTIAL_FILE") != "" {
		logger.Warn("JOLT_MCP_CREDENTIAL_FILE is ignored by serve; each client sends its own bearer token")
	}
	server, err := mcpserver.New(getenv("JOLT_MCP_CONTROL_URL"), "", options...)
	if err != nil {
		return nil, err
	}
	return server.Handler(mcpserver.HTTPOptions{AllowedOrigins: splitList(getenv("JOLT_MCP_ALLOWED_ORIGINS"))})
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
