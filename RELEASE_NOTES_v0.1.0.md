# Release Notes - v0.1.0

**Release Date:** 2026-01-10

## Overview

This is the initial release of `mcpruntime`, a library-first runtime for building MCP (Model Context Protocol) servers in Go. It wraps the official [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk) to provide a unified API where tools, prompts, and resources can be invoked either directly as library calls or exposed over standard MCP transports.

## Installation

```bash
go get github.com/grokify/mcpruntime@v0.1.0
```

Requires Go 1.23+ and MCP Go SDK v1.2.0+.

## Key Features

### Dual Execution Modes

Define capabilities once, use them two ways:

- **Library Mode**: Direct in-process function calls without JSON-RPC overhead
- **Server Mode**: Standard MCP transports (stdio, HTTP, SSE)

```go
rt := mcpruntime.New(&mcp.Implementation{Name: "my-server", Version: "v1.0.0"}, nil)

// Register once
mcpruntime.AddTool(rt, &mcp.Tool{Name: "add"}, addHandler)

// Library mode
result, err := rt.CallTool(ctx, "add", args)

// Server mode
rt.ServeStdio(ctx)
```

### Full MCP SDK Compatibility

- Uses `mcp.Tool`, `mcp.Prompt`, `mcp.Resource` types directly
- Same handler signatures as the MCP SDK
- Automatic JSON schema inference via generic `AddTool[In, Out]()`
- All MCP transports supported

### Comprehensive Feature Support

| Feature | Library Mode | Server Mode |
|---------|:------------:|:-----------:|
| Tools | Yes | Yes |
| Prompts | Yes | Yes |
| Static Resources | Yes | Yes |
| Resource Templates | No | Yes |

## API Highlights

### Runtime Creation

```go
rt := mcpruntime.New(impl *mcp.Implementation, opts *mcpruntime.Options)
```

### Tool Registration

```go
// Generic with schema inference
mcpruntime.AddTool(rt, tool, handler)

// Low-level
rt.AddToolHandler(tool, handler)
```

### Library Mode Invocation

```go
rt.CallTool(ctx, name, args)
rt.GetPrompt(ctx, name, args)
rt.ReadResource(ctx, uri)
```

### Transport Adapters

```go
rt.ServeStdio(ctx)
rt.StreamableHTTPHandler(opts)
rt.SSEHandler(opts)
rt.InMemorySession(ctx)  // for testing
```

### Escape Hatch

```go
rt.MCPServer()  // access underlying mcp.Server for advanced use
```

## Use Cases

- **Unit testing** MCP tools without mocking transports
- **Embedding** agent capabilities directly in applications
- **Building** local pipelines with MCP tools
- **Serverless** runtimes where subprocess overhead is unacceptable
- **Gradual migration** from library calls to full MCP server

## Breaking Changes

None (initial release).

## Known Limitations

- Resource templates (dynamic URI patterns) work in server mode only; library mode supports exact URI matches
- Advanced MCP features (subscriptions, progress notifications) accessible via `MCPServer()` escape hatch

## Dependencies

- `github.com/modelcontextprotocol/go-sdk` v1.2.0

## Contributors

- John Wang

## Links

- [GitHub Repository](https://github.com/grokify/mcpruntime)
- [Go Package Documentation](https://pkg.go.dev/github.com/grokify/mcpruntime)
- [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
