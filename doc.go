// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

// Package mcpruntime provides a library-first runtime for building MCP servers
// with interchangeable execution modes: in-process library calls and MCP server
// transports (stdio, HTTP).
//
// mcpruntime wraps the official MCP Go SDK (github.com/modelcontextprotocol/go-sdk)
// to provide a unified API where tools, prompts, and resources are defined once
// and can be invoked either directly as library calls or exposed over standard
// MCP transports.
//
// # Design Philosophy
//
// MCP (Model Context Protocol) is fundamentally a client-server protocol based
// on JSON-RPC. However, many use cases benefit from invoking MCP capabilities
// directly in-process without the overhead of transport serialization:
//
//   - Unit testing tools without mocking transports
//   - Embedding agent capabilities in applications
//   - Building local pipelines
//   - Serverless runtimes
//
// mcpruntime treats MCP as an "edge protocol" while providing a library-first
// internal API. Tools registered with mcpruntime use the exact same handler
// signatures as the MCP SDK, ensuring behavior is identical regardless of
// execution mode.
//
// # Quick Start
//
// Create a runtime, register tools, and use them either directly or via MCP:
//
//	// Create runtime
//	rt := mcpruntime.New(&mcp.Implementation{
//		Name:    "my-server",
//		Version: "v1.0.0",
//	}, nil)
//
//	// Register a tool using MCP SDK types
//	type AddInput struct {
//		A int `json:"a"`
//		B int `json:"b"`
//	}
//	type AddOutput struct {
//		Sum int `json:"sum"`
//	}
//	rt.AddTool(&mcp.Tool{Name: "add"}, func(ctx context.Context, req *mcp.CallToolRequest, in AddInput) (*mcp.CallToolResult, AddOutput, error) {
//		return nil, AddOutput{Sum: in.A + in.B}, nil
//	})
//
//	// Library mode: call directly
//	result, err := rt.CallTool(ctx, "add", map[string]any{"a": 1, "b": 2})
//
//	// Server mode: expose via stdio
//	rt.ServeStdio(ctx)
//
// # Tool Registration
//
// Tools use the exact same types as the MCP SDK:
//
//   - [mcp.Tool] for tool metadata
//   - [mcp.ToolHandlerFor] for typed handlers with automatic schema inference
//   - [mcp.ToolHandler] for low-level handlers
//
// The generic [Runtime.AddTool] method provides automatic input/output schema
// generation and validation, matching the behavior of [mcp.AddTool].
//
// # Prompts and Resources
//
// Similarly, prompts and resources use MCP SDK types directly:
//
//   - [mcp.Prompt] with [mcp.PromptHandler]
//   - [mcp.Resource] with [mcp.ResourceHandler]
//
// # Transport Adapters
//
// When ready to expose capabilities over MCP transports, use:
//
//   - [Runtime.ServeStdio] for stdio transport (subprocess)
//   - [Runtime.ServeHTTP] for HTTP transport
//   - [Runtime.MCPServer] to access the underlying mcp.Server directly
package mcpruntime
