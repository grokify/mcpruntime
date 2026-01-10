// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package mcpruntime

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolHandlerFor is an alias for the MCP SDK's typed tool handler.
// It provides automatic input/output schema inference and validation.
type ToolHandlerFor[In, Out any] = mcp.ToolHandlerFor[In, Out]

// ToolHandler is an alias for the MCP SDK's low-level tool handler.
type ToolHandler = mcp.ToolHandler

// AddToolHandler adds a tool with a low-level handler to the runtime.
//
// This is the low-level API that mirrors [mcp.Server.AddTool]. It does not
// perform automatic input validation or output schema generation.
//
// The tool's InputSchema must be non-nil and have type "object".
// See [mcp.Server.AddTool] for full documentation on requirements.
//
// Most users should use the generic [AddTool] function instead.
func (r *Runtime) AddToolHandler(t *mcp.Tool, h mcp.ToolHandler) {
	// Register with underlying MCP server
	r.server.AddTool(t, h)

	// Register in our internal map for library-mode dispatch
	r.mu.Lock()
	r.tools[t.Name] = toolEntry{tool: t, handler: h}
	r.mu.Unlock()
}

// AddTool adds a typed tool to the runtime with automatic schema inference.
//
// This mirrors [mcp.AddTool] from the MCP SDK. The generic type parameters
// In and Out are used to automatically generate JSON schemas for the tool's
// input and output if not already specified in the Tool struct.
//
// The In type provides the default input schema (must be a struct or map).
// The Out type provides the default output schema (use 'any' to omit).
//
// Example:
//
//	type AddInput struct {
//		A int `json:"a" jsonschema:"first number to add"`
//		B int `json:"b" jsonschema:"second number to add"`
//	}
//	type AddOutput struct {
//		Sum int `json:"sum"`
//	}
//
//	mcpruntime.AddTool(rt, &mcp.Tool{
//		Name:        "add",
//		Description: "Add two numbers",
//	}, func(ctx context.Context, req *mcp.CallToolRequest, in AddInput) (*mcp.CallToolResult, AddOutput, error) {
//		return nil, AddOutput{Sum: in.A + in.B}, nil
//	})
func AddTool[In, Out any](r *Runtime, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	// The MCP SDK's AddTool function handles schema inference and creates
	// a wrapped handler. We call it to register with the server.
	mcp.AddTool(r.server, t, h)

	// For library-mode dispatch, we need to create a compatible low-level
	// handler that matches what the MCP SDK creates internally.
	// This wrapper handles unmarshaling, validation, and result packaging.
	wrappedHandler := wrapTypedToolHandler(h)

	// Register in our internal map
	r.mu.Lock()
	r.tools[t.Name] = toolEntry{tool: t, handler: wrappedHandler}
	r.mu.Unlock()
}

// wrapTypedToolHandler creates a low-level ToolHandler from a typed handler.
// This mirrors the internal wrapping done by mcp.AddTool but for library-mode.
func wrapTypedToolHandler[In, Out any](h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Unmarshal input
		var input In
		if req.Params.Arguments != nil {
			if err := json.Unmarshal(req.Params.Arguments, &input); err != nil {
				return nil, fmt.Errorf("unmarshaling tool arguments: %w", err)
			}
		}

		// Call the typed handler
		result, output, err := h(ctx, req, input)
		if err != nil {
			// For tool errors, embed in result with IsError=true
			// (matching MCP SDK behavior)
			var errRes mcp.CallToolResult
			errRes.Content = []mcp.Content{&mcp.TextContent{Text: err.Error()}}
			errRes.IsError = true
			return &errRes, nil
		}

		if result == nil {
			result = &mcp.CallToolResult{}
		}

		// Marshal output for StructuredContent
		var outval any = output
		if outval != nil {
			outbytes, err := json.Marshal(outval)
			if err != nil {
				return nil, fmt.Errorf("marshaling tool output: %w", err)
			}
			result.StructuredContent = json.RawMessage(outbytes)

			// If Content is not set, populate with JSON text content
			if result.Content == nil {
				result.Content = []mcp.Content{&mcp.TextContent{Text: string(outbytes)}}
			}
		}

		return result, nil
	}
}

// RemoveTools removes tools with the given names from the runtime.
func (r *Runtime) RemoveTools(names ...string) {
	r.server.RemoveTools(names...)

	r.mu.Lock()
	for _, name := range names {
		delete(r.tools, name)
	}
	r.mu.Unlock()
}

// HasTool reports whether a tool with the given name is registered.
func (r *Runtime) HasTool(name string) bool {
	r.mu.RLock()
	_, ok := r.tools[name]
	r.mu.RUnlock()
	return ok
}

// ToolCount returns the number of registered tools.
func (r *Runtime) ToolCount() int {
	r.mu.RLock()
	n := len(r.tools)
	r.mu.RUnlock()
	return n
}
