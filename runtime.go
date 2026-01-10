// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package mcpruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Runtime is the core type for mcpruntime. It wraps an MCP Server and provides
// both library-mode direct invocation and transport-based MCP server capabilities.
//
// A Runtime should be created with [New] and configured with tools, prompts,
// and resources before use.
type Runtime struct {
	server *mcp.Server
	impl   *mcp.Implementation
	opts   *Options
	logger *slog.Logger

	// mu protects the handler registries for library-mode dispatch.
	// We maintain parallel registries to enable direct invocation without
	// going through the MCP JSON-RPC layer.
	mu        sync.RWMutex
	tools     map[string]toolEntry
	prompts   map[string]promptEntry
	resources map[string]resourceEntry
}

// toolEntry holds a tool and its handler for direct invocation.
type toolEntry struct {
	tool    *mcp.Tool
	handler mcp.ToolHandler
}

// promptEntry holds a prompt and its handler for direct invocation.
type promptEntry struct {
	prompt  *mcp.Prompt
	handler mcp.PromptHandler
}

// resourceEntry holds a resource and its handler for direct invocation.
type resourceEntry struct {
	resource *mcp.Resource
	handler  mcp.ResourceHandler
}

// Options configures a Runtime.
type Options struct {
	// Logger for runtime activity. If nil, a default logger is used.
	Logger *slog.Logger

	// ServerOptions are passed directly to the underlying mcp.Server.
	ServerOptions *mcp.ServerOptions
}

// New creates a new Runtime with the given implementation info and options.
//
// The implementation parameter must not be nil and describes the server
// identity (name, version, etc.) that will be reported to MCP clients.
//
// The options parameter may be nil to use default options.
func New(impl *mcp.Implementation, opts *Options) *Runtime {
	if impl == nil {
		panic("mcpruntime: nil Implementation")
	}

	if opts == nil {
		opts = &Options{}
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var serverOpts *mcp.ServerOptions
	if opts.ServerOptions != nil {
		serverOpts = opts.ServerOptions
	}

	server := mcp.NewServer(impl, serverOpts)

	return &Runtime{
		server:    server,
		impl:      impl,
		opts:      opts,
		logger:    logger,
		tools:     make(map[string]toolEntry),
		prompts:   make(map[string]promptEntry),
		resources: make(map[string]resourceEntry),
	}
}

// MCPServer returns the underlying mcp.Server for advanced use cases.
//
// This is an escape hatch for scenarios where direct access to the MCP SDK
// server is needed, such as plugging into existing MCP infrastructure or
// accessing features not yet exposed by mcpruntime.
//
// Use with caution: modifications to the returned server may not be reflected
// in mcpruntime's library-mode dispatch.
func (r *Runtime) MCPServer() *mcp.Server {
	return r.server
}

// Implementation returns the server's implementation info.
func (r *Runtime) Implementation() *mcp.Implementation {
	return r.impl
}

// ErrToolNotFound is returned when attempting to call a tool that doesn't exist.
var ErrToolNotFound = errors.New("tool not found")

// ErrPromptNotFound is returned when attempting to get a prompt that doesn't exist.
var ErrPromptNotFound = errors.New("prompt not found")

// ErrResourceNotFound is returned when attempting to read a resource that doesn't exist.
var ErrResourceNotFound = errors.New("resource not found")

// CallTool invokes a tool by name with the given arguments.
//
// This is the library-mode entry point for tool invocation. It bypasses
// MCP JSON-RPC transport and directly invokes the tool handler.
//
// The args parameter should be a map[string]any or a struct that can be
// marshaled to JSON matching the tool's input schema.
//
// Returns ErrToolNotFound if no tool with the given name exists.
func (r *Runtime) CallTool(ctx context.Context, name string, args any) (*mcp.CallToolResult, error) {
	r.mu.RLock()
	entry, ok := r.tools[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrToolNotFound, name)
	}

	// Marshal args to json.RawMessage for the handler
	var rawArgs json.RawMessage
	if args != nil {
		var err error
		rawArgs, err = json.Marshal(args)
		if err != nil {
			return nil, fmt.Errorf("marshaling tool arguments: %w", err)
		}
	}

	// Create a CallToolRequest matching what the MCP SDK expects.
	// Note: In library mode, there's no session, so Session will be nil.
	// Handlers should be written to handle this gracefully.
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      name,
			Arguments: rawArgs,
		},
	}

	result, err := entry.handler(ctx, req)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// GetPrompt retrieves a prompt by name with the given arguments.
//
// This is the library-mode entry point for prompt retrieval. It bypasses
// MCP JSON-RPC transport and directly invokes the prompt handler.
//
// Returns ErrPromptNotFound if no prompt with the given name exists.
func (r *Runtime) GetPrompt(ctx context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error) {
	r.mu.RLock()
	entry, ok := r.prompts[name]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrPromptNotFound, name)
	}

	req := &mcp.GetPromptRequest{
		Params: &mcp.GetPromptParams{
			Name:      name,
			Arguments: args,
		},
	}

	return entry.handler(ctx, req)
}

// ReadResource reads a resource by URI.
//
// This is the library-mode entry point for resource reading. It bypasses
// MCP JSON-RPC transport and directly invokes the resource handler.
//
// Returns ErrResourceNotFound if no resource with the given URI exists.
func (r *Runtime) ReadResource(ctx context.Context, uri string) (*mcp.ReadResourceResult, error) {
	r.mu.RLock()
	entry, ok := r.resources[uri]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrResourceNotFound, uri)
	}

	req := &mcp.ReadResourceRequest{
		Params: &mcp.ReadResourceParams{
			URI: uri,
		},
	}

	return entry.handler(ctx, req)
}

// ListTools returns all registered tools.
func (r *Runtime) ListTools() []*mcp.Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]*mcp.Tool, 0, len(r.tools))
	for _, entry := range r.tools {
		tools = append(tools, entry.tool)
	}
	return tools
}

// ListPrompts returns all registered prompts.
func (r *Runtime) ListPrompts() []*mcp.Prompt {
	r.mu.RLock()
	defer r.mu.RUnlock()

	prompts := make([]*mcp.Prompt, 0, len(r.prompts))
	for _, entry := range r.prompts {
		prompts = append(prompts, entry.prompt)
	}
	return prompts
}

// ListResources returns all registered resources.
func (r *Runtime) ListResources() []*mcp.Resource {
	r.mu.RLock()
	defer r.mu.RUnlock()

	resources := make([]*mcp.Resource, 0, len(r.resources))
	for _, entry := range r.resources {
		resources = append(resources, entry.resource)
	}
	return resources
}
