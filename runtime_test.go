// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package mcpruntime

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestNew tests runtime creation.
func TestNew(t *testing.T) {
	rt := New(&mcp.Implementation{
		Name:    "test-server",
		Version: "v1.0.0",
	}, nil)

	if rt == nil {
		t.Fatal("expected non-nil runtime")
	}

	if rt.MCPServer() == nil {
		t.Error("expected non-nil MCP server")
	}

	impl := rt.Implementation()
	if impl.Name != "test-server" {
		t.Errorf("expected name 'test-server', got %q", impl.Name)
	}
}

func TestNew_NilImplementation(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic with nil implementation")
		}
	}()
	New(nil, nil)
}

// addInput is the input type for the add tool.
type addInput struct {
	A int `json:"a"`
	B int `json:"b"`
}

// addOutput is the output type for the add tool.
type addOutput struct {
	Sum int `json:"sum"`
}

// addHandler is a typed handler for adding two numbers.
func addHandler(_ context.Context, _ *mcp.CallToolRequest, in addInput) (*mcp.CallToolResult, addOutput, error) {
	return nil, addOutput{Sum: in.A + in.B}, nil
}

// TestAddToolAndCallTool_LibraryMode tests tool registration and direct invocation.
func TestAddToolAndCallTool_LibraryMode(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	// Register tool
	AddTool(rt, &mcp.Tool{
		Name:        "add",
		Description: "Add two numbers",
	}, addHandler)

	// Verify tool is registered
	if !rt.HasTool("add") {
		t.Error("expected tool 'add' to be registered")
	}
	if rt.ToolCount() != 1 {
		t.Errorf("expected 1 tool, got %d", rt.ToolCount())
	}

	// Call tool directly (library mode)
	ctx := context.Background()
	result, err := rt.CallTool(ctx, "add", map[string]any{"a": 2, "b": 3})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	// Verify result
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content item, got %d", len(result.Content))
	}

	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if textContent.Text != `{"sum":5}` {
		t.Errorf("expected sum=5, got %s", textContent.Text)
	}
}

// TestCallTool_NotFound tests calling a non-existent tool.
func TestCallTool_NotFound(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	ctx := context.Background()
	_, err := rt.CallTool(ctx, "nonexistent", nil)
	if err == nil {
		t.Error("expected error for non-existent tool")
	}
}

// TestInMemorySession_ToolInterchangeability tests that tools work identically
// in library mode and MCP mode.
func TestInMemorySession_ToolInterchangeability(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	AddTool(rt, &mcp.Tool{
		Name:        "add",
		Description: "Add two numbers",
	}, addHandler)

	ctx := context.Background()

	// Call via library mode
	libraryResult, err := rt.CallTool(ctx, "add", map[string]any{"a": 10, "b": 20})
	if err != nil {
		t.Fatalf("library mode CallTool failed: %v", err)
	}

	// Call via MCP mode (InMemorySession)
	_, clientSession, err := rt.InMemorySession(ctx)
	if err != nil {
		t.Fatalf("InMemorySession failed: %v", err)
	}
	defer func() { _ = clientSession.Close() }()

	mcpResult, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "add",
		Arguments: map[string]any{"a": 10, "b": 20},
	})
	if err != nil {
		t.Fatalf("MCP mode CallTool failed: %v", err)
	}

	// Compare results - both should produce the same output
	libraryText := libraryResult.Content[0].(*mcp.TextContent).Text
	mcpText := mcpResult.Content[0].(*mcp.TextContent).Text

	if libraryText != mcpText {
		t.Errorf("library and MCP results differ:\n  library: %s\n  MCP: %s", libraryText, mcpText)
	}
}

// TestRemoveTools tests tool removal.
func TestRemoveTools(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	AddTool(rt, &mcp.Tool{Name: "add"}, addHandler)
	AddTool(rt, &mcp.Tool{Name: "subtract"}, addHandler) // reuse handler for simplicity

	if rt.ToolCount() != 2 {
		t.Errorf("expected 2 tools, got %d", rt.ToolCount())
	}

	rt.RemoveTools("add")

	if rt.HasTool("add") {
		t.Error("expected 'add' to be removed")
	}
	if !rt.HasTool("subtract") {
		t.Error("expected 'subtract' to still exist")
	}
	if rt.ToolCount() != 1 {
		t.Errorf("expected 1 tool, got %d", rt.ToolCount())
	}
}

// TestListTools tests listing tools.
func TestListTools(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	AddTool(rt, &mcp.Tool{Name: "tool1", Description: "First tool"}, addHandler)
	AddTool(rt, &mcp.Tool{Name: "tool2", Description: "Second tool"}, addHandler)

	tools := rt.ListTools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	if !names["tool1"] || !names["tool2"] {
		t.Errorf("expected both tool1 and tool2, got %v", names)
	}
}
