// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package mcpruntime

import (
	"context"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestAddPromptAndGetPrompt_LibraryMode tests prompt registration and retrieval.
func TestAddPromptAndGetPrompt_LibraryMode(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	rt.AddPrompt(&mcp.Prompt{
		Name:        "summarize",
		Description: "Summarize text",
		Arguments: []*mcp.PromptArgument{
			{Name: "text", Description: "Text to summarize", Required: true},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		text := req.Params.Arguments["text"]
		return &mcp.GetPromptResult{
			Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{
					Text: fmt.Sprintf("Please summarize: %s", text),
				}},
			},
		}, nil
	})

	if !rt.HasPrompt("summarize") {
		t.Error("expected prompt 'summarize' to be registered")
	}
	if rt.PromptCount() != 1 {
		t.Errorf("expected 1 prompt, got %d", rt.PromptCount())
	}

	ctx := context.Background()
	result, err := rt.GetPrompt(ctx, "summarize", map[string]string{"text": "Hello world"})
	if err != nil {
		t.Fatalf("GetPrompt failed: %v", err)
	}

	if len(result.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(result.Messages))
	}

	textContent, ok := result.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Messages[0].Content)
	}
	expected := "Please summarize: Hello world"
	if textContent.Text != expected {
		t.Errorf("expected %q, got %q", expected, textContent.Text)
	}
}

// TestGetPrompt_NotFound tests retrieving a non-existent prompt.
func TestGetPrompt_NotFound(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	ctx := context.Background()
	_, err := rt.GetPrompt(ctx, "nonexistent", nil)
	if err == nil {
		t.Error("expected error for non-existent prompt")
	}
}

// TestRemovePrompts tests prompt removal.
func TestRemovePrompts(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	handler := func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{}, nil
	}

	rt.AddPrompt(&mcp.Prompt{Name: "prompt1"}, handler)
	rt.AddPrompt(&mcp.Prompt{Name: "prompt2"}, handler)

	if rt.PromptCount() != 2 {
		t.Errorf("expected 2 prompts, got %d", rt.PromptCount())
	}

	rt.RemovePrompts("prompt1")

	if rt.HasPrompt("prompt1") {
		t.Error("expected 'prompt1' to be removed")
	}
	if !rt.HasPrompt("prompt2") {
		t.Error("expected 'prompt2' to still exist")
	}
}

// TestListPrompts tests listing prompts.
func TestListPrompts(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	handler := func(_ context.Context, _ *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{}, nil
	}

	rt.AddPrompt(&mcp.Prompt{Name: "prompt1", Description: "First"}, handler)
	rt.AddPrompt(&mcp.Prompt{Name: "prompt2", Description: "Second"}, handler)

	prompts := rt.ListPrompts()
	if len(prompts) != 2 {
		t.Fatalf("expected 2 prompts, got %d", len(prompts))
	}
}
