// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package mcpruntime

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestAddResourceAndReadResource_LibraryMode tests resource registration and reading.
func TestAddResourceAndReadResource_LibraryMode(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	rt.AddResource(&mcp.Resource{
		URI:         "config://app/settings",
		Name:        "settings",
		Description: "Application settings",
		MIMEType:    "application/json",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:  req.Params.URI,
				Text: `{"debug": true}`,
			}},
		}, nil
	})

	if !rt.HasResource("config://app/settings") {
		t.Error("expected resource to be registered")
	}
	if rt.ResourceCount() != 1 {
		t.Errorf("expected 1 resource, got %d", rt.ResourceCount())
	}

	ctx := context.Background()
	result, err := rt.ReadResource(ctx, "config://app/settings")
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	if len(result.Contents) != 1 {
		t.Fatalf("expected 1 content, got %d", len(result.Contents))
	}

	expected := `{"debug": true}`
	if result.Contents[0].Text != expected {
		t.Errorf("expected %q, got %q", expected, result.Contents[0].Text)
	}
}

// TestReadResource_NotFound tests reading a non-existent resource.
func TestReadResource_NotFound(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	ctx := context.Background()
	_, err := rt.ReadResource(ctx, "nonexistent://uri")
	if err == nil {
		t.Error("expected error for non-existent resource")
	}
}

// TestRemoveResources tests resource removal.
func TestRemoveResources(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	handler := func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{}, nil
	}

	rt.AddResource(&mcp.Resource{URI: "config://one", Name: "one"}, handler)
	rt.AddResource(&mcp.Resource{URI: "config://two", Name: "two"}, handler)

	if rt.ResourceCount() != 2 {
		t.Errorf("expected 2 resources, got %d", rt.ResourceCount())
	}

	rt.RemoveResources("config://one")

	if rt.HasResource("config://one") {
		t.Error("expected 'config://one' to be removed")
	}
	if !rt.HasResource("config://two") {
		t.Error("expected 'config://two' to still exist")
	}
}

// TestListResources tests listing resources.
func TestListResources(t *testing.T) {
	rt := New(&mcp.Implementation{Name: "test", Version: "v1.0.0"}, nil)

	handler := func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{}, nil
	}

	rt.AddResource(&mcp.Resource{URI: "config://one", Name: "one"}, handler)
	rt.AddResource(&mcp.Resource{URI: "config://two", Name: "two"}, handler)

	resources := rt.ListResources()
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
}
