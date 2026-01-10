// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package mcpruntime

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ResourceHandler is an alias for the MCP SDK's resource handler.
type ResourceHandler = mcp.ResourceHandler

// AddResource adds a resource to the runtime.
//
// The resource handler is called when clients request the resource via
// resources/read. In library mode, it can be invoked directly via
// [Runtime.ReadResource].
//
// Example:
//
//	rt.AddResource(&mcp.Resource{
//		URI:         "config://app/settings",
//		Name:        "settings",
//		Description: "Application settings",
//		MIMEType:    "application/json",
//	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
//		return &mcp.ReadResourceResult{
//			Contents: []*mcp.ResourceContents{{
//				URI:  req.Params.URI,
//				Text: `{"debug": true}`,
//			}},
//		}, nil
//	})
func (r *Runtime) AddResource(res *mcp.Resource, h mcp.ResourceHandler) {
	// Register with underlying MCP server
	r.server.AddResource(res, h)

	// Register in our internal map for library-mode dispatch
	r.mu.Lock()
	r.resources[res.URI] = resourceEntry{resource: res, handler: h}
	r.mu.Unlock()
}

// AddResourceTemplate adds a resource template to the runtime.
//
// Resource templates allow dynamic resource URIs using URI template syntax
// (RFC 6570). The handler is called for any URI matching the template.
//
// Note: Resource templates are registered with the MCP server but not
// currently supported in library-mode dispatch. Use [Runtime.MCPServer]
// for full resource template support.
func (r *Runtime) AddResourceTemplate(t *mcp.ResourceTemplate, h mcp.ResourceHandler) {
	r.server.AddResourceTemplate(t, h)
}

// RemoveResources removes resources with the given URIs from the runtime.
func (r *Runtime) RemoveResources(uris ...string) {
	r.server.RemoveResources(uris...)

	r.mu.Lock()
	for _, uri := range uris {
		delete(r.resources, uri)
	}
	r.mu.Unlock()
}

// RemoveResourceTemplates removes resource templates with the given URI templates.
func (r *Runtime) RemoveResourceTemplates(uriTemplates ...string) {
	r.server.RemoveResourceTemplates(uriTemplates...)
}

// HasResource reports whether a resource with the given URI is registered.
func (r *Runtime) HasResource(uri string) bool {
	r.mu.RLock()
	_, ok := r.resources[uri]
	r.mu.RUnlock()
	return ok
}

// ResourceCount returns the number of registered resources.
func (r *Runtime) ResourceCount() int {
	r.mu.RLock()
	n := len(r.resources)
	r.mu.RUnlock()
	return n
}
