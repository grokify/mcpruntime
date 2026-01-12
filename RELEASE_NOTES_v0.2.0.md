# Release Notes - v0.2.0

**Release Date:** 2026-01-11

## Overview

This release adds OAuth 2.1 authentication and HTTP server capabilities to mcpruntime, enabling deployment of MCP servers that work with ChatGPT.com and other OAuth-requiring clients. The new `ServeHTTP()` method provides a complete HTTP transport with optional ngrok tunnel integration for public URL exposure.

## Installation

```bash
go get github.com/grokify/mcpruntime@v0.2.0
```

Requires Go 1.23+ and MCP Go SDK v1.2.0+.

## Highlights

- **OAuth 2.1 Authorization Code + PKCE** support for ChatGPT.com and other MCP clients requiring user authentication
- **HTTP server mode** with optional ngrok tunnel for public URL exposure
- **Bearer token authentication** for protecting MCP endpoints

## What's New

### HTTP Server with ngrok Integration

New `ServeHTTP()` method provides a complete HTTP transport with graceful shutdown:

```go
result, err := rt.ServeHTTP(ctx, &mcpruntime.HTTPServerOptions{
    Addr: ":8080",
    Ngrok: &mcpruntime.NgrokOptions{
        Enabled: true,
        Domain:  "my-mcp-server.ngrok.io",
    },
    OnReady: func(r mcpruntime.HTTPServerResult) {
        fmt.Printf("Server ready at %s\n", r.PublicURL)
    },
})
```

### OAuth 2.1 with PKCE

Full OAuth 2.1 implementation required by ChatGPT.com:

```go
result, err := rt.ServeHTTP(ctx, &mcpruntime.HTTPServerOptions{
    Addr: ":8080",
    OAuth2: &mcpruntime.OAuth2Options{
        Issuer:   "https://my-mcp-server.example.com",
        ClientID: "chatgpt",
        // PKCE is automatically enforced per RFC 7636
    },
})
```

The `oauth2server` package implements:

- RFC 7636 - Proof Key for Code Exchange (PKCE)
- RFC 7591 - OAuth 2.0 Dynamic Client Registration
- RFC 8414 - OAuth 2.0 Authorization Server Metadata
- RFC 9728 - OAuth 2.0 Protected Resource Metadata

### Bearer Token Authentication

Protect MCP endpoints with bearer token middleware:

```go
result, err := rt.ServeHTTP(ctx, &mcpruntime.HTTPServerOptions{
    Addr: ":8080",
    OAuth: &mcpruntime.OAuthOptions{
        ClientID:     "my-client",
        ClientSecret: "my-secret",
    },
})
// Tokens available in result.OAuth.AccessToken
```

## API Additions

| Addition | Description |
|----------|-------------|
| `ServeHTTP()` | HTTP transport with graceful shutdown |
| `NgrokOptions` | Automatic ngrok tunnel with custom domain support |
| `OAuth2Options` | OAuth 2.1 Authorization Code + PKCE configuration |
| `oauth2server` | Full OAuth 2.1 server implementation |
| `HTTPServerResult` | Result with local/public URLs and OAuth credentials |
| `OnReady` callback | Server lifecycle event for startup notification |

## Deprecations

| Deprecated | Replacement | Rationale |
|------------|-------------|-----------|
| `OAuthOptions` | `OAuth2Options` | `OAuthOptions` only supports client_credentials grant; `OAuth2Options` provides full OAuth 2.1 with PKCE required by ChatGPT.com |

The deprecated `OAuthOptions` will continue to work but new integrations should use `OAuth2Options`.

## Upgrade Guide

### From v0.1.0

This is a backward-compatible release. Existing code using `ServeStdio()`, `StreamableHTTPHandler()`, or library mode will continue to work unchanged.

To adopt the new HTTP server:

```go
// Before (v0.1.0) - manual HTTP setup
http.Handle("/mcp", rt.StreamableHTTPHandler(nil))
http.ListenAndServe(":8080", nil)

// After (v0.2.0) - integrated HTTP server
rt.ServeHTTP(ctx, &mcpruntime.HTTPServerOptions{Addr: ":8080"})
```

To add OAuth 2.1 for ChatGPT.com:

```go
rt.ServeHTTP(ctx, &mcpruntime.HTTPServerOptions{
    Addr: ":8080",
    OAuth2: &mcpruntime.OAuth2Options{
        Issuer: "https://your-domain.com",
    },
    Ngrok: &mcpruntime.NgrokOptions{Enabled: true},
})
```

## Breaking Changes

None.

## Dependencies

New dependencies added:

- `golang.ngrok.com/ngrok/v2` - ngrok tunnel integration
- `github.com/inconshreveable/log15/v3` - ngrok logging

## Contributors

- John Wang

## Links

- [GitHub Repository](https://github.com/grokify/mcpruntime)
- [Go Package Documentation](https://pkg.go.dev/github.com/grokify/mcpruntime)
- [MCP Go SDK](https://github.com/modelcontextprotocol/go-sdk)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [ChatGPT MCP Integration Guide](https://platform.openai.com/docs/actions/mcp)
