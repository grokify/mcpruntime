# Release Notes - v0.3.1

**Release Date:** 2026-01-18

## Overview

This is a security patch release that fixes an open URL redirect vulnerability in the OAuth2 server component.

## Installation

```bash
go get github.com/agentplexus/mcpkit@v0.3.1
```

## Security Fix

### Open URL Redirect Vulnerability (CWE-601)

**Severity:** Medium  
**Component:** `oauth2/handlers.go` - `isValidRedirectURI` function

**Problem:** The `isValidRedirectURI` function accepted a wildcard `"*"` in the allowed redirect URIs list, which would permit redirection to any URL. This could allow attackers to redirect users to malicious sites after OAuth authentication.

**Fix:** The function now:
- Ignores wildcard `"*"` entries instead of treating them as "allow any"
- Properly parses URIs with `net/url` and rejects malformed URIs
- Requires exact scheme, host, and path match for absolute URIs
- Requires exact path match for relative URIs

**Impact:** Clients with properly configured explicit redirect URIs are unaffected. Only the insecure wildcard behavior is removed.

**Recommendation:** All users of the OAuth2 server component should upgrade to v0.3.1.

## Upgrade Guide

This is a drop-in replacement for v0.3.0:

```bash
go get github.com/agentplexus/mcpkit@v0.3.1
```

No code changes required unless you were relying on the wildcard `"*"` redirect URI behavior (which was insecure).

## Contributors

- John Wang

## Links

- [GitHub Repository](https://github.com/agentplexus/mcpkit)
- [Go Package Documentation](https://pkg.go.dev/github.com/agentplexus/mcpkit)
