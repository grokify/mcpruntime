// Copyright 2025 John Wang. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package oauth2

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuth 2.0 error codes per RFC 6749
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorAccessDenied            = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorServerError             = "server_error"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
)

// OAuthError represents an OAuth 2.0 error response.
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// RegistrationRequest is the DCR request body (RFC 7591).
type RegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// RegistrationResponse is the DCR response body (RFC 7591).
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// TokenRequest represents a token endpoint request.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// TokenResponse is the token endpoint response body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// registrationHandler handles Dynamic Client Registration (RFC 7591).
func (s *Server) registrationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS headers for browser clients
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			writeOAuthError(w, http.StatusMethodNotAllowed, ErrorInvalidRequest, "Method not allowed")
			return
		}

		var req RegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "Invalid JSON body")
			return
		}

		// Validate redirect URIs
		if len(req.RedirectURIs) == 0 {
			writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "redirect_uris is required")
			return
		}

		for _, uri := range req.RedirectURIs {
			if _, err := url.Parse(uri); err != nil {
				writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "Invalid redirect_uri: "+uri)
				return
			}
		}

		// Set defaults
		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}

		responseTypes := req.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}

		authMethod := req.TokenEndpointAuthMethod
		if authMethod == "" {
			authMethod = "none" // Public client by default for PKCE
		}

		// Generate credentials
		clientID, err := GenerateClientID()
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to generate client ID")
			return
		}

		var clientSecret string
		if authMethod != "none" {
			clientSecret, err = GenerateClientSecret()
			if err != nil {
				writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to generate client secret")
				return
			}
		}

		// Create client
		client := &Client{
			ClientID:                clientID,
			ClientSecret:            clientSecret,
			ClientName:              req.ClientName,
			RedirectURIs:            req.RedirectURIs,
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			TokenEndpointAuthMethod: authMethod,
			CreatedAt:               time.Now(),
		}

		if err := s.storage.CreateClient(client); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to store client")
			return
		}

		// Build response
		resp := RegistrationResponse{
			ClientID:                clientID,
			ClientSecret:            clientSecret,
			ClientName:              client.ClientName,
			RedirectURIs:            client.RedirectURIs,
			GrantTypes:              client.GrantTypes,
			ResponseTypes:           client.ResponseTypes,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// authorizationHandler handles the authorization endpoint.
func (s *Server) authorizationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle GET (show login form) and POST (process login)
		switch r.Method {
		case http.MethodGet:
			s.handleAuthorizationGet(w, r)
		case http.MethodPost:
			s.handleAuthorizationPost(w, r)
		default:
			writeOAuthError(w, http.StatusMethodNotAllowed, ErrorInvalidRequest, "Method not allowed")
		}
	})
}

// handleAuthorizationGet shows the login page.
func (s *Server) handleAuthorizationGet(w http.ResponseWriter, r *http.Request) {
	// Parse and validate authorization request
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	scope := q.Get("scope")

	// Validate required parameters
	if clientID == "" {
		s.renderLoginError(w, "Missing client_id parameter")
		return
	}

	if responseType != "code" {
		s.redirectWithError(w, r, redirectURI, state, ErrorUnsupportedResponseType, "Only 'code' response_type is supported")
		return
	}

	// Validate client
	client, err := s.storage.GetClient(clientID)
	if err != nil {
		s.renderLoginError(w, "Unknown client")
		return
	}

	// Validate redirect URI
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}

	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		s.renderLoginError(w, "Invalid redirect_uri")
		return
	}

	// PKCE is required for OAuth 2.1
	if codeChallenge == "" {
		s.redirectWithError(w, r, redirectURI, state, ErrorInvalidRequest, "code_challenge is required (PKCE)")
		return
	}

	if codeChallengeMethod != "" && codeChallengeMethod != PKCEMethodS256 {
		s.redirectWithError(w, r, redirectURI, state, ErrorInvalidRequest, "Only S256 code_challenge_method is supported")
		return
	}

	// Render login page
	s.renderLoginPage(w, &loginPageData{
		ClientID:            clientID,
		ClientName:          client.ClientName,
		RedirectURI:         redirectURI,
		State:               state,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})
}

// handleAuthorizationPost processes the login form submission.
func (s *Server) handleAuthorizationPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLoginError(w, "Failed to parse form")
		return
	}

	// Get form values
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scope := r.FormValue("scope")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	// Validate client exists
	client, err := s.storage.GetClient(clientID)
	if err != nil {
		s.renderLoginError(w, "Unknown client")
		return
	}

	// Validate redirect URI
	if !isValidRedirectURI(redirectURI, client.RedirectURIs) {
		s.renderLoginError(w, "Invalid redirect_uri")
		return
	}

	// Authenticate user
	if !s.authenticator(username, password) {
		s.renderLoginPage(w, &loginPageData{
			ClientID:            clientID,
			ClientName:          client.ClientName,
			RedirectURI:         redirectURI,
			State:               state,
			Scope:               scope,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Error:               "Invalid username or password",
		})
		return
	}

	// Generate authorization code
	code, err := GenerateAuthorizationCode()
	if err != nil {
		s.redirectWithError(w, r, redirectURI, state, ErrorServerError, "Failed to generate authorization code")
		return
	}

	// Store authorization code
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Subject:             username,
		ExpiresAt:           time.Now().Add(s.config.AuthorizationCodeExpiry),
		CreatedAt:           time.Now(),
	}

	if err := s.storage.CreateAuthorizationCode(authCode); err != nil {
		s.redirectWithError(w, r, redirectURI, state, ErrorServerError, "Failed to store authorization code")
		return
	}

	// Redirect with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		s.renderLoginError(w, "Invalid redirect URI")
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// tokenHandler handles the token endpoint.
func (s *Server) tokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logDebug("token request received", "method", r.Method, "path", r.URL.Path)

		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodPost {
			s.logDebug("token error: method not allowed", "method", r.Method)
			writeOAuthError(w, http.StatusMethodNotAllowed, ErrorInvalidRequest, "Method not allowed")
			return
		}

		if err := r.ParseForm(); err != nil {
			s.logDebug("token error: failed to parse form", "error", err)
			writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "Failed to parse form")
			return
		}

		// Parse token request
		req := &TokenRequest{
			GrantType:    r.FormValue("grant_type"),
			Code:         r.FormValue("code"),
			RedirectURI:  r.FormValue("redirect_uri"),
			CodeVerifier: r.FormValue("code_verifier"),
			RefreshToken: r.FormValue("refresh_token"),
			Scope:        r.FormValue("scope"),
		}

		// Get client credentials from Basic auth or form body
		req.ClientID, req.ClientSecret, _ = r.BasicAuth()
		if req.ClientID == "" {
			req.ClientID = r.FormValue("client_id")
			req.ClientSecret = r.FormValue("client_secret")
		}

		s.logDebug("token request parsed",
			"grant_type", req.GrantType,
			"client_id", req.ClientID,
			"code", truncate(req.Code, 10)+"...",
			"redirect_uri", req.RedirectURI,
			"code_verifier_len", len(req.CodeVerifier))

		switch req.GrantType {
		case "authorization_code":
			s.handleAuthorizationCodeGrant(w, req)
		case "refresh_token":
			s.handleRefreshTokenGrant(w, req)
		default:
			s.logDebug("token error: unsupported grant_type", "grant_type", req.GrantType)
			writeOAuthError(w, http.StatusBadRequest, ErrorUnsupportedGrantType, "Unsupported grant_type")
		}
	})
}

// truncate returns the first n characters of s, or s if len(s) < n.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// handleAuthorizationCodeGrant handles the authorization_code grant type.
func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, req *TokenRequest) {
	// Validate required parameters
	if req.Code == "" {
		s.logDebug("token error: code is required")
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "code is required")
		return
	}

	if req.CodeVerifier == "" {
		s.logDebug("token error: code_verifier is required")
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "code_verifier is required (PKCE)")
		return
	}

	// Get and validate authorization code
	authCode, err := s.storage.GetAuthorizationCode(req.Code)
	if err != nil {
		s.logDebug("token error: invalid authorization code", "error", err)
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidGrant, "Invalid or expired authorization code")
		return
	}

	s.logDebug("found auth code",
		"client_id", authCode.ClientID,
		"subject", authCode.Subject,
		"redirect_uri", authCode.RedirectURI)

	// Validate client ID matches
	if authCode.ClientID != req.ClientID {
		s.logDebug("token error: client ID mismatch",
			"code_client_id", authCode.ClientID,
			"request_client_id", req.ClientID)
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidGrant, "Client ID mismatch")
		return
	}

	// Authenticate the client (verify client_secret for confidential clients)
	client, err := s.storage.GetClient(req.ClientID)
	if err != nil {
		s.logDebug("token error: unknown client", "client_id", req.ClientID, "error", err)
		writeOAuthError(w, http.StatusUnauthorized, ErrorInvalidClient, "Unknown client")
		return
	}

	// If client has a secret, verify it
	if client.ClientSecret != "" && client.ClientSecret != req.ClientSecret {
		s.logDebug("token error: invalid client credentials", "client_id", req.ClientID)
		writeOAuthError(w, http.StatusUnauthorized, ErrorInvalidClient, "Invalid client credentials")
		return
	}

	// Validate redirect URI
	if req.RedirectURI != "" && req.RedirectURI != authCode.RedirectURI {
		s.logDebug("token error: redirect_uri mismatch",
			"code_redirect_uri", authCode.RedirectURI,
			"request_redirect_uri", req.RedirectURI)
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidGrant, "redirect_uri mismatch")
		return
	}

	// Verify PKCE
	method := authCode.CodeChallengeMethod
	if method == "" {
		method = PKCEMethodS256
	}

	s.logDebug("verifying PKCE",
		"method", method,
		"challenge", truncate(authCode.CodeChallenge, 10)+"...",
		"verifier_len", len(req.CodeVerifier))

	if err := VerifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge, method); err != nil {
		s.logDebug("token error: PKCE verification failed", "error", err)
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidGrant, "PKCE verification failed")
		return
	}

	s.logDebug("PKCE verification successful")

	// Mark code as used
	if err := s.storage.MarkAuthorizationCodeUsed(req.Code); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to consume authorization code")
		return
	}

	// Generate tokens
	accessToken, err := GenerateAccessToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to generate access token")
		return
	}

	var refreshToken string
	var refreshExpiresAt time.Time
	if s.config.RefreshTokenExpiry > 0 {
		refreshToken, err = GenerateRefreshToken()
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to generate refresh token")
			return
		}
		refreshExpiresAt = time.Now().Add(s.config.RefreshTokenExpiry)
	}

	// Store token
	tokenInfo := &TokenInfo{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        "Bearer",
		ClientID:         authCode.ClientID,
		Subject:          authCode.Subject,
		Scope:            authCode.Scope,
		ExpiresAt:        time.Now().Add(s.config.AccessTokenExpiry),
		RefreshExpiresAt: refreshExpiresAt,
		CreatedAt:        time.Now(),
	}

	if err := s.storage.CreateToken(tokenInfo); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to store token")
		return
	}

	// Return token response
	resp := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}

	s.logDebug("token issued successfully",
		"client_id", authCode.ClientID,
		"subject", authCode.Subject,
		"expires_in", resp.ExpiresIn)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRefreshTokenGrant handles the refresh_token grant type.
func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, req *TokenRequest) {
	if req.RefreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidRequest, "refresh_token is required")
		return
	}

	// Get token by refresh token
	oldToken, err := s.storage.GetTokenByRefresh(req.RefreshToken)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidGrant, "Invalid refresh token")
		return
	}

	// Validate client
	if req.ClientID != "" && oldToken.ClientID != req.ClientID {
		writeOAuthError(w, http.StatusBadRequest, ErrorInvalidGrant, "Client ID mismatch")
		return
	}

	// Delete old token
	_ = s.storage.DeleteToken(oldToken.AccessToken)

	// Generate new tokens
	accessToken, err := GenerateAccessToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to generate access token")
		return
	}

	var refreshToken string
	var refreshExpiresAt time.Time
	if s.config.RefreshTokenExpiry > 0 {
		refreshToken, err = GenerateRefreshToken()
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to generate refresh token")
			return
		}
		refreshExpiresAt = time.Now().Add(s.config.RefreshTokenExpiry)
	}

	// Determine scope
	scope := req.Scope
	if scope == "" {
		scope = oldToken.Scope
	}

	// Store new token
	tokenInfo := &TokenInfo{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        "Bearer",
		ClientID:         oldToken.ClientID,
		Subject:          oldToken.Subject,
		Scope:            scope,
		ExpiresAt:        time.Now().Add(s.config.AccessTokenExpiry),
		RefreshExpiresAt: refreshExpiresAt,
		CreatedAt:        time.Now(),
	}

	if err := s.storage.CreateToken(tokenInfo); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, ErrorServerError, "Failed to store token")
		return
	}

	// Return token response
	resp := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// metadataHandler returns the authorization server metadata (RFC 8414).
func (s *Server) metadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Derive base URL from request if issuer doesn't include it
		baseURL := s.config.Issuer
		if baseURL == "" {
			baseURL = getBaseURL(r)
		}

		metadata := map[string]interface{}{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + s.paths.Authorization,
			"token_endpoint":                        baseURL + s.paths.Token,
			"registration_endpoint":                 baseURL + s.paths.Registration,
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
			"code_challenge_methods_supported":      []string{"S256"},
		}

		if len(s.config.AllowedScopes) > 0 {
			metadata["scopes_supported"] = s.config.AllowedScopes
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})
}

// protectedResourceMetadataHandler returns the protected resource metadata (RFC 9728).
func (s *Server) protectedResourceMetadataHandler(resourcePath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		baseURL := s.config.Issuer
		if baseURL == "" {
			baseURL = getBaseURL(r)
		}

		metadata := map[string]interface{}{
			"resource":                 baseURL + resourcePath,
			"authorization_servers":    []string{baseURL},
			"bearer_methods_supported": []string{"header"},
		}

		if len(s.config.AllowedScopes) > 0 {
			metadata["scopes_supported"] = s.config.AllowedScopes
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})
}

// Helper functions

func writeOAuthError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(OAuthError{
		Error:            errCode,
		ErrorDescription: description,
	})
}

func (s *Server) redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, description string) {
	if redirectURI == "" {
		s.renderLoginError(w, description)
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		s.renderLoginError(w, description)
		return
	}

	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", description)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func isValidRedirectURI(uri string, allowed []string) bool {
	if uri == "" {
		return false
	}

	// Parse the requested URI
	requestedURL, err := url.Parse(uri)
	if err != nil {
		return false
	}

	for _, a := range allowed {
		// Skip empty entries and wildcards (wildcards are not secure)
		if a == "" || a == "*" {
			continue
		}

		// Parse the allowed URI
		allowedURL, err := url.Parse(a)
		if err != nil {
			continue
		}

		// Check if this is an absolute URI (has scheme)
		if allowedURL.Scheme != "" {
			// For absolute URIs: require exact scheme, host, and path match
			if requestedURL.Scheme == allowedURL.Scheme &&
				strings.EqualFold(requestedURL.Host, allowedURL.Host) &&
				requestedURL.Path == allowedURL.Path {
				return true
			}
		} else {
			// For relative URIs: require exact match of path
			if requestedURL.Path == allowedURL.Path && requestedURL.Host == "" && requestedURL.Scheme == "" {
				return true
			}
		}
	}
	return false
}

func getBaseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + r.Host
}

// Login page rendering

type loginPageData struct {
	ClientID            string
	ClientName          string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

const defaultLoginPageHTML = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        h1 {
            font-size: 24px;
            color: #333;
            margin-bottom: 8px;
            text-align: center;
        }
        .client-name {
            color: #666;
            text-align: center;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c00;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            color: #555;
            font-size: 14px;
            font-weight: 500;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e1e1;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>Sign In</h1>
        {{if .ClientName}}
        <p class="client-name">to continue to {{.ClientName}}</p>
        {{else}}
        <p class="client-name">to continue</p>
        {{end}}

        {{if .Error}}
        <div class="error">{{.Error}}</div>
        {{end}}

        <form method="POST">
            <input type="hidden" name="client_id" value="{{.ClientID}}">
            <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
            <input type="hidden" name="state" value="{{.State}}">
            <input type="hidden" name="scope" value="{{.Scope}}">
            <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
            <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">

            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`

var loginPageTemplate = template.Must(template.New("login").Parse(defaultLoginPageHTML))

func (s *Server) renderLoginPage(w http.ResponseWriter, data *loginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl := loginPageTemplate
	if s.config.LoginPageTemplate != "" {
		var err error
		tmpl, err = template.New("custom-login").Parse(s.config.LoginPageTemplate)
		if err != nil {
			http.Error(w, "Failed to render login page", http.StatusInternalServerError)
			return
		}
	}

	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "Failed to render login page", http.StatusInternalServerError)
	}
}

func (s *Server) renderLoginError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, err := fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>
<h1>Error</h1>
<p>%s</p>
</body>
</html>`, template.HTMLEscapeString(message))
	if err != nil {
		s.logger.Warn("failed to write login error response", "error", err)
	}
}

// BearerAuthMiddleware returns middleware that validates Bearer tokens
// and sets the token info in the request context.
func (s *Server) BearerAuthMiddleware(resourceMetadataURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			s.logDebugCtx(ctx, "auth middleware request", "method", r.Method, "path", r.URL.Path)

			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				s.logDebugCtx(ctx, "auth middleware: no Bearer token, returning 401")
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceMetadataURL))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")
			s.logDebugCtx(ctx, "auth middleware: validating token", "token", truncate(token, 10)+"...")

			tokenInfo, err := s.storage.GetToken(token)
			if err != nil {
				s.logDebugCtx(ctx, "auth middleware: invalid token", "error", err)
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s", error="invalid_token"`, resourceMetadataURL))
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			s.logDebugCtx(ctx, "auth middleware: token valid",
				"client_id", tokenInfo.ClientID,
				"subject", tokenInfo.Subject)

			// Store token info in context for downstream handlers
			ctx = SetTokenInfoContext(ctx, tokenInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
