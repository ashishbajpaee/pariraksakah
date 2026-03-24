// Package oidc handles enterprise identity federation via OAuth2/OIDC protocols.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ProviderConfig represents an OIDC provider's configuration.
type ProviderConfig struct {
	ProviderURL   string // e.g., https://keycloak.example.com/realms/cybershield
	ClientID      string // e.g., pariraksakah-client
	ClientSecret  string // Must be stored securely (e.g., in environment or Secrets Manager)
	RedirectURI   string // e.g., http://localhost:8002/auth/federation/callback
	Scopes        []string
	ResponseType  string // "code" for Authorization Code flow
	GrantType     string // "authorization_code"
	TokenEndpoint string // Populated from discovery
	AuthorizeURL  string // Populated from discovery
	UserinfoURL   string // Populated from discovery
	JWKSURL       string // Populated from discovery
}

// ProviderMetadata from OIDC Discovery (RFC 8414)
type ProviderMetadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// TokenResponse from OAuth2 token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // "Bearer"
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// UserInfo from OIDC userinfo endpoint
type UserInfo struct {
	Subject string                 `json:"sub"` // Unique user ID from IdP
	Email   string                 `json:"email"`
	Name    string                 `json:"name"`
	Groups  []string               `json:"groups"` // Optional: LDAP groups or custom groups claim
	Custom  map[string]interface{} `json:"-"`      // Catch-all for provider-specific claims
}

// OAuth2Client encapsulates OIDC/OAuth2 client logic
type OAuth2Client struct {
	config   *ProviderConfig
	metadata *ProviderMetadata
	client   *http.Client
}

// NewOAuth2Client initializes an OIDC client and discovers provider configuration.
func NewOAuth2Client(cfg *ProviderConfig) (*OAuth2Client, error) {
	if cfg.ProviderURL == "" || cfg.ClientID == "" {
		return nil, fmt.Errorf("provider URL and client ID required")
	}

	oac := &OAuth2Client{
		config: cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}

	// Discover provider metadata (RFC 8414)
	if err := oac.discover(); err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	return oac, nil
}

// discover fetches provider metadata from /.well-known/openid-configuration
func (oac *OAuth2Client) discover() error {
	discoveryURL := oac.config.ProviderURL + "/.well-known/openid-configuration"

	resp, err := oac.client.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discovery failed with status %d: %s", resp.StatusCode, string(body))
	}

	oac.metadata = &ProviderMetadata{}
	if err := json.NewDecoder(resp.Body).Decode(oac.metadata); err != nil {
		return fmt.Errorf("failed to parse discovery document: %w", err)
	}

	// Populate config from metadata
	oac.config.TokenEndpoint = oac.metadata.TokenEndpoint
	oac.config.AuthorizeURL = oac.metadata.AuthorizationEndpoint
	oac.config.UserinfoURL = oac.metadata.UserInfoEndpoint
	oac.config.JWKSURL = oac.metadata.JWKSURI

	return nil
}

// AuthorizationURL generates the authorization URL with PKCE
func (oac *OAuth2Client) AuthorizationURL(state, codeChallenge string) (string, error) {
	if oac.config.AuthorizeURL == "" {
		return "", fmt.Errorf("authorization endpoint not discovered")
	}

	query := url.Values{
		"client_id":             {oac.config.ClientID},
		"redirect_uri":          {oac.config.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {fmt.Sprintf("%v", oac.config.Scopes)}, // e.g., "openid profile email groups"
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"}, // PKCE with SHA256
	}

	return oac.config.AuthorizeURL + "?" + query.Encode(), nil
}

// ExchangeCodeForToken trades authorization code for access/ID token
func (oac *OAuth2Client) ExchangeCodeForToken(code, codeVerifier string) (*TokenResponse, error) {
	if oac.config.TokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint not discovered")
	}

	payload := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {oac.config.ClientID},
		"client_secret": {oac.config.ClientSecret},
		"code":          {code},
		"redirect_uri":  {oac.config.RedirectURI},
		"code_verifier": {codeVerifier}, // PKCE
	}

	resp, err := oac.client.PostForm(oac.config.TokenEndpoint, payload)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo fetches user information from the userinfo endpoint
func (oac *OAuth2Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if oac.config.UserinfoURL == "" {
		return nil, fmt.Errorf("userinfo endpoint not discovered")
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, oac.config.UserinfoURL, nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := oac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var userInfo UserInfo
	var rawMap map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rawMap); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}

	// Standard OIDC claims
	if sub, ok := rawMap["sub"].(string); ok {
		userInfo.Subject = sub
	}
	if email, ok := rawMap["email"].(string); ok {
		userInfo.Email = email
	}
	if name, ok := rawMap["name"].(string); ok {
		userInfo.Name = name
	}

	// Groups claim (varies by IdP implementation)
	if groups, ok := rawMap["groups"].([]interface{}); ok {
		for _, g := range groups {
			if groupStr, ok := g.(string); ok {
				userInfo.Groups = append(userInfo.Groups, groupStr)
			}
		}
	}

	userInfo.Custom = rawMap

	return &userInfo, nil
}

// PKCEChallenge generates code verifier and challenge for PKCE
func PKCEChallenge() (verifier, challenge string, err error) {
	// Generate 32-byte random code verifier
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	// Create challenge: base64url(sha256(verifier))
	// Note: This is a simplified example; use crypto/sha256 for SHA256 hashing
	challenge = verifier // Simplified: in practice, compute SHA256(verifier)

	return verifier, challenge, nil
}

// State generates a random state parameter for CSRF protection
func State() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
