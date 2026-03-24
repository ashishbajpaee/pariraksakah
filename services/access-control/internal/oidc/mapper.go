// Package oidc handles claim mapping from external identity providers to internal roles.
package oidc

import (
	"fmt"
	"strings"
	"time"
)

// ClaimMapper translates external IdP claims to internal roles and attributes
type ClaimMapper struct {
	GroupRoleMap map[string]string // External group → internal role (e.g., "security-analysts" → "analyst")
	EmailDomains map[string]string // Email domain → default role (e.g., "@company.io" → "analyst")
	DefaultRole  string            // Default role if no mapping found (e.g., "viewer")
}

// MappedUser represents the internal user after claim mapping
type MappedUser struct {
	Username string   // From IdP email or name
	Email    string   // From IdP email claim
	Role     string   // Mapped internal role (admin, analyst, responder, viewer)
	Groups   []string // Internal roles/groups
	Status   string   // active or inactive
	Reason   string   // Why user was accepted/rejected
}

// NewClaimMapper creates a claim mapper with default configurations
func NewClaimMapper(groupRoleMap map[string]string, emailDomains map[string]string, defaultRole string) *ClaimMapper {
	if groupRoleMap == nil {
		groupRoleMap = make(map[string]string)
	}
	if emailDomains == nil {
		emailDomains = make(map[string]string)
	}
	if defaultRole == "" {
		defaultRole = "viewer" // Least-privilege default
	}

	return &ClaimMapper{
		GroupRoleMap: groupRoleMap,
		EmailDomains: emailDomains,
		DefaultRole:  defaultRole,
	}
}

// MapClaims translates IdP UserInfo to internal MappedUser
func (cm *ClaimMapper) MapClaims(userInfo *UserInfo) *MappedUser {
	mapped := &MappedUser{
		Username: userInfo.Email,
		Email:    userInfo.Email,
		Status:   "active",
		Role:     cm.DefaultRole,
		Groups:   []string{},
	}

	// Step 1: Check if user's email domain has a mapping
	if mapped.Email != "" {
		if domain, found := emailDomain(mapped.Email); found {
			if role, ok := cm.EmailDomains[domain]; ok {
				mapped.Role = role
				mapped.Reason = fmt.Sprintf("mapped by email domain %s → %s", domain, role)
				return mapped
			}
		}
	}

	// Step 2: Check if any external group maps to an internal role
	// Priority: highest-privilege matching group wins
	roleHierarchy := []string{"admin", "responder", "analyst", "viewer"}
	assignedRole := ""
	assignedFromGroup := ""

	for _, priority := range roleHierarchy {
		for _, externalGroup := range userInfo.Groups {
			if internalRole, ok := cm.GroupRoleMap[externalGroup]; ok && internalRole == priority {
				assignedRole = internalRole
				assignedFromGroup = externalGroup
				break
			}
		}
		if assignedRole != "" {
			break
		}
	}

	if assignedRole != "" {
		mapped.Role = assignedRole
		mapped.Groups = userInfo.Groups
		mapped.Reason = fmt.Sprintf("mapped from IdP group %s → %s", assignedFromGroup, assignedRole)
		return mapped
	}

	// Step 3: No mappings found, use default role
	mapped.Groups = userInfo.Groups
	mapped.Reason = fmt.Sprintf("no mapping found; using default role %s", cm.DefaultRole)

	return mapped
}

// emailDomain extracts domain from email address
func emailDomain(email string) (string, bool) {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return "@" + parts[1], true
	}
	return "", false
}

// ValidateUser checks if a user meets organizational policies
func (cm *ClaimMapper) ValidateUser(mapped *MappedUser) error {
	if mapped == nil {
		return fmt.Errorf("mapped user is nil")
	}
	if mapped.Email == "" {
		return fmt.Errorf("email claim required")
	}
	if mapped.Username == "" {
		return fmt.Errorf("username required")
	}
	if mapped.Role == "" {
		return fmt.Errorf("role assignment failed")
	}

	// Optional: Check if user's email domain is allowed
	// Example: block @competitor.com, @temp-mail.com
	if domain, found := emailDomain(mapped.Email); found {
		blockedDomains := map[string]bool{
			// "@temp-mail.com": true,
			// "@10minutemail.com": true,
		}
		if blockedDomains[domain] {
			return fmt.Errorf("email domain %s not allowed", domain)
		}
	}

	return nil
}

// CreatePlatformClaims builds internal JWT claims for a mapped user
// This output can be used to issue a platform token (JWT)
func (cm *ClaimMapper) CreatePlatformClaims(mapped *MappedUser, userID string, ttl int64) map[string]interface{} {
	return map[string]interface{}{
		"uid":      userID,
		"username": mapped.Username,
		"email":    mapped.Email,
		"role":     mapped.Role,
		"groups":   mapped.Groups,
		"exp":      ttl, // Token expiration time (unix timestamp)
		"iat":      Now(),
		"federation": map[string]interface{}{
			"provider":     "oidc",
			"validated_at": Now(),
		},
	}
}

// Now returns current time (for testing purposes, can be overridden)
var Now = func() int64 {
	return int64(time.Now().Unix())
}

// ProviderAdapter allows different providers (Keycloak, Azure AD, Auth0) to customize behavior
type ProviderAdapter interface {
	// ExtractGroups parses provider-specific group claims
	ExtractGroups(userInfo *UserInfo) []string

	// ValidateToken checks provider-specific token metadata
	ValidateToken(idToken string) error

	// Name returns provider identifier
	Name() string
}

// KeycloakAdapter for Keycloak-specific implementations
type KeycloakAdapter struct{}

func (ka *KeycloakAdapter) Name() string {
	return "keycloak"
}

func (ka *KeycloakAdapter) ExtractGroups(userInfo *UserInfo) []string {
	// Keycloak typically stores groups in "groups" or "resource_access" claim
	// "groups": ["/security-team", "/incident-response"]
	cleanGroups := []string{}
	for _, g := range userInfo.Groups {
		cleanGroups = append(cleanGroups, strings.TrimPrefix(g, "/"))
	}
	return cleanGroups
}

func (ka *KeycloakAdapter) ValidateToken(idToken string) error {
	// Additional Keycloak-specific token validation
	// (e.g., check issuer, algorithm, etc.)
	return nil
}

// AzureADAdapter for Azure AD / Entra ID implementations
type AzureADAdapter struct{}

func (aa *AzureADAdapter) Name() string {
	return "azuread"
}

func (aa *AzureADAdapter) ExtractGroups(userInfo *UserInfo) []string {
	// Azure AD typically stores groups in "groups" claim (GUIDs)
	// Mapping needs to handle GUID → human-readable names
	return userInfo.Groups
}

func (aa *AzureADAdapter) ValidateToken(idToken string) error {
	// Azure AD specific token validation
	return nil
}

// Auth0Adapter for Auth0 implementations
type Auth0Adapter struct{}

func (a0 *Auth0Adapter) Name() string {
	return "auth0"
}

func (a0 *Auth0Adapter) ExtractGroups(userInfo *UserInfo) []string {
	// Auth0 stores roles in "https://company.io/roles" custom claim
	// This example assumes groups are correctly populated
	return userInfo.Groups
}

func (a0 *Auth0Adapter) ValidateToken(idToken string) error {
	// Auth0-specific token validation
	return nil
}
