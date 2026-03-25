// CyberShield-X Access Control Service — Zero Trust + JWT Auth
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"

	"github.com/cybershield-x/access-control/internal/keymanagement"
	"github.com/cybershield-x/access-control/internal/oidc"
)

// ── Config ────────────────────────────────────

var (
	tokenTTL          = 15 * time.Minute
	refreshTTL        = 24 * time.Hour
	authIssuer        = env("ACCESS_CONTROL_ISSUER", "http://access-control:8002")
	tokenAudience     = env("JWT_AUDIENCE", "pariraksakah-api")
	passwordPepper    = env("PASSWORD_PEPPER", "pariraksakah-dev-pepper-change-in-prod")
	keysDir           = env("KEYS_DIR", "/etc/cybershield/keys")
	keyRotationPeriod = parseDuration(env("KEY_ROTATION_PERIOD", "7d"), 7*24*time.Hour)
	keyLifetime       = parseDuration(env("KEY_LIFETIME", "30d"), 30*24*time.Hour)
	keyStore          *keymanagement.KeyStore

	// OIDC Federation Configuration
	oidcEnabled      = env("OIDC_ENABLED", "false") == "true"
	oidcProviderURL  = env("OIDC_PROVIDER_URL", "")  // e.g., https://keycloak.example.com/realms/cybershield
	oidcClientID     = env("OIDC_CLIENT_ID", "")     // e.g., pariraksakah-client
	oidcClientSecret = env("OIDC_CLIENT_SECRET", "") // Must be set in environment (never in code)
	oidcRedirectURI  = env("OIDC_REDIRECT_URI", "http://localhost:8002/auth/federation/callback")
	oidcGroupRoleMap = parseGroupRoleMap(env("OIDC_GROUP_ROLE_MAP", "")) // JSON: {"security-team": "analyst", "admin-group": "admin"}

	// OIDC client
	oauth2Client *oidc.OAuth2Client
	claimMapper  *oidc.ClaimMapper

	// OIDC session state: state → {verifier, timestamp}
	oidcStateMu  sync.RWMutex
	oidcStateMap = map[string]*oidcSessionState{}
)

type oidcSessionState struct {
	Verifier  string
	Timestamp time.Time
}

func parseGroupRoleMap(input string) map[string]string {
	result := make(map[string]string)
	if input == "" {
		return result
	}
	if err := json.Unmarshal([]byte(input), &result); err != nil {
		log.Printf("warning: failed to parse OIDC_GROUP_ROLE_MAP: %v", err)
	}
	return result
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseDuration(s string, defaultDur time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultDur
	}
	return d
}

// ── Simple user store (demo — replace with DB) ─

type User struct {
	UserID   string
	Username string
	Role     string
	PassHash string // Argon2id encoded hash
}

var (
	defaultUsers = []struct {
		UserID   string
		Username string
		Role     string
		Password string
	}{
		{UserID: "usr-001", Username: "admin", Role: "admin", Password: "admin123"},
		{UserID: "usr-002", Username: "analyst", Role: "analyst", Password: "analyst123"},
		{UserID: "usr-003", Username: "viewer", Role: "viewer", Password: "viewer123"},
	}
	usersMu sync.RWMutex
	users   = map[string]*User{}
	// session store: token_id → expiry
	sessions   = map[string]time.Time{}
	sessionsMu sync.RWMutex
)

// SigningKey is managed by keymanagement.KeyStore

// ── JWT helpers ───────────────────────────────

type Claims struct {
	jwt.RegisteredClaims
	UserID   string `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

func issueToken(user *User, ttl time.Duration) (string, error) {
	jti := randomHex(16)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.UserID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			Issuer:    authIssuer,
			Audience:  []string{tokenAudience},
			ID:        jti,
		},
		UserID:   user.UserID,
		Username: user.Username,
		Role:     user.Role,
	}

	// Get the current signing key from persistent key store
	signingKey := keyStore.GetSigningKey()
	if signingKey == nil {
		return "", fmt.Errorf("signing key not available")
	}

	// Decode the private key for signing
	privateKey, err := signingKey.DecodePrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = signingKey.Kid
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	sessionsMu.Lock()
	sessions[jti] = time.Now().Add(ttl)
	sessionsMu.Unlock()
	return signed, nil
}

func validateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, tokenKeyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
		jwt.WithIssuer(authIssuer),
		jwt.WithAudience(tokenAudience),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid claims")
	}
	// Check session not revoked
	sessionsMu.RLock()
	exp, exists := sessions[claims.ID]
	sessionsMu.RUnlock()
	if !exists || time.Now().After(exp) {
		return nil, fmt.Errorf("session expired or revoked")
	}
	return claims, nil
}

func tokenKeyFunc(token *jwt.Token) (interface{}, error) {
	kidRaw, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("missing kid in token")
	}
	kid, ok := kidRaw.(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("invalid kid in token")
	}

	// Get all public keys from the key store (current and next)
	publicKeys := keyStore.GetPublicKeys()
	for _, key := range publicKeys {
		if key.Kid == kid {
			pubKey, err := key.DecodePublicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to decode public key: %w", err)
			}
			return pubKey, nil
		}
	}
	return nil, fmt.Errorf("unknown kid: %s", kid)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}

func initUsers() error {
	usersMu.Lock()
	defer usersMu.Unlock()
	for _, du := range defaultUsers {
		hash, err := hashPassword(du.Password)
		if err != nil {
			return err
		}
		users[du.Username] = &User{
			UserID:   du.UserID,
			Username: du.Username,
			Role:     du.Role,
			PassHash: hash,
		}
	}
	return nil
}

func hashPassword(password string) (string, error) {
	const (
		memory      = 64 * 1024
		iterations  = 3
		parallelism = 2
		saltLen     = 16
		keyLen      = 32
	)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password+passwordPepper), salt, iterations, memory, parallelism, keyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory,
		iterations,
		parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func verifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	// Expected format from hashPassword:
	// argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false
	}

	var memory, iterations, parallelism uint32
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	calc := argon2.IDKey(
		[]byte(password+passwordPepper),
		salt,
		iterations,
		memory,
		uint8(parallelism),
		uint32(len(decodedHash)),
	)
	return subtle.ConstantTimeCompare(decodedHash, calc) == 1
}

// initSigningKeys() replaced by keymanagement.KeyStore initialization

// generateSigningKey() replaced by keymanagement.KeyStore.generateSigningKey()

func buildJWK(kid string, pubKey *rsa.PublicKey) map[string]string {
	if pubKey == nil {
		return map[string]string{}
	}
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": jwt.SigningMethodRS256.Name,
		"use": "sig",
		"n":   n,
		"e":   e,
	}
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	publicKeys := keyStore.GetPublicKeys()
	keys := make([]map[string]string, 0, len(publicKeys))

	for _, key := range publicKeys {
		pubKey, err := key.DecodePublicKey()
		if err != nil {
			log.Printf("failed to decode public key %s: %v", key.Kid, err)
			continue
		}
		jwk := buildJWK(key.Kid, pubKey)
		keys = append(keys, jwk)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keys})
}

func publicKeyPEMHandler(w http.ResponseWriter, r *http.Request) {
	signingKey := keyStore.GetSigningKey()
	if signingKey == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "public key unavailable"})
		return
	}

	pk, err := signingKey.DecodePublicKey()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "public key decoding failed"})
		return
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "public key encoding failed"})
		return
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pemBytes)
}

// ── Redis session (optional) ──────────────────

func initRedis() *redis.Client {
	addr := env("REDIS_URL", "redis:6379")
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Printf("Redis unavailable (%v) — using in-memory sessions", err)
		return nil
	}
	log.Printf("Redis connected at %s", addr)
	return rdb
}

// ── OIDC/Federation Handlers ──────────────────

// federationAuthorizeHandler initiates OAuth2 Authorization Code flow with PKCE
func federationAuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled || oauth2Client == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "federation not enabled"})
		return
	}

	// Generate PKCE challenge and state
	verifier, challenge, err := oidc.PKCEChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate PKCE challenge"})
		return
	}

	state, err := oidc.State()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate state"})
		return
	}

	// Store state and verifier for callback validation (expires in 10 minutes)
	oidcStateMu.Lock()
	oidcStateMap[state] = &oidcSessionState{
		Verifier:  verifier,
		Timestamp: time.Now().Add(10 * time.Minute),
	}
	oidcStateMu.Unlock()

	// Generate authorization URL
	authURL, err := oauth2Client.AuthorizationURL(state, challenge)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to build authorization URL"})
		return
	}

	// Redirect to IdP
	http.Redirect(w, r, authURL, http.StatusFound)
}

// federationCallbackHandler processes OAuth2 authorization code callback
func federationCallbackHandler(w http.ResponseWriter, r *http.Request) {
	if !oidcEnabled || oauth2Client == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "federation not enabled"})
		return
	}

	// Parse callback query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "authorization denied",
			"error_description": r.URL.Query().Get("error_description"),
		})
		return
	}

	if code == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing code or state"})
		return
	}

	// Validate state and retrieve verifier
	oidcStateMu.RLock()
	sessionState, found := oidcStateMap[state]
	oidcStateMu.RUnlock()

	if !found {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid state"})
		return
	}

	// Check if state is expired
	if time.Now().After(sessionState.Timestamp) {
		oidcStateMu.Lock()
		delete(oidcStateMap, state)
		oidcStateMu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "state expired"})
		return
	}

	// Exchange code for token
	tokenResp, err := oauth2Client.ExchangeCodeForToken(code, sessionState.Verifier)
	if err != nil {
		log.Printf("token exchange failed: %v", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token exchange failed"})
		return
	}

	// Get user info from IdP
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	userInfo, err := oauth2Client.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		log.Printf("failed to get user info: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to retrieve user info"})
		return
	}

	// Map IdP claims to internal roles
	mapped := claimMapper.MapClaims(userInfo)

	// Validate user meets organizational policies
	if err := claimMapper.ValidateUser(mapped); err != nil {
		log.Printf("user validation failed for %s: %v", userInfo.Email, err)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":  "user validation failed",
			"reason": err.Error(),
		})
		return
	}

	// Create internal user from mapped claims
	internalUser := &User{
		UserID:   randomHex(16),
		Username: mapped.Username,
		Role:     mapped.Role,
		PassHash: "", // Federation users don't have password hashes
	}

	usersMu.Lock()
	users[internalUser.UserID] = internalUser
	usersMu.Unlock()

	// Issue platform token with mapped claims
	token, err := issueToken(internalUser, tokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token issuance failed"})
		return
	}

	// Clean up state
	oidcStateMu.Lock()
	delete(oidcStateMap, state)
	oidcStateMu.Unlock()

	// Return token to client
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(tokenTTL.Seconds()),
		"user": map[string]interface{}{
			"uid":      internalUser.UserID,
			"username": internalUser.Username,
			"email":    mapped.Email,
			"role":     internalUser.Role,
			"groups":   mapped.Groups,
		},
	})
}

// ── Handlers ──────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// POST /auth/login  { "username": "admin", "password": "admin123" }
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	usersMu.RLock()
	user, ok := users[req.Username]
	usersMu.RUnlock()
	if !ok || !verifyPassword(req.Password, user.PassHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	accessToken, err := issueToken(user, tokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
		return
	}
	refreshToken, _ := issueToken(user, refreshTTL)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    int(tokenTTL.Seconds()),
		"user": map[string]string{
			"user_id":  user.UserID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

// POST /auth/verify  or  GET /auth/verify  (Authorization: Bearer <token>)
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}
	claims, err := validateToken(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":    true,
		"user_id":  claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
		"expires":  claims.ExpiresAt,
	})
}

// POST /auth/logout  (revokes current token)
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing token"})
		return
	}
	claims, err := validateToken(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	sessionsMu.Lock()
	delete(sessions, claims.ID)
	sessionsMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// GET /auth/users  (admin only — lists users without passwords)
func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	usersMu.RLock()
	defer usersMu.RUnlock()
	result := make([]map[string]string, 0, len(users))
	for _, u := range users {
		result = append(result, map[string]string{
			"user_id":  u.UserID,
			"username": u.Username,
			"role":     u.Role,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": result, "total": len(result)})
}

// GET /auth/.well-known/openid-configuration
func openIDConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := authIssuer
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":                 base,
			"authorization_endpoint": base + "/auth/authorize",
			"token_endpoint":         base + "/auth/token",
			"userinfo_endpoint":      base + "/auth/userinfo",
			"jwks_uri":               base + "/auth/.well-known/jwks.json",
		})
	}
}

// ── Main ──────────────────────────────────────

func main() {
	port := env("ACCESS_CONTROL_PORT", "8002")
	if err := initUsers(); err != nil {
		log.Fatalf("failed to initialize users: %v", err)
	}
	var err error
	keyStore, err = keymanagement.NewKeyStore(keysDir, keyRotationPeriod, keyLifetime)
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}
	keyStore.StartRotationScheduler()
	initRedis()

	// Initialize OIDC/Federation if enabled
	if oidcEnabled {
		if oidcProviderURL == "" || oidcClientID == "" || oidcClientSecret == "" {
			log.Fatalf("OIDC enabled but missing configuration: provider_url, client_id, or client_secret")
		}
		cfg := &oidc.ProviderConfig{
			ProviderURL:  oidcProviderURL,
			ClientID:     oidcClientID,
			ClientSecret: oidcClientSecret,
			RedirectURI:  oidcRedirectURI,
			Scopes:       []string{"openid", "profile", "email", "groups"},
		}
		oc, err := oidc.NewOAuth2Client(cfg)
		if err != nil {
			log.Fatalf("failed to initialize OIDC client: %v", err)
		}
		oauth2Client = oc
		claimMapper = oidc.NewClaimMapper(oidcGroupRoleMap, nil, "viewer")
		log.Printf("OIDC/Federation enabled for provider: %s", oidcProviderURL)
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if req.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/health", func(w http.ResponseWriter, req *http.Request) {
		sessionsMu.RLock()
		activeSessions := len(sessions)
		sessionsMu.RUnlock()
		var kid, keyStatus string
		if signingKey := keyStore.GetSigningKey(); signingKey != nil {
			kid = signingKey.Kid
			keyStatus = signingKey.Status
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":          "healthy",
			"service":         "access-control",
			"version":         "2.1.0",
			"active_sessions": activeSessions,
			"signing_kid":     kid,
			"key_status":      keyStatus,
		})
	})
	r.Handle("/metrics", promhttp.Handler())

	r.Post("/auth/login", loginHandler)
	r.Post("/auth/verify", verifyHandler)
	r.Get("/auth/verify", verifyHandler)
	r.Post("/auth/logout", logoutHandler)
	r.Get("/auth/users", listUsersHandler)
	r.Get("/auth/.well-known/openid-configuration", openIDConfigHandler())
	r.Get("/auth/.well-known/jwks.json", jwksHandler)
	r.Get("/auth/public-key.pem", publicKeyPEMHandler)

	// OIDC/Federation routes
	if oidcEnabled {
		r.Get("/auth/federation/authorize", federationAuthorizeHandler)
		r.Get("/auth/federation/callback", federationCallbackHandler)
	}

	// Legacy stubs — now functional
	r.Post("/auth/authorize", func(w http.ResponseWriter, req *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"message": "Use POST /auth/login for direct token issuance",
		})
	})
	r.Post("/auth/token", func(w http.ResponseWriter, req *http.Request) {
		loginHandler(w, req) // delegate to login
	})

	log.Printf("Access Control Service (Zero-Trust + JWT + OIDC Federation) starting on :%s", port)
	log.Printf("Default users initialized: admin, analyst, viewer")
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
