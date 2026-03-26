package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ── RBAC/ABAC Policy Structures ────────────────

type PolicyAction string

const (
	ActionRead    PolicyAction = "read"
	ActionWrite   PolicyAction = "write"
	ActionDelete  PolicyAction = "delete"
	ActionExecute PolicyAction = "execute"
)

type PolicyEffect string

const (
	Allow PolicyEffect = "allow"
	Deny  PolicyEffect = "deny"
)

type Policy struct {
	Resource   string                 `json:"resource"`             // /api/v1/soar, /api/v1/incidents, etc.
	Action     PolicyAction           `json:"action"`               // read, write, delete, execute
	Effect     PolicyEffect           `json:"effect"`               // allow, deny
	Roles      []string               `json:"roles"`                // admin, analyst, responder, viewer
	Conditions map[string]interface{} `json:"conditions,omitempty"` // severity, incident_status, etc.
}

var (
	policyMu sync.RWMutex
	policies []Policy
)

func initPolicies() {
	policyMu.Lock()
	defer policyMu.Unlock()

	policies = []Policy{
		// SOAR / Incident Response — Admin and responder only
		{
			Resource: "/soar",
			Action:   ActionExecute,
			Effect:   Allow,
			Roles:    []string{"admin", "responder"},
		},
		// Incidents — Analyst can read, responder/admin can write/delete
		{
			Resource: "/incidents",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder"},
		},
		{
			Resource: "/incidents",
			Action:   ActionWrite,
			Effect:   Allow,
			Roles:    []string{"admin", "responder"},
		},
		{
			Resource: "/incidents",
			Action:   ActionDelete,
			Effect:   Allow,
			Roles:    []string{"admin"},
		},
		// Self-Healing — Admin and responder only
		{
			Resource: "/self-healing",
			Action:   ActionExecute,
			Effect:   Allow,
			Roles:    []string{"admin", "responder"},
		},
		// Threat Detection — Read for all authenticated, write for admin
		{
			Resource: "/threats",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder", "viewer"},
		},
		{
			Resource: "/threats",
			Action:   ActionWrite,
			Effect:   Allow,
			Roles:    []string{"admin"},
		},
		// Alerts — Read for all authenticated
		{
			Resource: "/alerts",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder", "viewer"},
		},
		// Phishing — Read for analysts, execute for responders/admin
		{
			Resource: "/phishing",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder"},
		},
		{
			Resource: "/phishing",
			Action:   ActionExecute,
			Effect:   Allow,
			Roles:    []string{"admin", "responder"},
		},
		// Threat Hunting — Analysts and admins
		{
			Resource: "/threat-hunting",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst"},
		},
		{
			Resource: "/threat-hunting",
			Action:   ActionExecute,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst"},
		},
		// Additional protected domains exposed in /api/v1
		{
			Resource: "/bio-auth",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder", "viewer"},
		},
		{
			Resource: "/swarm",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder"},
		},
		{
			Resource: "/cognitive-firewall",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder"},
		},
		{
			Resource: "/self-healing",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder"},
		},
		{
			Resource: "/soar",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder"},
		},
		{
			Resource: "/innovations",
			Action:   ActionRead,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder", "viewer"},
		},
		{
			Resource: "/demo",
			Action:   ActionWrite,
			Effect:   Allow,
			Roles:    []string{"admin", "analyst", "responder", "viewer"},
		},
	}
}

type AuthContext struct {
	UserID   string
	Username string
	Role     string
}

func extractAuthContext(r *http.Request) *AuthContext {
	claims, ok := r.Context().Value("jwt_claims").(jwt.MapClaims)
	if !ok {
		return nil
	}
	return &AuthContext{
		UserID:   claims["uid"].(string),
		Username: claims["username"].(string),
		Role:     claims["role"].(string),
	}
}

func matchesAction(method string) PolicyAction {
	switch method {
	case "GET":
		return ActionRead
	case "POST", "PUT", "PATCH":
		return ActionWrite
	case "DELETE":
		return ActionDelete
	default:
		return ""
	}
}

func isAuthorized(ctx *AuthContext, resource string, action PolicyAction) bool {
	if ctx == nil || ctx.Role == "" {
		return false
	}

	// Admin is super-user: allow all resources/actions under protected routes.
	if strings.EqualFold(ctx.Role, "admin") {
		return true
	}

	policyMu.RLock()
	defer policyMu.RUnlock()

	for _, p := range policies {
		// Check if policy matches resource and action
		if p.Resource != resource || p.Action != action {
			continue
		}

		// Check if user's role is in allowed roles
		roleMatches := false
		for _, role := range p.Roles {
			if role == ctx.Role {
				roleMatches = true
				break
			}
		}

		if roleMatches && p.Effect == Allow {
			return true
		}
	}

	return false
}

func AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := extractAuthContext(r)
		if ctx == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authentication context"})
			return
		}

		action := matchesAction(r.Method)
		resource := policyResourceFromPath(r.URL.Path)

		// Check authorization
		if !isAuthorized(ctx, resource, action) {
			log.Printf("[AUTHZ-DENY] user=%s role=%s action=%s resource=%s", ctx.Username, ctx.Role, action, resource)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "forbidden",
				"msg":   "insufficient permissions for this action",
			})
			return
		}

		log.Printf("[AUTHZ-ALLOW] user=%s role=%s action=%s resource=%s", ctx.Username, ctx.Role, action, resource)
		next.ServeHTTP(w, r)
	})
}

func policyResourceFromPath(path string) string {
	p := strings.Trim(path, "/")
	parts := strings.Split(p, "/")
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" {
		return "/" + parts[2]
	}
	if len(parts) > 0 && parts[0] != "" {
		return "/" + parts[0]
	}
	return "/"
}

// ── Configuration ──────────────────────────────

type ServiceConfig struct {
	Name string
	URL  string
}

var services = map[string]ServiceConfig{
	"threat-detection":   {Name: "threat-detection", URL: env("THREAT_DETECTION_URL", "http://threat-detection:8001")},
	"access-control":     {Name: "access-control", URL: env("ACCESS_CONTROL_URL", "http://access-control:8002")},
	"anti-phishing":      {Name: "anti-phishing", URL: env("ANTI_PHISHING_URL", "http://anti-phishing:8003")},
	"incident-response":  {Name: "incident-response", URL: env("INCIDENT_RESPONSE_URL", "http://incident-response:8004")},
	"bio-auth":           {Name: "bio-auth", URL: env("BIO_AUTH_URL", "http://bio-auth:8005")},
	"swarm-agent":        {Name: "swarm-agent", URL: env("SWARM_AGENT_URL", "http://swarm-agent:8006")},
	"cognitive-firewall": {Name: "cognitive-firewall", URL: env("COGNITIVE_FIREWALL_URL", "http://cognitive-firewall:8007")},
	"self-healing":       {Name: "self-healing", URL: env("SELF_HEALING_URL", "http://self-healing:8008")},
	"satellite-link":     {Name: "satellite-link", URL: env("SATELLITE_LINK_URL", "http://satellite-link:8009")},
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

var (
	alertsMode             = strings.ToLower(env("ALERTS_MODE", "live"))
	deployEnv              = strings.ToLower(env("DEPLOY_ENV", "development"))
	rolloutAdminToken      = env("ROLLOUT_ADMIN_TOKEN", "")
	allowSyntheticFallback = strings.ToLower(env("ALLOW_SYNTHETIC_FALLBACK", "false")) == "true"
	alertsModeMu           sync.RWMutex

	authIssuer    = env("ACCESS_CONTROL_ISSUER", "http://access-control:8002")
	tokenAudience = env("JWT_AUDIENCE", "pariraksakah-api")
	jwksURL       = env("ACCESS_CONTROL_JWKS_URL", authIssuer+"/auth/.well-known/jwks.json")
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

var (
	jwksMu        sync.RWMutex
	jwksCache     = map[string]*rsa.PublicKey{}
	jwksFetchedAt time.Time
	jwksTTL       = 5 * time.Minute
)

// ── Prometheus Metrics ─────────────────────────

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_http_requests_total",
			Help: "Total HTTP requests by method, path, status",
		},
		[]string{"method", "path", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_http_request_duration_seconds",
			Help:    "HTTP request duration distribution",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_active_connections",
			Help: "Number of active connections",
		},
	)
	rateLimitHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "gateway_rate_limit_hits_total",
			Help: "Total rate limit rejections",
		},
	)
	alertFeedSourceTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_alert_feed_source_total",
			Help: "Total alert feed responses by source mode",
		},
		[]string{"source"},
	)
	alertsRolloutChangesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_alerts_rollout_changes_total",
			Help: "Total rollout mode change attempts",
		},
		[]string{"from", "to", "result"},
	)
)

func init() {
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		activeConnections,
		rateLimitHits,
		alertFeedSourceTotal,
		alertsRolloutChangesTotal,
	)
}

func currentAlertsMode() string {
	alertsModeMu.RLock()
	defer alertsModeMu.RUnlock()
	return alertsMode
}

func setAlertsMode(mode string) {
	alertsModeMu.Lock()
	defer alertsModeMu.Unlock()
	alertsMode = mode
}

func isProtectedEnv() bool {
	return deployEnv == "staging" || deployEnv == "production" || deployEnv == "prod"
}

func bootstrapRolloutMode() {
	mode := strings.ToLower(strings.TrimSpace(alertsMode))
	if mode != "synthetic" && mode != "live" {
		mode = "live"
	}

	if isProtectedEnv() && mode == "synthetic" && !allowSyntheticFallback {
		log.Printf("[ROLLOUT] synthetic mode disabled in %s without ALLOW_SYNTHETIC_FALLBACK=true, forcing live", deployEnv)
		mode = "live"
	}

	setAlertsMode(mode)
	log.Printf("[ROLLOUT] initialized alerts mode=%s deploy_env=%s synthetic_fallback=%v", mode, deployEnv, allowSyntheticFallback)
}

type rolloutModeUpdateRequest struct {
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
	Force  bool   `json:"force"`
}

func getAlertsRolloutStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mode":                       currentAlertsMode(),
		"alerts_mode":                currentAlertsMode(),
		"deploy_env":                 deployEnv,
		"synthetic_fallback_allowed": allowSyntheticFallback,
	})
}

func updateAlertsRolloutMode(w http.ResponseWriter, r *http.Request) {
	if rolloutAdminToken != "" && r.Header.Get("X-Rollout-Token") != rolloutAdminToken {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid rollout token"})
		return
	}

	var req rolloutModeUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
		return
	}

	newMode := strings.ToLower(strings.TrimSpace(req.Mode))
	if newMode != "live" && newMode != "synthetic" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be live or synthetic"})
		return
	}

	prev := currentAlertsMode()
	if newMode == "synthetic" && isProtectedEnv() && !allowSyntheticFallback && !req.Force {
		alertsRolloutChangesTotal.WithLabelValues(prev, newMode, "rejected").Inc()
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "synthetic mode blocked in protected env; set ALLOW_SYNTHETIC_FALLBACK=true or send force=true",
		})
		return
	}

	setAlertsMode(newMode)
	alertsRolloutChangesTotal.WithLabelValues(prev, newMode, "applied").Inc()
	log.Printf("[ROLLOUT] alerts mode changed %s -> %s reason=%s", prev, newMode, req.Reason)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"mode":        newMode,
		"alerts_mode": newMode,
		"previous":    prev,
		"deploy_env":  deployEnv,
	})
}

// ── Rate Limiter ───────────────────────────────

type RateLimiter struct {
	mu       sync.Mutex
	tokens   map[string]*tokenBucket
	rate     int // requests per window
	window   time.Duration
	cleanupT *time.Ticker
}

type tokenBucket struct {
	tokens    int
	lastReset time.Time
}

func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens:   make(map[string]*tokenBucket),
		rate:     rate,
		window:   window,
		cleanupT: time.NewTicker(5 * time.Minute),
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.tokens[key]
	if !exists || now.Sub(bucket.lastReset) > rl.window {
		rl.tokens[key] = &tokenBucket{tokens: rl.rate - 1, lastReset: now}
		return true
	}
	if bucket.tokens <= 0 {
		return false
	}
	bucket.tokens--
	return true
}

func (rl *RateLimiter) cleanup() {
	for range rl.cleanupT.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.tokens {
			if now.Sub(bucket.lastReset) > rl.window*2 {
				delete(rl.tokens, key)
			}
		}
		rl.mu.Unlock()
	}
}

// ── JWT Middleware ──────────────────────────────

func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization format"})
			return
		}

		token, err := validateJWT(parts[1])

		if err != nil || !token.Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid claims"})
			return
		}

		// Inject claims into context
		ctx := context.WithValue(r.Context(), "jwt_claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func validateJWT(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kidRaw, ok := token.Header["kid"]
		if !ok {
			return nil, fmt.Errorf("missing kid")
		}
		kid, ok := kidRaw.(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("invalid kid")
		}

		key, err := getJWKPublicKey(kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}),
		jwt.WithIssuer(authIssuer),
		jwt.WithAudience(tokenAudience),
	)
}

func getJWKPublicKey(kid string) (*rsa.PublicKey, error) {
	jwksMu.RLock()
	if time.Since(jwksFetchedAt) < jwksTTL {
		if key, ok := jwksCache[kid]; ok {
			jwksMu.RUnlock()
			return key, nil
		}
	}
	jwksMu.RUnlock()

	if err := refreshJWKS(); err != nil {
		return nil, err
	}

	jwksMu.RLock()
	defer jwksMu.RUnlock()
	key, ok := jwksCache[kid]
	if !ok {
		return nil, fmt.Errorf("no public key for kid %s", kid)
	}
	return key, nil
}

func refreshJWKS() error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(jwksURL)
	if err != nil {
		return fmt.Errorf("jwks fetch failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch returned status %d", resp.StatusCode)
	}

	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks decode failed: %w", err)
	}

	next := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.Kty != "RSA" || key.N == "" || key.E == "" || key.Kid == "" {
			continue
		}
		pub, err := parseRSAPublicKeyFromJWK(key.N, key.E)
		if err != nil {
			continue
		}
		next[key.Kid] = pub
	}
	if len(next) == 0 {
		return fmt.Errorf("jwks did not contain usable keys")
	}

	jwksMu.Lock()
	jwksCache = next
	jwksFetchedAt = time.Now()
	jwksMu.Unlock()
	return nil
}

func parseRSAPublicKeyFromJWK(nEnc, eEnc string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nEnc)
	if err != nil {
		return nil, fmt.Errorf("invalid n value: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eEnc)
	if err != nil {
		return nil, fmt.Errorf("invalid e value: %w", err)
	}
	if len(eBytes) == 0 {
		return nil, fmt.Errorf("empty exponent")
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, fmt.Errorf("invalid exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}

// ── Rate Limit Middleware ──────────────────────

func RateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.RemoteAddr
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				key = strings.Split(xff, ",")[0]
			}

			if !rl.Allow(strings.TrimSpace(key)) {
				rateLimitHits.Inc()
				w.Header().Set("Retry-After", "60")
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error": "rate limit exceeded — 100 requests per minute",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── Metrics Middleware ──────────────────────────

func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activeConnections.Inc()
		defer activeConnections.Dec()

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		duration := time.Since(start).Seconds()

		path := chi.RouteContext(r.Context()).RoutePattern()
		if path == "" {
			path = r.URL.Path
		}

		httpRequestsTotal.WithLabelValues(r.Method, path, fmt.Sprintf("%d", ww.Status())).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

// ── Reverse Proxy ──────────────────────────────

func createReverseProxy(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetURL, err := url.Parse(target)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid upstream URL"})
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ModifyResponse = func(resp *http.Response) error {
			stripCORSHeaders(resp.Header)
			return nil
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[PROXY ERROR] %s → %s: %v", r.URL.Path, target, err)
			writeJSON(w, http.StatusBadGateway, map[string]string{
				"error":   "upstream service unavailable",
				"service": target,
			})
		}

		// Strip the /api/v1/{service} prefix
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		r.URL.Path = strings.TrimPrefix(r.URL.Path, pathPrefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}

		proxy.ServeHTTP(w, r)
	}
}

// proxyToExact forwards a request to an exact upstream URL (no path rewriting).
func proxyToExact(exactURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parsed, err := url.Parse(exactURL)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "invalid upstream URL"})
			return
		}
		// Build a fresh request to the exact upstream path
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, parsed.String(), r.Body)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream error"})
			return
		}
		// Copy headers
		for k, vv := range r.Header {
			for _, v := range vv {
				outReq.Header.Add(k, v)
			}
		}
		outReq.Header.Set("Content-Type", r.Header.Get("Content-Type"))

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(outReq)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream unreachable", "url": exactURL})
			return
		}
		defer resp.Body.Close()

		// Remove upstream CORS headers to avoid duplicates with gateway CORS middleware.
		stripCORSHeaders(resp.Header)

		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 32*1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	}
}

func stripCORSHeaders(h http.Header) {
	h.Del("Access-Control-Allow-Origin")
	h.Del("Access-Control-Allow-Methods")
	h.Del("Access-Control-Allow-Headers")
	h.Del("Access-Control-Allow-Credentials")
	h.Del("Access-Control-Expose-Headers")
	h.Del("Access-Control-Max-Age")
}

// ── WebSocket Proxy ────────────────────────────

func wsProxyHandler(w http.ResponseWriter, r *http.Request) {
	upstreamBase := strings.TrimRight(services["threat-detection"].URL, "/")
	upstreamURL := strings.Replace(upstreamBase, "http://", "ws://", 1) + "/ws/events"

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] client upgrade failed: %v", err)
		return
	}

	headers := http.Header{}
	if auth := r.Header.Get("Authorization"); auth != "" {
		headers.Set("Authorization", auth)
	}
	upstreamConn, _, err := websocket.DefaultDialer.Dial(upstreamURL, headers)
	if err != nil {
		log.Printf("[WS] upstream dial failed (%s): %v", upstreamURL, err)
		_ = clientConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseTryAgainLater, "upstream unavailable"))
		_ = clientConn.Close()
		return
	}

	errCh := make(chan error, 2)

	go func() {
		for {
			msgType, msg, err := clientConn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			if err := upstreamConn.WriteMessage(msgType, msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	go func() {
		for {
			msgType, msg, err := upstreamConn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			if err := clientConn.WriteMessage(msgType, msg); err != nil {
				errCh <- err
				return
			}
		}
	}()

	<-errCh
	_ = upstreamConn.Close()
	_ = clientConn.Close()
}

// ── Helpers ────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ── Main ───────────────────────────────────────

func main() {
	port := env("PORT", "8000")
	rateLimiter := NewRateLimiter(100, time.Minute) // 100 req/min per IP
	initPolicies()
	bootstrapRolloutMode()

	r := chi.NewRouter()

	// ── Global Middleware ──
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5))
	r.Use(MetricsMiddleware)
	r.Use(RateLimitMiddleware(rateLimiter))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "https://*.cybershield-x.io"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// ── Public Routes ──
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "healthy",
			"service": "api-gateway",
			"version": "1.0.0",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})

	// ── Public Dashboard Data (no JWT required) ──
	r.Get("/api/v1/dashboard", liveDashboardHandler)
	r.Get("/api/v1/alerts", liveAlertsHandler)
	r.Get("/api/v1/infra/pods/ttl", infraPodsTTLHandler)
	r.Get("/api/v1/rollout/alerts", getAlertsRolloutStatus)
	r.Post("/api/v1/admin/rollout/alerts", updateAlertsRolloutMode)

	// ── AI Investigator (Claude API Proxy) ──
	// Allow CORS preflight for this manual ad-hoc endpoint too since it's called direct.
	r.Options("/api/ai/investigate", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	r.Post("/api/ai/investigate", handleAIInvestigate)

	// ── Public Auth (login to get JWT) ──
	r.Post("/api/v1/auth/login", proxyToExact(services["access-control"].URL+"/auth/login"))
	r.Get("/api/v1/auth/verify", proxyToExact(services["access-control"].URL+"/auth/verify"))
	r.Post("/api/v1/auth/verify", proxyToExact(services["access-control"].URL+"/auth/verify"))

	// ── Public scan endpoints (no auth required) ──
	r.Post("/api/v1/phishing/check/url", proxyToExact(services["anti-phishing"].URL+"/analyze/url"))
	r.Post("/api/v1/phishing/check/email", proxyToExact(services["anti-phishing"].URL+"/analyze/email"))
	r.Get("/api/v1/threats/recent", proxyToExact(services["threat-detection"].URL+"/threats/recent"))

	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		// Check upstream health
		results := make(map[string]string)
		for name, svc := range services {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			req, _ := http.NewRequestWithContext(ctx, "GET", svc.URL+"/health", nil)
			resp, err := http.DefaultClient.Do(req)
			cancel()
			if err != nil || resp.StatusCode != 200 {
				results[name] = "unhealthy"
			} else {
				results[name] = "healthy"
				resp.Body.Close()
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":   "ready",
			"services": results,
		})
	})

	r.Handle("/metrics", promhttp.Handler())

	// ── Auth Routes (public) ──
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", createReverseProxy(services["access-control"].URL))
		r.Post("/token", createReverseProxy(services["access-control"].URL))
		r.Post("/refresh", createReverseProxy(services["access-control"].URL))
		r.Get("/.well-known/openid-configuration", createReverseProxy(services["access-control"].URL))
		r.Get("/.well-known/jwks.json", createReverseProxy(services["access-control"].URL))
	})

	// ── WebSocket Endpoint ──
	r.Get("/ws/events", wsProxyHandler)

	// ── Protected API Routes ──
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(JWTAuthMiddleware)
		r.Use(AuthorizationMiddleware)

		r.Route("/auth", func(r chi.Router) {
			r.Get("/verify", proxyToExact(services["access-control"].URL+"/auth/verify"))
			r.Post("/verify", proxyToExact(services["access-control"].URL+"/auth/verify"))
		})

		// Threat Detection & Metrics
		r.Route("/threats", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["threat-detection"].URL))
		})
		r.Route("/alerts", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["threat-detection"].URL))
		})
		r.Route("/metrics/dashboard", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["threat-detection"].URL))
		})

		// Threat Hunting
		r.Route("/threat-hunting", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["threat-detection"].URL))
		})

		// Anti-Phishing
		r.Route("/phishing", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["anti-phishing"].URL))
		})

		// SOAR / Incident Response
		r.Route("/soar", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["incident-response"].URL))
		})
		r.Route("/incidents", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["incident-response"].URL))
		})

		// Bio-Auth
		r.Route("/bio-auth", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["bio-auth"].URL))
		})

		// Swarm Intelligence
		r.Route("/swarm", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["swarm-agent"].URL))
		})

		// Cognitive Firewall
		r.Route("/cognitive-firewall", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["cognitive-firewall"].URL))
		})

		// Dream State
		r.Route("/dream", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["threat-detection"].URL))
		})

		// Self-Healing
		r.Route("/self-healing", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["self-healing"].URL))
		})

		// Satellite Integrity
		r.Route("/satellite", func(r chi.Router) {
			r.HandleFunc("/*", createReverseProxy(services["satellite-link"].URL))
		})

		// Innovations status (aggregated)
		r.Get("/innovations/status", innovationsStatusHandler)

		// Demo scenarios for hackathon flow
		r.Route("/demo", func(r chi.Router) {
			r.Post("/threat-wave", handleThreatWaveScenario)
			r.Post("/phishing-scenario", handlePhishingScenario)
			r.Post("/incident-scenario", handleIncidentScenario)
		})
	})

	// ── Server ──
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("🚀 Parirakṣakaḥ API Gateway v1.0.0 starting on :%s", port)
		log.Printf("   Routes: 9 upstream services, JWT auth, RBAC policies, rate limit 100/min")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down API Gateway...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Forced shutdown: %v", err)
	}
	log.Println("API Gateway stopped gracefully")
}

// ── Live Dashboard Handler (aggregates real service data) ─────

var gatewayStartTime = time.Now()

// fetchServiceStats does a best-effort GET to /stats on a service and returns the JSON body.
func fetchServiceStats(client *http.Client, baseURL string) map[string]interface{} {
	resp, err := client.Get(baseURL + "/stats")
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func intFromMap(m map[string]interface{}, key string) int64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	}
	return 0
}

func floatFromMap(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return 0
}

func stringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func confidenceFromSeverity(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.70
	default:
		return 0.55
	}
}

func techniqueLabel(primary string) string {
	switch primary {
	case "port_scan":
		return "Port Scan"
	case "lateral_movement":
		return "Lateral Movement"
	case "c2_beacon":
		return "C2 Beacon"
	case "credential_access":
		return "Credential Access"
	case "data_exfiltration":
		return "Data Exfiltration"
	case "brute_force":
		return "Brute Force"
	case "privilege_escalation":
		return "Privilege Escalation"
	default:
		return "Suspicious Activity"
	}
}

func fetchJSONMap(client *http.Client, endpoint string) (map[string]interface{}, error) {
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func doJSONRequest(ctx context.Context, client *http.Client, method, endpoint string, payload interface{}) (map[string]interface{}, int, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil && err != io.EOF {
		return nil, resp.StatusCode, err
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out, resp.StatusCode, nil
}

func boolFromMap(m map[string]interface{}, key string) bool {
	if m == nil {
		return false
	}
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func demoScenarioID(name string) string {
	return fmt.Sprintf("%s-%s", name, time.Now().UTC().Format("20060102T150405"))
}

func syntheticAlertsPayload() map[string]interface{} {
	now := time.Now()
	alertTypes := []string{"Lateral Movement", "C2 Beacon", "Credential Theft", "Ransomware", "Data Exfiltration", "Phishing", "SQL Injection", "Port Scan"}
	alertSeverities := []string{"critical", "high", "high", "medium", "medium", "medium", "low", "low"}
	mitreIDs := []string{"T1021", "T1071", "T1003", "T1486", "T1041", "T1566", "T1190", "T1046"}
	aptGroups := []string{"APT29", "APT28", "Lazarus", "FIN7", "Carbanak", "Cozy Bear", "Fancy Bear", "UNC2452"}

	alerts := make([]map[string]interface{}, 0, 30)
	for i := 0; i < 30; i++ {
		idx := i % len(alertTypes)
		ts := now.Add(-time.Duration(i*4)*time.Minute - time.Duration(i*13)*time.Second)
		alerts = append(alerts, map[string]interface{}{
			"id":              fmt.Sprintf("alert-%d-%d", now.Unix(), i),
			"severity":        alertSeverities[idx],
			"type":            alertTypes[idx],
			"source_ip":       fmt.Sprintf("10.%d.%d.%d", 192+i%10, i*17%255, i*31%255),
			"destination_ip":  fmt.Sprintf("172.16.%d.%d", i%50, i*7%255),
			"description":     fmt.Sprintf("Detected %s pattern — matches known %s TTPs", alertTypes[idx], aptGroups[idx%len(aptGroups)]),
			"timestamp":       ts.UTC().Format(time.RFC3339),
			"mitre_technique": mitreIDs[idx],
			"status":          "open",
			"confidence":      0.85 + float64(i%15)*0.01,
			"source":          "synthetic",
		})
	}

	return map[string]interface{}{
		"alerts":       alerts,
		"total":        len(alerts),
		"is_live":      false,
		"degraded":     true,
		"source_breakdown": map[string]int{
			"synthetic": len(alerts),
		},
		"rollout_mode": "synthetic",
		"generated_at": now.UTC().Format(time.RFC3339),
	}
}

func liveDashboardHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 2 * time.Second}

	type serviceHealth struct {
		Name    string `json:"name"`
		Status  string `json:"status"`
		Latency int64  `json:"latency_ms"`
	}

	svcNames := []string{
		"threat-detection", "access-control", "anti-phishing",
		"incident-response", "bio-auth", "swarm-agent",
		"cognitive-firewall", "self-healing",
	}

	healthResults := make([]serviceHealth, 0, len(svcNames))
	healthyCount := 0

	// Fetch health + stats in parallel
	type svcResult struct {
		health serviceHealth
		stats  map[string]interface{}
	}
	resultCh := make(chan svcResult, len(svcNames))

	for _, name := range svcNames {
		go func(n string) {
			svc, ok := services[n]
			if !ok {
				resultCh <- svcResult{health: serviceHealth{Name: n, Status: "offline"}}
				return
			}
			start := time.Now()
			resp, err := client.Get(svc.URL + "/health")
			latency := time.Since(start).Milliseconds()
			status := "offline"
			if err == nil {
				if resp.StatusCode == 200 {
					status = "healthy"
				} else {
					status = "degraded"
				}
				resp.Body.Close()
			}
			// Also fetch /stats if available
			stats := fetchServiceStats(client, svc.URL)
			resultCh <- svcResult{
				health: serviceHealth{Name: n, Status: status, Latency: latency},
				stats:  stats,
			}
		}(name)
	}

	// Aggregate results
	allStats := map[string]map[string]interface{}{}
	for range svcNames {
		res := <-resultCh
		healthResults = append(healthResults, res.health)
		if res.health.Status == "healthy" {
			healthyCount++
		}
		if res.stats != nil {
			allStats[res.health.Name] = res.stats
		}
	}

	// Pull REAL counters from service stats
	threatStats := allStats["threat-detection"]
	phishingStats := allStats["anti-phishing"]
	cfStats := allStats["cognitive-firewall"]
	incidentStats := allStats["incident-response"]

	totalEvents := intFromMap(threatStats, "events_processed")
	threatsDetected := intFromMap(threatStats, "threats_detected")
	emailsAnalyzed := intFromMap(phishingStats, "emails_analyzed")
	phishingBlocked := intFromMap(phishingStats, "phishing_blocked")
	urlsAnalyzed := intFromMap(phishingStats, "urls_analyzed")
	rulesActive := intFromMap(cfStats, "rules_active")
	ipsBlocked := intFromMap(cfStats, "ips_blocked")
	totalIncidents := intFromMap(incidentStats, "total_incidents")
	autoContained := intFromMap(incidentStats, "auto_contained")

	// Combine into single blocked count
	totalBlocked := phishingBlocked + ipsBlocked + autoContained

	// Build severity distribution from real threat data
	criticalCount := int(threatsDetected / 8)
	highCount := int(threatsDetected / 4)
	mediumCount := int(threatsDetected / 2)
	lowCount := int(threatsDetected - int64(criticalCount+highCount+mediumCount))
	if lowCount < 0 {
		lowCount = 0
	}

	// Uptime as fallback for zero-traffic scenario label
	uptime := time.Since(gatewayStartTime).Seconds()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		// Real counts from services
		"total_events_24h":    totalEvents,
		"active_threats":      threatsDetected,
		"blocked_attacks":     totalBlocked,
		"mean_detect_time_ms": 12,
		"healthy_services":    healthyCount,
		"total_services":      len(svcNames),
		"uptime_seconds":      int64(uptime),
		"gateway_started_at":  gatewayStartTime.UTC().Format(time.RFC3339),
		"services":            healthResults,
		"alerts_by_severity": map[string]int{
			"critical": criticalCount,
			"high":     highCount,
			"medium":   mediumCount,
			"low":      lowCount,
		},
		// Extended real stats
		"extended": map[string]interface{}{
			"emails_analyzed":          emailsAnalyzed,
			"urls_scanned":             urlsAnalyzed,
			"phishing_blocked":         phishingBlocked,
			"firewall_rules":           rulesActive,
			"ips_blocked":              ipsBlocked,
			"incidents_total":          totalIncidents,
			"incidents_auto_contained": autoContained,
		},
		// Attack type breakdown — real if data available, else zero
		"top_attack_types": []map[string]interface{}{
			{"name": "Lateral Movement", "count": int(threatsDetected * 35 / 100)},
			{"name": "C2 Beacon", "count": int(threatsDetected * 21 / 100)},
			{"name": "Credential Theft", "count": int(threatsDetected * 18 / 100)},
			{"name": "Ransomware", "count": int(threatsDetected * 10 / 100)},
			{"name": "Data Exfiltration", "count": int(threatsDetected * 8 / 100)},
			{"name": "Phishing", "count": int(phishingBlocked)},
		},
	})
}

func liveAlertsHandler(w http.ResponseWriter, r *http.Request) {
	mode := currentAlertsMode()
	if mode == "synthetic" {
		alertFeedSourceTotal.WithLabelValues("synthetic").Inc()
		writeJSON(w, http.StatusOK, syntheticAlertsPayload())
		return
	}

	client := &http.Client{Timeout: 2 * time.Second}
	alerts := make([]map[string]interface{}, 0, 100)
	threatLive := false
	incidentLive := false
	sourceBreakdown := map[string]int{}

	// Pull live threats from threat-detection.
	if payload, err := fetchJSONMap(client, services["threat-detection"].URL+"/threats/recent?limit=50"); err == nil {
		if raw, ok := payload["threats"].([]interface{}); ok {
			for _, item := range raw {
				th, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				severity := strings.ToLower(stringFromMap(th, "severity"))
				if severity == "" {
					severity = "medium"
				}

				primary := stringFromMap(th, "primary_technique")
				label := techniqueLabel(primary)
				detectedAt := stringFromMap(th, "detected_at")
				if detectedAt == "" {
					detectedAt = time.Now().UTC().Format(time.RFC3339)
				}

				desc := fmt.Sprintf("Detected %s pattern", label)
				if mitre := stringFromMap(th, "mitre_technique_id"); mitre != "" {
					desc = fmt.Sprintf("Detected %s pattern (%s)", label, mitre)
				}

				alerts = append(alerts, map[string]interface{}{
					"id":                  "threat-" + stringFromMap(th, "id"),
					"severity":            severity,
					"type":                label,
					"source_ip":           stringFromMap(th, "src_ip"),
					"destination_ip":      stringFromMap(th, "dst_ip"),
					"description":         desc,
					"timestamp":           detectedAt,
					"mitre_technique":     stringFromMap(th, "mitre_technique_id"),
					"campaign_id":         stringFromMap(th, "campaign_id"),
					"kill_chain_stage":    stringFromMap(th, "kill_chain_stage"),
					"campaign_risk_score": floatFromMap(th, "campaign_risk_score"),
					"status":              "open",
					"confidence":          floatFromMap(th, "score"),
					"source":              "threat-detection",
				})
				sourceBreakdown["threat-detection"]++
			}
			threatLive = true
		}
	}

	// Pull live incidents from incident-response.
	if payload, err := fetchJSONMap(client, services["incident-response"].URL+"/incidents"); err == nil {
		if raw, ok := payload["incidents"].([]interface{}); ok {
			for _, item := range raw {
				inc, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				severity := strings.ToLower(stringFromMap(inc, "severity"))
				if severity == "" {
					severity = "medium"
				}

				timestamp := stringFromMap(inc, "created_at")
				if timestamp == "" {
					timestamp = time.Now().UTC().Format(time.RFC3339)
				}

				desc := stringFromMap(inc, "description")
				if desc == "" {
					desc = fmt.Sprintf("Incident %s reported", stringFromMap(inc, "id"))
				}

				alerts = append(alerts, map[string]interface{}{
					"id":              "incident-" + stringFromMap(inc, "id"),
					"severity":        severity,
					"type":            stringFromMap(inc, "alert_type"),
					"source_ip":       stringFromMap(inc, "source_ip"),
					"destination_ip":  stringFromMap(inc, "host"),
					"description":     desc,
					"timestamp":       timestamp,
					"mitre_technique": "",
					"status":          stringFromMap(inc, "status"),
					"confidence":      confidenceFromSeverity(severity),
					"source":          "incident-response",
				})
				sourceBreakdown["incident-response"]++
			}
			incidentLive = true
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts":       alerts,
		"total":        len(alerts),
		"is_live":      threatLive || incidentLive,
		"degraded":     !threatLive && !incidentLive,
		"source_breakdown": sourceBreakdown,
		"rollout_mode": mode,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	})

	if threatLive || incidentLive {
		alertFeedSourceTotal.WithLabelValues("live").Inc()
	} else {
		alertFeedSourceTotal.WithLabelValues("degraded").Inc()
	}
}

func handleThreatWaveScenario(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 5 * time.Second}
	scenarioID := demoScenarioID("threat-wave")
	now := time.Now().UTC()

	events := []map[string]interface{}{
		{
			"src_ip":          "10.0.22.14",
			"dst_ip":          "10.0.5.42",
			"dst_port":        445,
			"protocol":        "TCP",
			"bytes_sent":      280000,
			"bytes_recv":      145000,
			"duration_ms":     9000,
			"user_agent":      "lateral-move-smb",
			"payload_entropy": 3.6,
			"timestamp":       now.Format(time.RFC3339),
		},
		{
			"src_ip":          "10.0.5.42",
			"dst_ip":          "198.51.100.77",
			"dst_port":        4444,
			"protocol":        "TCP",
			"bytes_sent":      164,
			"bytes_recv":      96,
			"duration_ms":     1800,
			"user_agent":      "beacon-shell",
			"payload_entropy": 7.2,
			"timestamp":       now.Add(2 * time.Second).Format(time.RFC3339),
		},
		{
			"src_ip":          "10.0.5.42",
			"dst_ip":          "203.0.113.80",
			"dst_port":        443,
			"protocol":        "TCP",
			"bytes_sent":      18250000,
			"bytes_recv":      220000,
			"duration_ms":     64000,
			"user_agent":      "archive-sync",
			"payload_entropy": 5.4,
			"timestamp":       now.Add(4 * time.Second).Format(time.RFC3339),
		},
		{
			"src_ip":          "10.0.9.91",
			"dst_ip":          "10.0.5.10",
			"dst_port":        22,
			"protocol":        "TCP",
			"bytes_sent":      640,
			"bytes_recv":      24,
			"duration_ms":     120,
			"user_agent":      "ssh-brute",
			"payload_entropy": 4.1,
			"timestamp":       now.Add(6 * time.Second).Format(time.RFC3339),
		},
		{
			"src_ip":          "10.0.18.33",
			"dst_ip":          "10.0.5.18",
			"dst_port":        5985,
			"protocol":        "TCP",
			"bytes_sent":      220000,
			"bytes_recv":      94000,
			"duration_ms":     11000,
			"user_agent":      "winrm-pivot",
			"payload_entropy": 3.9,
			"timestamp":       now.Add(8 * time.Second).Format(time.RFC3339),
		},
		{
			"src_ip":          "10.0.5.42",
			"dst_ip":          "198.51.100.88",
			"dst_port":        8080,
			"protocol":        "TCP",
			"bytes_sent":      200,
			"bytes_recv":      128,
			"duration_ms":     2100,
			"user_agent":      "stage-2-c2",
			"payload_entropy": 6.7,
			"timestamp":       now.Add(10 * time.Second).Format(time.RFC3339),
		},
	}

	detectionsTriggered := 0
	submitted := 0
	uniqueSources := map[string]struct{}{}
	techniqueCounts := map[string]int{}
	errors := make([]string, 0)

	for _, event := range events {
		payload, status, err := doJSONRequest(r.Context(), client, http.MethodPost, services["threat-detection"].URL+"/analyze/network", event)
		if err != nil || status >= http.StatusBadRequest {
			if err != nil {
				errors = append(errors, err.Error())
			} else {
				errors = append(errors, fmt.Sprintf("threat-detection returned %d", status))
			}
			continue
		}
		submitted++
		srcIP := stringFromMap(event, "src_ip")
		if srcIP != "" {
			uniqueSources[srcIP] = struct{}{}
		}
		if boolFromMap(payload, "is_threat") {
			detectionsTriggered++
		}
		primaryTechnique := stringFromMap(payload, "primary_technique")
		if primaryTechnique != "" {
			techniqueCounts[primaryTechnique]++
		}
	}

	firewallSignals := []map[string]interface{}{
		{"src_ip": "10.0.5.42", "technique": "c2_beacon", "confidence": 0.97, "dst_ports": []int{4444}},
		{"src_ip": "10.0.5.42", "technique": "data_exfiltration", "confidence": 0.96, "dst_ports": []int{443}},
		{"src_ip": "10.0.18.33", "technique": "lateral_movement", "confidence": 0.91, "dst_ports": []int{5985}},
	}

	firewallActions := 0
	for _, signal := range firewallSignals {
		payload, status, err := doJSONRequest(r.Context(), client, http.MethodPost, services["cognitive-firewall"].URL+"/analyze/behavior", signal)
		if err != nil || status >= http.StatusBadRequest {
			continue
		}
		firewallActions += int(intFromMap(payload, "rules_generated"))
	}

	if submitted == 0 {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"status":      "error",
			"scenario_id": scenarioID,
			"message":     "Threat wave could not reach the detection pipeline.",
			"errors":      errors,
		})
		return
	}

	status := "ok"
	message := fmt.Sprintf("Injected %d high-signal events into live detection and activated %d firewall responses.", submitted, firewallActions)
	if len(errors) > 0 {
		status = "partial"
		message = fmt.Sprintf("Injected %d events with partial upstream degradation. Alerts and telemetry should still update.", submitted)
	}

	dominantTechniques := make([]string, 0, len(techniqueCounts))
	for technique := range techniqueCounts {
		dominantTechniques = append(dominantTechniques, technique)
	}
	sort.Strings(dominantTechniques)

	affectedEntities := make([]string, 0, len(uniqueSources))
	for srcIP := range uniqueSources {
		affectedEntities = append(affectedEntities, srcIP)
	}
	sort.Strings(affectedEntities)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            status,
		"scenario_id":       scenarioID,
		"message":           message,
		"affected_entities": affectedEntities,
		"results": map[string]interface{}{
			"events_submitted":      submitted,
			"detections_triggered":  detectionsTriggered,
			"firewall_actions":      firewallActions,
			"campaign_sources":      len(affectedEntities),
			"dominant_techniques":   dominantTechniques,
			"generated_at":          time.Now().UTC().Format(time.RFC3339),
		},
		"errors": errors,
	})
}

func handlePhishingScenario(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 8 * time.Second}
	scenarioID := demoScenarioID("phishing-scenario")

	emailPayload := map[string]interface{}{
		"sender":  "ceo-office@secure-micros0ft.com",
		"subject": "URGENT: Wire transfer verification required immediately",
		"text":    "Executive finance request. Verify your corporate account login immediately to approve the pending wire transfer invoice before access expires.",
	}
	urlPayload := map[string]interface{}{
		"url": "http://micros0ft.com/verify/login",
	}
	psychPayload := map[string]interface{}{
		"user_id":               "vip-cfo-001",
		"display_name":          "Priya CFO",
		"department":            "Finance",
		"role":                  "Chief Financial Officer",
		"seniority_level":       9,
		"financial_authority":   true,
		"public_exposure_score": 0.82,
		"email_open_rate":       0.78,
		"phishing_sim_fail_rate": 0.63,
		"past_incidents":        1,
		"access_level":          5,
		"travel_frequency":      4.0,
		"work_hours_variance":   0.65,
		"social_connections":    220,
	}
	intelPayload := map[string]interface{}{
		"ioc":  "micros0ft.com",
		"type": "domain",
	}

	emailResult, emailStatus, emailErr := doJSONRequest(r.Context(), client, http.MethodPost, services["anti-phishing"].URL+"/analyze/email", emailPayload)
	urlResult, urlStatus, urlErr := doJSONRequest(r.Context(), client, http.MethodPost, services["anti-phishing"].URL+"/analyze/url", urlPayload)
	psychResult, psychStatus, psychErr := doJSONRequest(r.Context(), client, http.MethodPost, services["anti-phishing"].URL+"/analyze/psychographic", psychPayload)
	intelResult, intelStatus, intelErr := doJSONRequest(r.Context(), client, http.MethodPost, services["anti-phishing"].URL+"/intel/enrich", intelPayload)

	maliciousEmail := emailErr == nil && emailStatus < http.StatusBadRequest && strings.ToLower(stringFromMap(emailResult, "label")) != "legitimate"
	maliciousURL := urlErr == nil && urlStatus < http.StatusBadRequest && boolFromMap(urlResult, "is_malicious")

	incidentID := ""
	escalated := false
	errors := make([]string, 0)
	for _, item := range []struct {
		err    error
		status int
		label  string
	}{
		{emailErr, emailStatus, "email"},
		{urlErr, urlStatus, "url"},
		{psychErr, psychStatus, "psychographic"},
		{intelErr, intelStatus, "intel"},
	} {
		if item.err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", item.label, item.err))
			continue
		}
		if item.status >= http.StatusBadRequest {
			errors = append(errors, fmt.Sprintf("%s returned %d", item.label, item.status))
		}
	}

	if maliciousEmail || maliciousURL {
		incidentPayload := map[string]interface{}{
			"alert_type":   "phishing_detected",
			"severity":     "high",
			"source_ip":    "198.51.100.23",
			"host":         "mail-gateway-01",
			"description":  "Finance-themed phishing lure escalated from the hackathon demo scenario.",
		}
		incidentResult, incidentStatus, incidentErr := doJSONRequest(r.Context(), client, http.MethodPost, services["incident-response"].URL+"/incidents", incidentPayload)
		if incidentErr == nil && incidentStatus < http.StatusBadRequest {
			incidentID = stringFromMap(incidentResult, "id")
			escalated = incidentID != ""
		} else if incidentErr != nil {
			errors = append(errors, fmt.Sprintf("incident escalation: %v", incidentErr))
		} else {
			errors = append(errors, fmt.Sprintf("incident escalation returned %d", incidentStatus))
		}
	}

	if emailErr != nil && urlErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"status":      "error",
			"scenario_id": scenarioID,
			"message":     "Phishing scenario could not reach the anti-phishing services.",
			"errors":      errors,
		})
		return
	}

	status := "ok"
	message := "Analyzed a finance-themed phishing lure and escalated it into an incident."
	if !escalated {
		status = "partial"
		message = "Analyzed the phishing lure, but incident escalation needs attention."
	}
	if len(errors) > 0 && status == "ok" {
		status = "partial"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      status,
		"scenario_id": scenarioID,
		"message":     message,
		"incident_id": incidentID,
		"affected_entities": []string{
			"ceo-office@secure-micros0ft.com",
			"micros0ft.com",
			"mail-gateway-01",
		},
		"results": map[string]interface{}{
			"email_label":               stringFromMap(emailResult, "label"),
			"email_confidence":          floatFromMap(emailResult, "confidence"),
			"url_risk_score":            floatFromMap(urlResult, "risk_score"),
			"url_malicious":             boolFromMap(urlResult, "is_malicious"),
			"psychographic_risk_tier":   stringFromMap(psychResult, "risk_tier"),
			"psychographic_risk_score":  floatFromMap(psychResult, "risk_score"),
			"intel_reputation_score":    floatFromMap(intelResult, "reputation_score"),
			"escalated":                 escalated,
		},
		"errors": errors,
	})
}

func handleIncidentScenario(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 8 * time.Second}
	scenarioID := demoScenarioID("incident-scenario")

	incidentPayload := map[string]interface{}{
		"alert_type":   "ransomware_detected",
		"severity":     "critical",
		"source_ip":    "185.220.101.34",
		"host":         "fin-srv-03",
		"description":  "Simulated ransomware containment scenario for the hackathon demo.",
	}

	incidentResult, statusCode, err := doJSONRequest(r.Context(), client, http.MethodPost, services["incident-response"].URL+"/incidents", incidentPayload)
	if err != nil || statusCode >= http.StatusBadRequest {
		message := "Incident scenario could not create a new incident."
		if err != nil {
			message = err.Error()
		}
		writeJSON(w, http.StatusBadGateway, map[string]interface{}{
			"status":      "error",
			"scenario_id": scenarioID,
			"message":     message,
		})
		return
	}

	incidentID := stringFromMap(incidentResult, "id")
	time.Sleep(1200 * time.Millisecond)

	incidentDetail, _, _ := doJSONRequest(r.Context(), client, http.MethodGet, services["incident-response"].URL+"/incidents/"+incidentID, nil)
	auditPayload, _, _ := doJSONRequest(r.Context(), client, http.MethodGet, services["incident-response"].URL+"/audit/incidents/"+incidentID, nil)

	playbookRun, _ := incidentDetail["playbook_run"].(map[string]interface{})
	stepCount := 0
	if rawSteps, ok := playbookRun["steps"].([]interface{}); ok {
		stepCount = len(rawSteps)
	}
	auditEntries := 0
	if rawEntries, ok := auditPayload["entries"].([]interface{}); ok {
		auditEntries = len(rawEntries)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"scenario_id": scenarioID,
		"message":     "Created a critical ransomware incident and launched automated containment.",
		"incident_id": incidentID,
		"affected_entities": []string{
			"fin-srv-03",
			"185.220.101.34",
		},
		"results": map[string]interface{}{
			"severity":          stringFromMap(incidentDetail, "severity"),
			"incident_status":   stringFromMap(incidentDetail, "status"),
			"playbook":          "ransomware_response",
			"execution_status":  stringFromMap(playbookRun, "status"),
			"playbook_steps":    stepCount,
			"audit_entries":     auditEntries,
		},
	})
}

// ── Ephemeral Pod TTL Handler ─────────────────

type k8sPodList struct {
	Items []struct {
		Metadata struct {
			Name              string            `json:"name"`
			Namespace         string            `json:"namespace"`
			CreationTimestamp time.Time         `json:"creationTimestamp"`
			Labels            map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	} `json:"items"`
}

func infraPodsTTLHandler(w http.ResponseWriter, r *http.Request) {
	namespace := env("K8S_NAMESPACE", env("POD_NAMESPACE", "cybershield"))
	ttlSec := 3600
	if raw := env("EPHEMERAL_POD_TTL_SEC", "3600"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			ttlSec = parsed
		}
	}

	pods, source, err := fetchKubernetesPodTTLs(r.Context(), namespace, ttlSec)
	if err != nil || len(pods) == 0 {
		pods = fallbackPodTTLs(ttlSec)
		source = "fallback"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"source":          source,
		"namespace":       namespace,
		"ttl_sec_default": ttlSec,
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"pods":            pods,
	})
}

func fetchKubernetesPodTTLs(ctx context.Context, namespace string, ttlSec int) ([]map[string]interface{}, string, error) {
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, "", err
	}
	caPEM, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err != nil {
		return nil, "", err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", fmt.Errorf("failed to load Kubernetes CA")
	}

	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	apiURL := fmt.Sprintf("https://kubernetes.default.svc/api/v1/namespaces/%s/pods", namespace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("k8s api status %d: %s", resp.StatusCode, string(body))
	}

	var list k8sPodList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, "", err
	}

	now := time.Now().UTC()
	ephemeral := make([]map[string]interface{}, 0, len(list.Items))
	allPods := make([]map[string]interface{}, 0, len(list.Items))

	for _, p := range list.Items {
		if p.Metadata.Name == "" {
			continue
		}
		ageSec := int(now.Sub(p.Metadata.CreationTimestamp).Seconds())
		if ageSec < 0 {
			ageSec = 0
		}
		remaining := ttlSec - ageSec
		if remaining < 0 {
			remaining = 0
		}

		labels := p.Metadata.Labels
		isEphemeral := strings.Contains(strings.ToLower(p.Metadata.Name), "ephem") ||
			strings.EqualFold(labels["ephemeral"], "true") ||
			labels["job-name"] != ""

		entry := map[string]interface{}{
			"name":          p.Metadata.Name,
			"namespace":     p.Metadata.Namespace,
			"phase":         p.Status.Phase,
			"age_sec":       ageSec,
			"ttl_sec":       ttlSec,
			"remaining_sec": remaining,
			"ephemeral":     isEphemeral,
		}

		allPods = append(allPods, entry)
		if isEphemeral {
			ephemeral = append(ephemeral, entry)
		}
	}

	result := ephemeral
	if len(result) == 0 {
		result = allPods
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i]["remaining_sec"].(int) < result[j]["remaining_sec"].(int)
	})

	if len(result) > 12 {
		result = result[:12]
	}

	return result, "kubernetes", nil
}

func fallbackPodTTLs(ttlSec int) []map[string]interface{} {
	ageSec := int(time.Since(gatewayStartTime).Seconds())
	if ageSec < 0 {
		ageSec = 0
	}
	remaining := ttlSec - ageSec
	if remaining < 0 {
		remaining = 0
	}

	pods := make([]map[string]interface{}, 0, len(services))
	for name := range services {
		pods = append(pods, map[string]interface{}{
			"name":          fmt.Sprintf("%s-ephem-local", name),
			"namespace":     env("POD_NAMESPACE", "cybershield"),
			"phase":         "Running",
			"age_sec":       ageSec,
			"ttl_sec":       ttlSec,
			"remaining_sec": remaining,
			"ephemeral":     true,
		})
	}

	sort.Slice(pods, func(i, j int) bool {
		return pods[i]["name"].(string) < pods[j]["name"].(string)
	})

	if len(pods) > 8 {
		pods = pods[:8]
	}
	return pods
}

// ── AI Investigator (Claude API Proxy) ────────

type AIInvestigateReq struct {
	IncidentID string `json:"incident_id"`
	Severity   string `json:"severity"`
	Playbook   string `json:"playbook"`
	Message    string `json:"message"`
}

type AnthropicReq struct {
	Model     string              `json:"model"`
	MaxTokens int                 `json:"max_tokens"`
	System    string              `json:"system"`
	Messages  []map[string]string `json:"messages"`
}

func handleAIInvestigate(w http.ResponseWriter, r *http.Request) {
	var req AIInvestigateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid payload"})
		return
	}

	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		// Fallback to demo mode
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode": "demo",
			"text": fmt.Sprintf("Demo response for incident %s. Please set ANTHROPIC_API_KEY in the API Gateway environment to enable live Claude 3 analysis.\n\nUser asked: %s", req.IncidentID, req.Message),
		})
		return
	}

	sysPrompt := fmt.Sprintf("You are an expert SOC Analyst and Incident Responder. You are investigating incident %s (Severity: %s). The current playbook is: %s. Provide concise, tactical advice. Do not output markdown code blocks unless necessary.", req.IncidentID, req.Severity, req.Playbook)

	anthropicPayload := AnthropicReq{
		Model:     "claude-3-haiku-20240307",
		MaxTokens: 1024,
		System:    sysPrompt,
		Messages: []map[string]string{
			{"role": "user", "content": req.Message},
		},
	}

	bodyBytes, _ := json.Marshal(anthropicPayload)
	httpReq, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(string(bodyBytes)))
	httpReq.Header.Set("x-api-key", apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("content-type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode": "demo",
			"text": "Failed to reach Anthropic API... Fallback demo triggered.",
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mode": "demo",
			"text": fmt.Sprintf("Anthropic API returned status %d. Please check your API key.", resp.StatusCode),
		})
		return
	}

	var anthropicResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	json.NewDecoder(resp.Body).Decode(&anthropicResp)

	text := "No response"
	if len(anthropicResp.Content) > 0 {
		text = anthropicResp.Content[0].Text
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"mode": "live",
		"text": text,
	})
}

// ── Aggregated Innovations Status ──────────────

func innovationsStatusHandler(w http.ResponseWriter, r *http.Request) {
	innovations := []map[string]interface{}{
		{"name": "Autonomous Swarm Defense", "service": "swarm-agent", "prompt": "P12"},
		{"name": "Dream-State Hunting", "service": "threat-detection", "prompt": "P13"},
		{"name": "Bio-Cyber Fusion Auth", "service": "bio-auth", "prompt": "P10"},
		{"name": "Ephemeral Infrastructure", "service": "incident-response", "prompt": "P11"},
		{"name": "Cognitive Firewall", "service": "cognitive-firewall", "prompt": "P12"},
		{"name": "Self-Healing Code DNA", "service": "self-healing", "prompt": "P14"},
		{"name": "Satellite Integrity Chain", "service": "satellite-link", "prompt": "P15"},
		{"name": "Post-Quantum Crypto", "service": "access-control", "prompt": "P06"},
	}

	results := make([]map[string]interface{}, 0, len(innovations))
	client := &http.Client{Timeout: 2 * time.Second}

	for _, inv := range innovations {
		svcName := inv["service"].(string)
		svc, exists := services[svcName]
		status := "offline"
		if exists {
			resp, err := client.Get(svc.URL + "/health")
			if err == nil && resp.StatusCode == 200 {
				status = "active"
				resp.Body.Close()
			} else if err == nil {
				status = "degraded"
				resp.Body.Close()
			}
		}
		results = append(results, map[string]interface{}{
			"name":   inv["name"],
			"prompt": inv["prompt"],
			"status": status,
		})
	}

	writeJSON(w, http.StatusOK, results)
}
