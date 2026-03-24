# Section B Implementation Progress — Secure Access & Advanced Encryption

**Status**: Phase 1, 2, 3, & 4 Complete (Asymmetric JWT + JWKS + RBAC + Persistent Key Rotation + OIDC Federation)
**Updated**: 2026-03-24

## What Has Been Implemented

### Phase 1: Hardened Cryptography & Token Lifecycle ✅

#### 1.1 Password Hashing (Access Control Service)
- **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L199)
- **Implementation**: Argon2id with per-user salt + server-side pepper
  - Memory: 64KB, Iterations: 3, Parallelism: 2
  - 16-byte random salt per user, 32-byte key derived
  - Pepper stored in `PASSWORD_PEPPER` environment variable
- **Verification**: Constant-time comparison to prevent timing attacks
  - **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L222)

#### 1.2 Asymmetric JWT Signing (Access Control Service)
- **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L117)
- **Implementation**: RS256 (RSA 2048-bit) instead of HS256
  - Each JWT includes `kid` (key ID) header for key identification
  - Claims include issuer (`ACCESS_CONTROL_ISSUER`) and audience (`JWT_AUDIENCE`)
  - Supports token validation without shared secrets

#### 1.3 JWKS (JSON Web Key Set) Publication ✅
- **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L298)
- **Endpoint**: `GET /auth/.well-known/jwks.json`
- **Content**: Contains current and next signing keys with:
  - `kty`: RSA
  - `kid`: Key identifier (8-byte hex)
  - `use`: sig (signature)
  - `n`, `e`: Modulus and public exponent (RFC 7517 format)
- **Key Rotation**: Two keys maintained (current + next) for zero-downtime rotation
  - **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L266)

#### 1.4 Public Key Export (for offline verification)
- **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L307)
- **Endpoint**: `GET /auth/public-key.pem`
### Phase 2: Gateway JWT Verification via JWKS ✅

  - Requires RS256 signing method (rejects HS256)
  - Enforces issuer validation against `ACCESS_CONTROL_ISSUER`
#### 2.2 JWKS Caching & Refresh (API Gateway)
- **File**: [services/api-gateway/cmd/main.go](services/api-gateway/cmd/main.go#L258)
- **Function**: `refreshJWKS()`
  - Fetches from `ACCESS_CONTROL_JWKS_URL`
  - Caches for 5 minutes (configurable)
  - Parses RSA public keys from base64url N and E components
  - On unknown kid, refreshes cache automatically

#### 2.3 RSA Public Key Parsing (API Gateway)
  - Base64url decoding with validation
  - Exponent range validation


  ### Phase 4: Enterprise Identity Federation ✅

  **Objective**: Integrate external identity providers for centralized user/group management via OAuth2/OIDC.

  #### 4.1 OIDC Client with Discovery (Access Control Service)
  - **File**: [services/access-control/internal/oidc/client.go](services/access-control/internal/oidc/client.go)
  - **Implementation**: Full-featured OAuth2/OIDC client with automatic provider discovery
    - RFC 8414 well-known/openid-configuration discovery
    - Support for multiple providers: Keycloak, Azure AD, Auth0
    - PKCE (RFC 7636) support for secure authorization code flow
    - Automatic JWKS fetching and caching
  - **Key Methods**:
    - `NewOAuth2Client()`: Initialize with provider config
    - `discover()`: Fetch provider metadata from .well-known/openid-configuration
    - `AuthorizationURL()`: Generate authorization URL with PKCE challenge
    - `ExchangeCodeForToken()`: Trade authorization code for access/ID token
    - `GetUserInfo()`: Fetch user information from userinfo endpoint

  #### 4.2 Claim Mapping Engine (Access Control Service)
  - **File**: [services/access-control/internal/oidc/mapper.go](services/access-control/internal/oidc/mapper.go)
  - **Implementation**: Flexible claim mapping with hierarchical role assignment
    - `ClaimMapper`: Translates IdP claims → internal roles (admin, analyst, responder, viewer)
    - Supports multiple mapping strategies:
      1. Email domain mapping: `@company.io` → analyst
      2. LDAP/IdP groups: `security-team` → analyst, `admins` → admin
      3. Hierarchical role assignment: highest-privilege matching group wins
    - `MappedUser`: Internal representation after mapping
    - Provider-specific adapters: Keycloak, Azure AD, Auth0
  - **Key Methods**:
    - `MapClaims()`: Translate IdP claims to internal MappedUser
    - `ValidateUser()`: Check if user meets organizational policies (e.g., blocked email domains)
    - `CreatePlatformClaims()`: Build JWT claims for platform token

  #### 4.3 Federation Routes (Access Control Service)
  - **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L680)
  - **Routes**:
    - `GET /auth/federation/authorize`: Initiates OAuth2 Authorization Code flow
      - Generates PKCE challenge and state parameter
      - Stores state in in-memory session map (expires in 10 minutes)
      - Redirects user to IdP authorization endpoint
    - `GET /auth/federation/callback`: Processes OAuth2 callback
      - Validates state parameter for CSRF protection
      - Exchanges authorization code for token using PKCE verifier
      - Fetches user info from IdP userinfo endpoint
      - Maps IdP claims to internal roles via ClaimMapper
      - Issues platform JWT token with internal role assignments
      - Returns token in JSON response

  #### 4.4 Configuration & Credentials (Access Control Service)
  - **Environment Variables**:
    ```bash
    OIDC_ENABLED=true|false                  # Enable federation (default: false)
    OIDC_PROVIDER_URL=https://...            # IdP base URL (e.g., https://keycloak.example.com/realms/cybershield)
    OIDC_CLIENT_ID=pariraksakah-client       # OAuth2 client ID from IdP
    OIDC_CLIENT_SECRET=<secret>              # OAuth2 client secret (MUST be in environment, never in code)
    OIDC_REDIRECT_URI=http://...             # Callback URL (e.g., http://localhost:8002/auth/federation/callback)
    OIDC_GROUP_ROLE_MAP={"group":"role"}     # JSON mapping of IdP groups → platform roles
    ```
  - **Initialization** (in main()):
    - NewOAuth2Client() discovers provider metadata automatically
    - NewClaimMapper() initializes with groupRoleMap from environment
    - Federation routes only registered if OIDC_ENABLED=true

  #### 4.5 Federation Flow (Complete End-to-End)
  1. User initiates federation: `GET /auth/federation/authorize`
  2. Service generates PKCE challenge and state, stores state temporarily
  3. Service redirects user to IdP: `GET https://keycloak.../auth?code_challenge=...&state=...`
  4. User authenticates with IdP (password, MFA, passkeys, etc.)
  5. IdP redirects back to callback: `GET /auth/federation/callback?code=...&state=...`
  6. Service validates state, exchanges code for token using PKCE verifier
  7. Service fetches UserInfo from IdP via access token
  8. ClaimMapper translates IdP groups → internal roles (e.g., "security-team" → "analyst")
  9. Service creates internal User record from mapped claims
  10. Service issues platform JWT token with internal role assignments
  11. Token includes: uid, username, email, role, groups, federation metadata
  12. Service returns token to client: `{"access_token": "...", "user": {...}}`

  #### 4.6 Provider-Specific Implementations
  - **Keycloak Adapter**: Handles Keycloak group claim format (e.g., "/security-team")
  - **Azure AD Adapter**: Handles Azure group GUIDs and app roles claim format
  - **Auth0 Adapter**: Handles Auth0 custom namespaced claims (e.g., "https://company.io/roles")

  #### 4.7 Compile Status
  - access-control service: `go build ./cmd` ✅ SUCCESS
  - api-gateway service: `go build ./cmd` ✅ SUCCESS (no changes needed)

  ---
### Phase 2b: RBAC/ABAC Authorization Enforcement ✅
  ## What Remains for Section B

  ### Phase 5: Advanced MFA & Device Posture (Future)

  **Objective**: Multi-factor authentication and zero-trust device trust validation.

  **Planned implementations**:
  - Time-based OTP (TOTP) / FIDO2 / WebAuthn support
  - Device posture checking (antivirus, OS patch level)
  - Conditional access policies based on risk assessment
  - Session invalidation on device trust loss

  ---

#### 2b.1 Policy Definition & Storage (API Gateway)
- **File**: [services/api-gateway/cmd/main.go](services/api-gateway/cmd/main.go#L70)
- **Structure**: `Policy` with Resource, Action, Effect, Roles, Conditions
- **Initialization**: `initPolicies()` called at gateway startup
  - **File**: [services/api-gateway/cmd/main.go](services/api-gateway/cmd/main.go#L117)

#### 2b.2 Authorization Policy Rules ✅
Deny-by-default policies for critical operations:

| Resource | Action | Allowed Roles | Denied Roles |
|----------|--------|---------------|--------------|
| `/soar` | execute | admin, responder | analyst, viewer |
| `/incidents` | read | admin, analyst, responder | viewer |
| `/incidents` | write | admin, responder | analyst, viewer |
| `/incidents` | delete | admin | all others |
| `/self-healing` | execute | admin, responder | analyst, viewer |
| `/threats` | read | all authenticated | — |
| `/threats` | write | admin | analyst, responder, viewer |
| `/phishing` | read | admin, analyst, responder | viewer |
| `/phishing` | execute | admin, responder | analyst, viewer |
| `/threat-hunting` | read, execute | admin, analyst | responder, viewer |

#### 2b.3 Authorization Middleware (API Gateway)
- **File**: [services/api-gateway/cmd/main.go](services/api-gateway/cmd/main.go#L211)
- **Function**: `AuthorizationMiddleware()`
- **Behavior**:
  - Extracts authentication context from JWT claims
  - Maps HTTP method to policy action: GET→read, POST/PUT/PATCH→write, DELETE→delete, custom→execute
  - Looks up resource from route pattern
  - Checks role membership against allowed roles
  - Allows only if matched policy has `Effect: allow`
  - Logs `[AUTHZ-ALLOW]` or `[AUTHZ-DENY]` for audit trail

#### 2b.4 Applied to Protected Routes
- **File**: [services/api-gateway/cmd/main.go](services/api-gateway/cmd/main.go#L739)
- All routes under `/api/v1` now require both:
  1. Valid JWT (JWTAuthMiddleware)
  2. Role-based authorization (AuthorizationMiddleware)

---

### Phase 3: Persistent Key Management & Rotation ✅

**Objective**: Move from in-memory ephemeral keys to persistent, rotatable keys with audit trail.

#### 3.1 Persistent Key Storage (Access Control Service)
- **File**: [services/access-control/internal/keymanagement/keymanager.go](services/access-control/internal/keymanagement/keymanager.go)
- **Implementation**: JSON-based file storage on disk (migrates to Kubernetes Secret)
  - Path: `KEYS_DIR` environment variable (default: `/etc/cybershield/keys`)
  - Permissions: 0600 (read/write owner only)
  - Contains: Current, next, and retiring RSA 2048-bit keys with metadata

#### 3.2 Key Metadata Tracking
- **File**: [services/access-control/internal/keymanagement/keymanager.go](services/access-control/internal/keymanagement/keymanager.go#L18)
- **SigningKey struct**: Kid, Version, Algorithm, PrivateKey (base64), PublicKey (base64), CreatedAt, ExpiresAt, RotatedBy, Status
- **Statuses**: "active" (current signing key), "next" (staged for tomorrow), "retiring" (grace period, validates old tokens)

#### 3.3 Zero-Downtime Key Rotation
- **File**: [services/access-control/internal/keymanagement/keymanager.go](services/access-control/internal/keymanagement/keymanager.go#L133)
- **Function**: `RotateKeys()`
- **Behavior**: 
  - 3-key overlap strategy: current → retiring (grace period), next → current (becomes active), generate new next
  - Gateway continues validating old tokens with retiring key during overlap window
  - Tokens issued after rotation use new kid automatically
  - No service restarts required

#### 3.4 Automatic Rotation Scheduler
- **File**: [services/access-control/internal/keymanagement/keymanager.go](services/access-control/internal/keymanagement/keymanager.go#L159)
- **Function**: `StartRotationScheduler()`
- **Configuration**:
  - Rotation period: `KEY_ROTATION_PERIOD` env var (default: 7 days)
  - Key lifetime: `KEY_LIFETIME` env var (default: 30 days)
  - Implements exponential backoff on errors
  - Runs as background goroutine in access-control service

#### 3.5 Access Control Service Integration
- **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L497)
- **Initialization**: `keyStore, err := keymanagement.NewKeyStore(keysDir, keyRotationPeriod, keyLifetime)`
- **Startup**: `keyStore.StartRotationScheduler()` called in main()
- **Usage**: 
  - `issueToken()` calls `keyStore.GetSigningKey().DecodePrivateKey()` for RS256 signing
  - `tokenKeyFunc()` iterates `keyStore.GetPublicKeys()` for token validation
  - `jwksHandler()` exposes current + next + retiring keys via JWKS endpoint
- **Compile Status**: ✅ go build ./cmd succeeds

#### 3.6 Gateway Key Validation Support
- **File**: [services/api-gateway/cmd/main.go](services/api-gateway/cmd/main.go#L258)
- **Function**: `refreshJWKS()` with automatic refresh on unknown kid
- **Behavior**: 
  - Caches JWKS for 5 minutes
  - On unknown kid from access-control, automatically refreshes to pick up newly rotated key
  - Validates tokens with any key from current + next + retiring set
  - No manual intervention required

#### 3.7 Health Endpoint Enhancement
- **File**: [services/access-control/cmd/main.go](services/access-control/cmd/main.go#L520)
- **Metrics**:
  - `signing_kid`: Current active key ID
  - `key_status`: Current key status (active/next/retiring)
  - `active_sessions`: Connected sessions
- **Sample Response**:
  ```json
  {
    "status": "healthy",
    "service": "access-control",
    "version": "2.1.0",
    "active_sessions": 5,
    "signing_kid": "a1b2c3d4",
    "key_status": "active"
  }
  ```

---

## What Remains for Section B

### Phase 4: Enterprise Identity Federation (TODO)

**Objective**: Integrate external identity providers for centralized user/group management.

**Option A: Keycloak (Self-Hosted, Recommended for national-grade security)**
- OAuth2 / OIDC provider
- Multi-realm support, flexible claim mapping
- Native group/role federation to platform roles
- Audit trail, session management, MFA support

**Option B: Azure AD / Entra ID (Enterprise)**
- OIDC with group claims
- Conditional Access policies
- Seamless integration with corporate IdP

**Option C: Auth0 (SaaS, fastest to deploy)**
- Managed OIDC identity platform
- Rules engine for claim transformation
- Integration with 100+ identity providers

**Required Implementation**:
1. Authorization Code + PKCE flow endpoint
2. Token handler to call IdP token endpoint
3. Claim mapper (external groups → platform roles + policies)
4. Session management (optional: use IdP's, or bridge to Redis)
5. Logout flow with IdP sign-out

**Implementation files**:
- `services/access-control/internal/oidc/client.go` (OIDC client)
- `services/access-control/internal/auth/federation.go` (claim mapping)
- `services/access-control/cmd/federation_routes.go` (OAuth2 routes)

**Estimated effort**: 3-5 days (for one provider integration)

---

## Environment Variables & Configuration

### Access Control Service
```bash
ACCESS_CONTROL_PORT=8002
ACCESS_CONTROL_ISSUER=http://access-control:8002  # or https://auth.company.io
JWT_AUDIENCE=pariraksakah-api
PASSWORD_PEPPER=<random-secure-string>             # Production: rotate periodically
```

### API Gateway Service
```bash
PORT=8000
ACCESS_CONTROL_ISSUER=http://access-control:8002
JWT_AUDIENCE=pariraksakah-api
ACCESS_CONTROL_JWKS_URL=http://access-control:8002/auth/.well-known/jwks.json
```

### Kubernetes Deployment
See [infrastructure/kubernetes/access-control.yaml](infrastructure/kubernetes/access-control.yaml) for Secret mounting and volume handling.

---

## Testing Checklist for Section B

### Phase 1 & 2 Tests (Ready to Execute)

- [ ] **Password Hashing**
  - Test: Login with valid credentials → token issued
  - Test: Login with wrong password → 401 Unauthorized
  - Test: Multiple login attempts with same password → different hashes
  
- [ ] **JWT Asymmetric Signing**
  - Test: Decode token JWT header → contains `kid`
  - Test: Token claims contain `iss` (issuer) and `aud` (audience)
  - Test: Verify with gateway JWKS endpoint works
  
- [ ] **JWKS Endpoint**
  - Test: GET `/auth/.well-known/jwks.json` → valid JSON with keys array
  - Test: Each key contains kty, kid, alg, use, n, e
  - Test: Keys are RSA (not symmetric)
  
- [ ] **RBAC Authorization**
  - Test: Admin user can POST to `/api/v1/incidents` → 200 OK
  - Test: Analyst user can GET `/api/v1/incidents` → 200 OK
  - Test: Analyst user can POST to `/api/v1/incidents` → 403 Forbidden
  - Test: Viewer user can GET `/api/v1/threats` → 200 OK
  - Test: Viewer user can POST to `/api/v1/soar` → 403 Forbidden
  - Test: Unauthenticated user to protected route → 401 Unauthorized
  
- [ ] **Audit Logging**
  - Test: Check gateway logs for `[AUTHZ-ALLOW]` entries
  - Test: Check gateway logs for `[AUTHZ-DENY]` entries with reason

---

## Deployment Notes

### Local Development (docker-compose)
- Keys stored in JSON file at `./keys/keys.json` (must be created before container start)
- Gateway fetches JWKS from `http://access-control:8002/auth/.well-known/jwks.json`
- Rotation runs in background; seeds with 2 keys on first startup (current + next)
- Use default users: admin/admin123, analyst/analyst123, viewer/viewer123
- **Note**: For local testing, mount `/etc/cybershield/keys` as volume to persist keys across restarts

### Production Deployment (Kubernetes)
1. Create Secret with initial keys.json: `kubectl create secret generic cybershield-keys --from-file=keys.json -n cybershield`
2. Update access-control.yaml to mount Secret as volume: `secretRef: name: cybershield-keys`
3. Configure access-control environment variables:
   - `KEYS_DIR=/etc/cybershield/keys`
   - `KEY_ROTATION_PERIOD=7d` (rotate weekly)
   - `KEY_LIFETIME=30d` (keys valid for 30 days after creation)
4. Configure api-gateway: `ACCESS_CONTROL_JWKS_URL=http://access-control:8002/auth/.well-known/jwks.json`
5. Monitor access-control logs for RotationScheduler events (INFO level)
6. Set up alerting on rotation failures (ERROR level)
7. Validate key rotation in staging with: `curl http://access-control:8002/health`

---

## Next Immediate Action: Phase 3 (Persistent Keys) — COMPLETE ✅

Phase 3 implementation is complete with the following deliverables:
- ✅ Persistent key manager (keymanager.go) with JSON file storage
- ✅ 3-key overlap strategy (current/next/retiring) for zero-downtime rotation
- ✅ Background rotation scheduler with configurable period
- ✅ Integration into access-control service with full token lifecycle support
- ✅ Gateway automatic JWKS refresh on key rotation
- ✅ Health endpoint reports key status and rotation metrics
- ✅ Both services compile successfully without errors

### Next Phase: Phase 4 (Enterprise Federation)

To proceed with centralized identity management (OAuth2/OIDC federation):
1. Choose federation provider: Keycloak (recommended), Azure AD, or Auth0
2. Implement OAuth2 Authorization Code + PKCE flow
3. Add IdP claim mapper (external groups → platform roles)
4. Integrate with persistent key manager for federated key trust
5. Test end-to-end federation with external IdP
6. Deploy to staging, validate with real corporate users

Estimated effort for Phase 4: 3-5 days

---

## Summary: Section B Completion Status

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Post-quantum crypto claims | ⚠️ Deferred | Updated docs (not claimed in README) |
| Full RBAC/ABAC engine | ✅ Implemented | Gateway middleware with deny-by-default |
| OIDC/OAuth2 provider | ⏳ Planned | Phase 4 (3-5 days) |
| Key rotation/JWKS lifecycle | ⏳ Planned | Phase 3 (1-2 days) |
| Enterprise IdP integration | ⏳ Planned | Phase 4 (3-5 days) |

**Estimated completion for full Section B: 1-2 weeks** (with daily development effort)
