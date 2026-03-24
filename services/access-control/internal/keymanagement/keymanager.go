// Package keymanagement handles persistent key storage, rotation, and lifecycle for JWT signing.
package keymanagement

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// SigningKey represents an RSA key pair with metadata for key rotation and versioning.
type SigningKey struct {
	Kid        string    `json:"kid"`         // Key identifier (8-byte hex)
	Version    int       `json:"version"`     // Incremental version number
	Algorithm  string    `json:"algorithm"`   // RS256
	PrivateKey string    `json:"private_key"` // PEM-encoded private key (base64)
	PublicKey  string    `json:"public_key"`  // PEM-encoded public key (base64)
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"` // When this key will expire
	RotatedBy  string    `json:"rotated_by"` // User/service that triggered rotation
	Status     string    `json:"status"`     // active, next, retiring
}

// KeyStore manages the complete key lifecycle.
type KeyStore struct {
	mu              sync.RWMutex
	keysDir         string
	rotationPeriod  time.Duration
	keyLifetime     time.Duration
	currentKey      *SigningKey
	nextKey         *SigningKey
	retiringKey     *SigningKey
	lastRotation    time.Time
	rotationTickerC chan struct{} // Channel to trigger rotation manually
}

// NewKeyStore initializes a key store with persistent file-based storage.
func NewKeyStore(keysDir string, rotationPeriod, keyLifetime time.Duration) (*KeyStore, error) {
	ks := &KeyStore{
		keysDir:         keysDir,
		rotationPeriod:  rotationPeriod,
		keyLifetime:     keyLifetime,
		rotationTickerC: make(chan struct{}, 1),
	}

	// Create keys directory if it doesn't exist
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	// Load existing keys
	if err := ks.load(); err != nil {
		log.Printf("loadingkeys failed (generating new): %v", err)
		// Generate new keys
		if err := ks.generateInitialKeys(); err != nil {
			return nil, fmt.Errorf("failed to generate initial keys: %w", err)
		}
	}

	return ks, nil
}

// generateInitialKeys creates the initial current and next signing keys.
func (ks *KeyStore) generateInitialKeys() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	now := time.Now().UTC()
	current, err := ks.generateSigningKey(1, "system", now)
	if err != nil {
		return err
	}
	next, err := ks.generateSigningKey(2, "system", now)
	if err != nil {
		return err
	}

	ks.currentKey = current
	ks.nextKey = next
	ks.lastRotation = now

	return ks.save()
}

// generateSigningKey creates a new RSA 2048-bit signing key.
func (ks *KeyStore) generateSigningKey(version int, rotatedBy string, createdAt time.Time) (*SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	kid := randomHex(8)
	return &SigningKey{
		Kid:        kid,
		Version:    version,
		Algorithm:  "RS256",
		PrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
		PublicKey:  base64.StdEncoding.EncodeToString(publicKeyBytes),
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(ks.keyLifetime),
		RotatedBy:  rotatedBy,
		Status:     "active",
	}, nil
}

// GetSigningKey returns the current active signing key.
func (ks *KeyStore) GetSigningKey() *SigningKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.currentKey
}

// GetPublicKeys returns all active and next keys for JWKS publication.
func (ks *KeyStore) GetPublicKeys() []*SigningKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	keys := []*SigningKey{}
	if ks.currentKey != nil {
		keys = append(keys, ks.currentKey)
	}
	if ks.nextKey != nil {
		keys = append(keys, ks.nextKey)
	}
	return keys
}

// RotateKeys performs a key rotation: current -> retiring, next -> current, generate new next.
func (ks *KeyStore) RotateKeys() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	now := time.Now().UTC()
	nextVersion := 1
	if ks.nextKey != nil {
		nextVersion = ks.nextKey.Version + 1
	}

	// Generate new next key
	newNextKey, err := ks.generateSigningKey(nextVersion, "rotation", now)
	if err != nil {
		return err
	}

	// Shift keys: current -> retiring, next -> current, new -> next
	if ks.currentKey != nil {
		ks.currentKey.Status = "retiring"
		ks.retiringKey = ks.currentKey
	}
	if ks.nextKey != nil {
		ks.nextKey.Status = "active"
	}
	ks.currentKey = ks.nextKey
	ks.nextKey = newNextKey
	ks.nextKey.Status = "next"
	ks.lastRotation = now

	if err := ks.save(); err != nil {
		return fmt.Errorf("failed to save rotated keys: %w", err)
	}

	log.Printf("[KEY-ROTATION] completed: current_kid=%s next_kid=%s retiring_kid=%s",
		ks.currentKey.Kid,
		ks.nextKey.Kid,
		func() string {
			if ks.retiringKey != nil {
				return ks.retiringKey.Kid
			}
			return "none"
		}())

	return nil
}

// StartRotationScheduler runs a background goroutine that rotates keys on schedule.
func (ks *KeyStore) StartRotationScheduler() {
	go func() {
		ticker := time.NewTicker(ks.rotationPeriod)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ks.mu.RLock()
				timeSinceRotation := time.Since(ks.lastRotation)
				ks.mu.RUnlock()

				if timeSinceRotation >= ks.rotationPeriod {
					if err := ks.RotateKeys(); err != nil {
						log.Printf("[KEY-ROTATION-ERROR] %v", err)
					}
				}
			case <-ks.rotationTickerC:
				// Manual rotation trigger
				if err := ks.RotateKeys(); err != nil {
					log.Printf("[KEY-ROTATION-ERROR] manual trigger failed: %v", err)
				}
			}
		}
	}()
}

// TriggerRotation manually triggers an immediate key rotation.
func (ks *KeyStore) TriggerRotation() {
	select {
	case ks.rotationTickerC <- struct{}{}:
	default:
		// Channel full, skip
	}
}

// save persists keys to disk as JSON.
func (ks *KeyStore) save() error {
	keys := map[string]interface{}{
		"current_version": ks.currentKey.Version,
		"current_kid":     ks.currentKey.Kid,
		"current_key":     ks.currentKey,
		"next_version":    ks.nextKey.Version,
		"next_kid":        ks.nextKey.Kid,
		"next_key":        ks.nextKey,
		"last_rotation":   ks.lastRotation,
	}
	if ks.retiringKey != nil {
		keys["retiring_key"] = ks.retiringKey
	}

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}

	// Write with restricted permissions (owner read/write only)
	keyFile := ks.keysDir + "/keys.json"
	if err := os.WriteFile(keyFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write keys file: %w", err)
	}

	return nil
}

// load restores keys from disk.
func (ks *KeyStore) load() error {
	keyFile := ks.keysDir + "/keys.json"
	data, err := os.ReadFile(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("keys file not found")
		}
		return err
	}

	var keysData map[string]interface{}
	if err := json.Unmarshal(data, &keysData); err != nil {
		return fmt.Errorf("failed to unmarshal keys: %w", err)
	}

	// Parse current key
	if currentKeyRaw, ok := keysData["current_key"]; ok {
		currentKeyJSON, _ := json.Marshal(currentKeyRaw)
		var currentKey SigningKey
		if err := json.Unmarshal(currentKeyJSON, &currentKey); err == nil {
			ks.currentKey = &currentKey
		}
	}

	// Parse next key
	if nextKeyRaw, ok := keysData["next_key"]; ok {
		nextKeyJSON, _ := json.Marshal(nextKeyRaw)
		var nextKey SigningKey
		if err := json.Unmarshal(nextKeyJSON, &nextKey); err == nil {
			ks.nextKey = &nextKey
		}
	}

	// Parse retiring key (optional)
	if retiringKeyRaw, ok := keysData["retiring_key"]; ok {
		retiringKeyJSON, _ := json.Marshal(retiringKeyRaw)
		var retiringKey SigningKey
		if err := json.Unmarshal(retiringKeyJSON, &retiringKey); err == nil {
			ks.retiringKey = &retiringKey
		}
	}

	// Parse last rotation time
	if lastRotationRaw, ok := keysData["last_rotation"]; ok {
		if lastRotationStr, ok := lastRotationRaw.(string); ok {
			if t, err := time.Parse(time.RFC3339, lastRotationStr); err == nil {
				ks.lastRotation = t
			}
		}
	}

	if ks.currentKey == nil || ks.nextKey == nil {
		return fmt.Errorf("keys not fully loaded")
	}

	return nil
}

// DecodePrivateKey deserializes a signing key's private RSA key.
func (sk *SigningKey) DecodePrivateKey() (*rsa.PrivateKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(sk.PrivateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(keyBytes)
}

// DecodePublicKey deserializes a signing key's public RSA key.
func (sk *SigningKey) DecodePublicKey() (*rsa.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(sk.PublicKey)
	if err != nil {
		return nil, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, err
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return rsaPubKey, nil
}

// randomHex generates a random hex string of n bytes.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", b)
}
