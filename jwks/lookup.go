// Package jwks fetches public keys from a JWKS endpoint and returns them as
// PEM-encoded X.509 certificates. Results are cached in memory for 15 minutes
// to avoid making an HTTP request on every Dovecot key lookup.
package jwks

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	maxResponseBytes = 1 << 20 // 1 MB — cap to guard against malformed responses
	cacheTTL         = 15 * time.Minute
)

// client is a package-level singleton — equivalent to a companion object
// property in Kotlin. Reusing a single http.Client means the underlying TCP
// connections to the JWKS endpoint are pooled and reused across requests.
var client = &http.Client{}

// cacheEntry holds a cached PEM certificate and the time it expires.
type cacheEntry struct {
	pem     string
	expires time.Time
}

// cacheMu is a read/write mutex — it allows many concurrent readers or one
// writer at a time, equivalent to java.util.concurrent.locks.ReadWriteLock.
// cache is the underlying map it protects.
var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)
)

// jwksResponse mirrors the top-level structure of a JWKS JSON document.
// The `json:"keys"` struct tag tells the decoder to map the JSON field "keys"
// to this Go field — equivalent to @JsonProperty("keys") in Kotlin/Jackson.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// jwk represents a single JSON Web Key. Only the fields we actually use are
// declared; the JSON decoder silently ignores any additional fields in the
// response — equivalent to ignoring unknown properties in Jackson.
type jwk struct {
	Kid string   `json:"kid"`
	Alg string   `json:"alg"`
	X5C []string `json:"x5c"`
}

// LookupX5C returns the PEM certificate for the key matching both kid and alg.
// Results are cached for 15 minutes. Returns ("", nil) when no match is found.
// Returns a non-nil error on network or parse failures.
func LookupX5C(jwksUri, kid, alg string) (string, error) {
	// Build a cache key from the two lookup dimensions.
	cacheKey := alg + "/" + kid
	if pem, ok := cacheGet(cacheKey); ok {
		return pem, nil
	}

	resp, err := client.Get(jwksUri)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", jwksUri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned HTTP %d", jwksUri, resp.StatusCode)
	}

	// io.LimitReader wraps the response body so that at most maxResponseBytes
	// are read — guards against a runaway response exhausting memory.
	// io.ReadAll then reads all of those bytes into a []byte (byte slice),
	// equivalent to ByteArray in Kotlin.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("reading JWKS response body: %w", err)
	}

	// json.Unmarshal deserialises the byte slice into the jwksResponse struct.
	// Note the "&jwks" — we pass a pointer so the function can populate the
	// struct in place, equivalent to passing by reference.
	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return "", fmt.Errorf("parsing JWKS JSON: %w", err)
	}

	// Range over the keys slice. The blank identifier "_" discards the index
	// (equivalent to Kotlin's forEach { key -> ... } where you don't need "it").
	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Alg == alg {
			if len(key.X5C) == 0 {
				return "", fmt.Errorf("key kid=%q alg=%q has an empty x5c array", kid, alg)
			}
			pub, err := extractPublicKeyPEM(key.X5C[0])
			if err != nil {
				return "", fmt.Errorf("key kid=%q alg=%q: %w", kid, alg, err)
			}
			cacheSet(cacheKey, pub)
			return pub, nil
		}
	}

	return "", nil // no matching key — caller sends N
}

// cacheGet retrieves a cache entry if it exists and has not expired.
// It holds only a read lock (RLock/RUnlock) so concurrent reads do not block
// each other — equivalent to ReadWriteLock.readLock().lock() in Java.
func cacheGet(key string) (string, bool) {
	cacheMu.RLock()
	entry, ok := cache[key]
	cacheMu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return "", false
	}
	return entry.pem, true
}

// cacheSet stores a PEM certificate under the given key with a 15-minute TTL.
// It holds an exclusive write lock so no other goroutine reads or writes the
// map while it is being updated — equivalent to ReadWriteLock.writeLock().lock().
func cacheSet(key, pem string) {
	cacheMu.Lock()
	cache[key] = cacheEntry{pem: pem, expires: time.Now().Add(cacheTTL)}
	cacheMu.Unlock()
}

// extractPublicKeyPEM decodes a base64-encoded DER certificate from a JWK x5c
// array entry, parses the X.509 certificate, and returns the public key as a
// PEM-encoded PKIX public key block ("-----BEGIN PUBLIC KEY-----").
//
// Dovecot's dcrypt library expects a "BEGIN PUBLIC KEY" (SubjectPublicKeyInfo)
// PEM block for local JWT validation key loading.
func extractPublicKeyPEM(b64cert string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(b64cert)
	if err != nil {
		return "", fmt.Errorf("decoding x5c base64: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parsing x5c certificate: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshalling public key: %w", err)
	}

	block := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(block), nil
}