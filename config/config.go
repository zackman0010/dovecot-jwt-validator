// Package config handles reading the application's key=value config file and
// resolving the JWKS URI from the OpenID Connect discovery document.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// DefaultConfigPath is the config file location used when no --config flag is
// passed. In Go, package-level constants are declared with const.
const DefaultConfigPath = "jwks.conf"

// Config is a plain data-holding struct — equivalent to a Kotlin data class.
// Exported fields (capitalised) are accessible from other packages; unexported
// fields (lowercase) would be package-private.
type Config struct {
	OIDCUrl    string // raw value of oidc_url from the config file
	JWKSUri    string // resolved from the OpenID configuration document
	SocketPath string
	ClientID   string // optional; empty means azp validation is skipped
	Scopes     string // space-separated required scopes; defaults to "openid email"
	Debug      bool   // optional; enables verbose request/response logging
}

// Load reads a key=value config file at the given path, fetches the OpenID
// configuration document at the URL found under "oidc_url", and extracts the
// jwks_uri from the response.
//
// Required keys: oidc_url, socket_path
// Optional keys: client_id
//
// The *Config return type is a pointer to a Config — equivalent to returning a
// nullable reference in Kotlin. Go never implicitly dereferences pointers;
// callers use cfg.Field to access fields (the compiler handles the dereference).
func Load(path string) (*Config, error) {
	values, err := parseKeyValue(path)
	if err != nil {
		return nil, err
	}

	oidcURL := values["oidc_url"]
	if oidcURL == "" {
		return nil, fmt.Errorf("config file %s does not contain a non-empty 'oidc_url' key", path)
	}

	socketPath := values["socket_path"]
	if socketPath == "" {
		return nil, fmt.Errorf("config file %s does not contain a non-empty 'socket_path' key", path)
	}

	jwksUri, err := fetchJWKSUri(oidcURL)
	if err != nil {
		return nil, err
	}

	// &Config{...} allocates a Config on the heap and returns a pointer to it,
	// equivalent to Config(...) returning a reference in Kotlin.
	scopes := values["scopes"]
	if scopes == "" {
		scopes = "openid email"
	}

	return &Config{
		OIDCUrl:    oidcURL,
		JWKSUri:    jwksUri,
		SocketPath: socketPath,
		ClientID:   values["client_id"], // missing key returns "" (zero value for string)
		Scopes:     scopes,
		Debug:      values["debug"] == "true",
	}, nil
}

// parseKeyValue reads a key=value file, ignoring blank lines and '#' comments.
// It returns a map[string]string — equivalent to Map<String, String> in Kotlin.
func parseKeyValue(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file %s: %w", path, err)
	}
	// defer schedules f.Close() to run when this function returns, regardless
	// of which return path is taken — similar to Kotlin's use {} block or
	// try-with-resources in Java.
	defer f.Close()

	// make() initialises a map — equivalent to mutableMapOf() in Kotlin.
	values := make(map[string]string)

	// bufio.Scanner reads the file line by line without loading it all into
	// memory at once, similar to BufferedReader.lineSequence() in Kotlin.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strings.Cut splits on the first occurrence of "=" and returns
		// (before, after, found) — similar to partition in Kotlin.
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		values[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	return values, nil
}

// fetchJWKSUri GETs the OpenID configuration URL and returns the jwks_uri claim.
func fetchJWKSUri(oidcURL string) (string, error) {
	resp, err := http.Get(oidcURL)
	if err != nil {
		return "", fmt.Errorf("fetching OpenID configuration from %s: %w", oidcURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetching OpenID configuration from %s: HTTP %d", oidcURL, resp.StatusCode)
	}

	// An anonymous struct used purely as a local JSON shape — equivalent to a
	// one-off Kotlin data class defined inside a function. The `json:"jwks_uri"`
	// tag tells the JSON decoder which JSON field maps to this struct field.
	var doc struct {
		JWKSUri string `json:"jwks_uri"`
	}
	// json.NewDecoder streams the response body directly into the struct
	// without buffering the whole body first.
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("parsing OpenID configuration response: %w", err)
	}

	if doc.JWKSUri == "" {
		return "", fmt.Errorf("OpenID configuration at %s does not contain a non-empty 'jwks_uri'", oidcURL)
	}

	return doc.JWKSUri, nil
}
