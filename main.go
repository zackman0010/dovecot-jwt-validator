package main

// In Go, every file belongs to a package. The special package name "main"
// marks this as an executable entry point — equivalent to a Kotlin file with
// a top-level fun main().

import (
	"dovecot-jwt-validator/config"
	"dovecot-jwt-validator/dict"
	_ "embed" // blank import — imported solely for its side effect of enabling //go:embed directives
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Both templates are compiled into the binary at build time. The correct one
// is selected at runtime based on the detected Dovecot version.
//
//go:embed dovecot-oauth-conf-2.3.template
var configTemplate23 string

//go:embed dovecot-oauth-conf-2.4.template
var configTemplate24 string

// main() is the entry point, equivalent to fun main() in Kotlin.
func main() {
	// The flag package is Go's equivalent of a basic CLI argument parser.
	// flag.String registers a string flag and returns a *string (pointer).
	// The arguments are: flag name, default value, help text.
	configPath := flag.String("config", config.DefaultConfigPath, "path to the key=value config file")
	outputPath := flag.String("output", "dovecot-oauth2.conf.ext", "path to write the rendered Dovecot OAuth2 config")
	// flag.Parse() actually reads os.Args and populates the registered flags.
	flag.Parse()

	// Resolve relative paths against the systemd-managed directories exposed
	// via environment variables, so the binary works without explicit flags
	// when started by systemd.
	resolvedConfig := resolvePath(*configPath, "CONFIGURATION_DIRECTORY")
	resolvedOutput := resolvePath(*outputPath, "STATE_DIRECTORY")

	// Go functions commonly return (value, error) pairs instead of throwing
	// exceptions. The convention is to check err immediately after the call.
	cfg, err := config.Load(resolvedConfig)
	if err != nil {
		// log.Fatalf prints the message and calls os.Exit(1) — equivalent to
		// throwing an unrecovered exception that terminates the process.
		log.Fatalf("configuration error: %v", err)
	}

	// Resolve the socket path from the config file against RUNTIME_DIRECTORY.
	cfg.SocketPath = resolvePath(cfg.SocketPath, "RUNTIME_DIRECTORY")

	major, minor, patch, err := dovecotVersion()
	if err != nil {
		log.Fatalf("detecting Dovecot version: %v", err)
	}
	log.Printf("detected Dovecot version %d.%d.%d", major, minor, patch)

	if err := validateDovecotVersion(major, minor, patch); err != nil {
		log.Fatalf("version check failed: %v", err)
	}

	if err := renderTemplate(resolvedOutput, cfg, major, minor); err != nil {
		log.Fatalf("rendering output config: %v", err)
	}

	// Struct literal with named fields — equivalent to a Kotlin data class
	// constructor call with named arguments.
	srv := &dict.Server{
		SocketPath:    cfg.SocketPath,
		JWKSUri:       cfg.JWKSUri,
		OAuthClientID: cfg.ClientID,
	}

	// ListenAndServe blocks indefinitely (accept loop). If it ever returns,
	// something has gone wrong, so we treat the error as fatal.
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// resolvePath returns path unchanged if it is absolute (starts with /);
// otherwise it is joined with the directory named by envVar, falling back to
// the current working directory if the environment variable is not set.
func resolvePath(path, envVar string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if dir := os.Getenv(envVar); dir != "" {
		return filepath.Join(dir, path)
	}
	return path
}

// dovecotVersion runs "dovecot --version" and returns the major, minor, and
// patch version numbers. The output format is "2.3.21 (abc123ef4)" — we parse
// the first three dot-separated components.
//
// exec.Command is Go's equivalent of ProcessBuilder in Java/Kotlin.
// Output() runs the command and returns its stdout as a []byte.
func dovecotVersion() (major, minor, patch int, err error) {
	out, err := exec.Command("dovecot", "--version").Output()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("running 'dovecot --version': %w", err)
	}

	// strings.Fields splits on any whitespace — equivalent to Kotlin's split("\\s+".toRegex()).
	// The version string is the first token, e.g. "2.3.21".
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return 0, 0, 0, fmt.Errorf("unexpected empty output from 'dovecot --version'")
	}

	parts := strings.SplitN(fields[0], ".", 3)
	if len(parts) < 3 {
		return 0, 0, 0, fmt.Errorf("cannot parse version %q", fields[0])
	}

	// strconv.Atoi converts a string to an int — equivalent to toInt() in Kotlin.
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("cannot parse major version from %q", fields[0])
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("cannot parse minor version from %q", fields[0])
	}
	patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("cannot parse patch version from %q", fields[0])
	}

	return major, minor, patch, nil
}

// validateDovecotVersion returns an error if the given version is older than
// 2.3.17, which is the minimum version that supports the required dict protocol.
func validateDovecotVersion(major, minor, patch int) error {
	// Compare as a single integer triplet for clarity.
	// 2.3.17 → major=2, minor=3, patch=17
	const (
		minMajor = 2
		minMinor = 3
		minPatch = 17
	)
	if major > minMajor {
		return nil
	}
	if major == minMajor && minor > minMinor {
		return nil
	}
	if major == minMajor && minor == minMinor && patch >= minPatch {
		return nil
	}
	//goland:noinspection GoErrorStringFormat
	return fmt.Errorf(
		"Dovecot %d.%d.%d is not supported; minimum required version is %d.%d.%d",
		major, minor, patch, minMajor, minMinor, minPatch,
	)
}

// renderTemplate selects the appropriate embedded template for the detected
// Dovecot version, substitutes ${oidc_url} and ${socket_path}, and writes the
// result to the destination path.
//
// In Go, functions are declared with func, return types come after the
// parameter list, and multiple return values are common (here: nothing + error).
func renderTemplate(dst string, cfg *config.Config, major, minor int) error {
	// Select the template based on Dovecot's major.minor version.
	// Dovecot 2.3 uses a flat key; 2.4+ uses a nested block syntax.
	var tmpl string
	if major < 2 || (major == 2 && minor <= 3) {
		tmpl = configTemplate23
	} else {
		tmpl = configTemplate24
	}

	// strings.NewReplacer takes pairs of (old, new) strings and applies all
	// substitutions in a single pass — similar to calling replace() chained
	// in Kotlin but more efficient.
	replacer := strings.NewReplacer(
		"${oidc_url}", cfg.OIDCUrl,
		"${socket_path}", cfg.SocketPath,
		"${scopes}", cfg.Scopes,
	)
	rendered := replacer.Replace(tmpl)

	// Remove the existing file if present so we always write a fresh copy.
	// os.IsNotExist lets us ignore the error when the file simply didn't exist
	// yet — equivalent to catching a FileNotFoundException and discarding it.
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing existing output file %s: %w", dst, err)
	}

	// 0640 is a Unix permission octet: owner read/write, group read, others none.
	if err := os.WriteFile(dst, []byte(rendered), 0640); err != nil {
		return fmt.Errorf("writing output file %s: %w", dst, err)
	}

	log.Printf("wrote Dovecot %d.%d OAuth2 config to %s", major, minor, dst)
	return nil // nil is Go's equivalent of returning null for an error — means "no error"
}
