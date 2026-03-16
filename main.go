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
	"strings"
)

// //go:embed is a compiler directive that reads the file at build time and
// stores its contents in the variable below. The template is baked into the
// binary — no separate file needs to be deployed alongside it.
//
//go:embed dovecot-oauth-conf.template
var configTemplate string

// main() is the entry point, equivalent to fun main() in Kotlin.
func main() {
	// The flag package is Go's equivalent of a basic CLI argument parser.
	// flag.String registers a string flag and returns a *string (pointer).
	// The arguments are: flag name, default value, help text.
	configPath := flag.String("config", config.DefaultConfigPath, "path to the key=value config file")
	outputPath := flag.String("output", "/etc/dovecot/dovecot-oauth2.conf.ext", "path to write the rendered Dovecot OAuth2 config")
	// flag.Parse() actually reads os.Args and populates the registered flags.
	flag.Parse()

	// Go functions commonly return (value, error) pairs instead of throwing
	// exceptions. The convention is to check err immediately after the call.
	// *configPath dereferences the pointer returned by flag.String above.
	cfg, err := config.Load(*configPath)
	if err != nil {
		// log.Fatalf prints the message and calls os.Exit(1) — equivalent to
		// throwing an unrecovered exception that terminates the process.
		log.Fatalf("configuration error: %v", err)
	}

	if err := renderTemplate(*outputPath, cfg); err != nil {
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

// renderTemplate substitutes ${oidc_url} and ${socket_path} placeholders in
// the embedded template, then writes the result to the destination path.
//
// In Go, functions are declared with func, return types come after the
// parameter list, and multiple return values are common (here: nothing + error).
func renderTemplate(dst string, cfg *config.Config) error {
	// strings.NewReplacer takes pairs of (old, new) strings and applies all
	// substitutions in a single pass — similar to calling replace() chained
	// in Kotlin but more efficient.
	replacer := strings.NewReplacer(
		"${oidc_url}",    cfg.OIDCUrl,
		"${socket_path}", cfg.SocketPath,
	)
	rendered := replacer.Replace(configTemplate)

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

	log.Printf("wrote Dovecot OAuth2 config to %s", dst)
	return nil // nil is Go's equivalent of returning null for an error — means "no error"
}