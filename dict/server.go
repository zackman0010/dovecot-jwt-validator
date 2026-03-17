// Package dict implements the Dovecot Dict protocol server over a Unix domain
// socket. It handles version negotiation (HELLO) and key lookups (LOOKUP).
package dict

import (
	"bufio"
	"dovecot-jwt-validator/jwks"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// Server holds the configuration needed to run the Dict protocol listener.
// In Go, methods are attached to types rather than defined inside a class body.
// The receiver (s *Server) below is roughly equivalent to "this" in Kotlin.
type Server struct {
	SocketPath    string
	JWKSUri       string
	OAuthClientID string
}

// ListenAndServe removes any stale socket file, binds the Unix domain socket,
// and blocks in an accept loop. Each accepted connection is handled in its own
// goroutine so the loop is never stalled by slow clients.
func (s *Server) ListenAndServe() error {
	// Remove a leftover socket file from a previous run. Unix sockets are
	// represented as filesystem entries; net.Listen will fail if the path
	// already exists, so we clean it up first.
	if err := os.Remove(s.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %s: %w", s.SocketPath, err)
	}

	// net.Listen("unix", path) is the Go equivalent of creating a
	// ServerSocketChannel bound to a Unix domain socket path in Java/Kotlin.
	ln, err := net.Listen("unix", s.SocketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.SocketPath, err)
	}
	defer ln.Close()

	log.Printf("listening on %s", s.SocketPath)

	// Infinite accept loop — runs until the process is killed or ln is closed.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		// "go" launches handleConnection in a new goroutine — a lightweight
		// thread managed by the Go runtime, similar to launching a Kotlin
		// coroutine with launch{}. Each connection gets its own goroutine so
		// they are all handled concurrently without blocking each other.
		go s.handleConnection(conn)
	}
}

// handleConnection reads lines from a single Dovecot connection and dispatches
// each command to the appropriate handler. It runs in its own goroutine.
func (s *Server) handleConnection(conn net.Conn) {
	// defer conn.Close() ensures the connection is closed when this function
	// returns, no matter which code path exits — like Kotlin's use {} block.
	defer conn.Close()

	// bufio.NewScanner wraps the connection in a buffered line reader,
	// equivalent to BufferedReader(InputStreamReader(socket.getInputStream()))
	// in Java. scanner.Scan() blocks until a full line is available.
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		// The Dovecot Dict protocol prefixes each command with a single
		// character. line[0] indexes the first byte of the string — Go
		// strings are byte slices, so this gives us the ASCII value.
		// The switch compares against character literals ('H', 'L').
		switch line[0] {
		case 'H': // HELLO — version negotiation
			// handleHello returns false if the version is rejected, in which
			// case we return from this function, triggering defer conn.Close().
			if !s.handleHello(conn, line) {
				return
			}
		case 'L': // LOOKUP — key fetch
			s.handleLookup(conn, line)
		default:
			// Unknown or unimplemented command (e.g. ITERATE)
			fmt.Fprintf(conn, "FUnsupported command\n")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("connection read error: %v", err)
	}
}

// handleHello parses the HELLO line, validates the version, and writes the
// server response. Returns false if the version is unsupported, in which case
// the caller should close the connection.
//
// HELLO format: H<major>\t<minor>\t<valueType>\t<obsolete>\t<dictName>
// Supported versions: 3.2 and 4.0
func (s *Server) handleHello(conn net.Conn, line string) bool {
	// strings.Split is equivalent to Kotlin's split(). It returns a []string
	// (string slice) — Go's equivalent of List<String>.
	parts := strings.Split(line, "\t")
	if len(parts) < 2 {
		log.Printf("malformed HELLO: %q", line)
		fmt.Fprintf(conn, "FMalformed command\n")
		return false
	}

	// line[0] is 'H'; the major version digits follow immediately with no
	// separator, so we slice from index 1 onward. In Go, string slicing uses
	// the same [start:end] syntax as Kotlin but operates on bytes, not chars.
	major := parts[0][1:] // strip leading 'H'
	minor := parts[1]

	if !isSupportedVersion(major, minor) {
		log.Printf("unsupported dict protocol version %s.%s, closing connection", major, minor)
		fmt.Fprintf(conn, "FUnsupported version\n")
		return false
	}

	// fmt.Fprintf writes a formatted string to any io.Writer — conn satisfies
	// that interface because net.Conn has a Write method. Equivalent to
	// PrintWriter(socket.getOutputStream()).printf(...) in Java.
	fmt.Fprintf(conn, "O\t%s\t%s\n", major, minor)
	return true
}

// isSupportedVersion reports whether the given major.minor version pair is
// one of the versions this server supports (3.2 or 4.0).
//
// Go's switch does not fall through by default (unlike Java/Kotlin), and the
// expressionless "switch {}" form evaluates each case as a boolean condition —
// equivalent to a chain of if/else if in Kotlin.
func isSupportedVersion(major, minor string) bool {
	switch {
	case major == "3" && minor == "2":
		return true
	case major == "4" && minor == "0":
		return true
	default:
		return false
	}
}

// handleLookup parses a LOOKUP line and writes the Dict response.
//
// LOOKUP format: L<key>\t<user>
// Key format:    /shared/<azp>/<alg>/<kid>
//
// The azp is validated against the configured OAuthClientID. The alg and kid
// are used together to find the matching key in the JWKS response.
func (s *Server) handleLookup(conn net.Conn, line string) {
	// Record the start time immediately — this is the beginning of the lookup
	// as far as Dovecot is concerned.
	start := time.Now()

	// line[1:] slices off the leading 'L', giving us "<key>\t<user>".
	// SplitN limits the split to at most 2 parts so a tab inside the user
	// field wouldn't cause extra splits — equivalent to split("\t", 2) in Kotlin.
	parts := strings.SplitN(line[1:], "\t", 2)
	if len(parts) < 1 || parts[0] == "" {
		fmt.Fprintf(conn, "FMalformed command\n")
		return
	}

	// Go supports multiple return values. parseKey returns four values;
	// "ok" is a boolean idiom for "did this succeed?" — common in Go
	// for operations that may or may not produce a result.
	azp, alg, kid, ok := parseKey(parts[0])
	if !ok {
		log.Printf("malformed lookup key: %q", parts[0])
		fmt.Fprintf(conn, "FMalformed key\n")
		return
	}

	// Only validate azp if a client ID was configured. An empty OAuthClientID
	// means validation is intentionally skipped.
	if s.OAuthClientID != "" && azp != s.OAuthClientID {
		log.Printf("azp %q does not match configured oauth_client_id", azp)
		end := time.Now()
		fmt.Fprintf(conn, "N%s", timingFields(start, end))
		return
	}

	cert, err := jwks.LookupX5C(s.JWKSUri, kid, alg)
	if err != nil {
		log.Printf("JWKS lookup error for kid=%q alg=%q: %v", kid, alg, err)
		fmt.Fprintf(conn, "FUnable to fetch JWKS URL\n")
		return
	}

	end := time.Now()

	if cert == "" {
		fmt.Fprintf(conn, "N%s", timingFields(start, end))
		return
	}

	fmt.Fprintf(conn, "O%s%s", dictEscape(cert), timingFields(start, end))
}

// dictEscape applies the Dovecot Dict protocol value escaping rules.
// The escape character is \001; the following characters are replaced:
//
//	\001 → \001 + '1'   (must be first to avoid double-escaping)
//	NUL  → \001 + '0'
//	\t   → \001 + 't'
//	\r   → \001 + 'r'
//	\n   → \001 + 'l'
func dictEscape(s string) string {
	// strings.NewReplacer applies all substitutions in a single pass, but
	// because \001 must be replaced before the others we use a manual builder
	// to guarantee ordering.
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\x01':
			sb.WriteString("\x01" + "1")
		case '\x00':
			sb.WriteString("\x01" + "0")
		case '\t':
			sb.WriteString("\x01" + "t")
		case '\r':
			sb.WriteString("\x01" + "r")
		case '\n':
			sb.WriteString("\x01" + "l")
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// timingFields formats start and end times as the tab-separated timestamp
// suffix the Dovecot Dict protocol appends to LOOKUP responses:
//
//	\t<startSecond>\t<startUSecond>\t<endSecond>\t<endUSecond>\n
//
// Each timestamp is split into its Unix seconds component and its microseconds
// component (the sub-second remainder, 0–999999).
func timingFields(start, end time.Time) string {
	startSec := start.Unix()
	startUsec := int64(start.Nanosecond()) / 1000
	endSec := end.Unix()
	endUsec := int64(end.Nanosecond()) / 1000
	return fmt.Sprintf("\t%d\t%d\t%d\t%d\n", startSec, startUsec, endSec, endUsec)
}

// parseKey parses a key in the form /shared/<azp>/<alg>/<kid> and returns its
// components. ok is false if the key does not match the expected structure.
//
// Named return values (azp, alg, kid string, ok bool) are declared here for
// documentation clarity; they are assigned explicitly in the return statements
// rather than relying on Go's "naked return" feature.
func parseKey(key string) (azp, alg, kid string, ok bool) {
	// Splitting "/shared/foo/RS256/key1" on "/" gives:
	// ["", "shared", "foo", "RS256", "key1"] — 5 elements with an empty
	// first element because the string starts with "/".
	parts := strings.Split(key, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "shared" {
		return "", "", "", false
	}
	azp, alg, kid = parts[2], parts[3], parts[4]
	if azp == "" || alg == "" || kid == "" {
		return "", "", "", false
	}
	return azp, alg, kid, true
}