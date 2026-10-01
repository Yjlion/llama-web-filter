// Package pwhash implements the PBKDF2-SHA256 password hashing used for
// both the management login password and the proxy's own HTTP Basic auth
// password, in the exact format the Python original uses:
//
//	pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
//
// (This happens to be the same shape as Django's password hash format.)
package pwhash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	iterations = 200_000
	saltBytes  = 16
	keyBytes   = sha256.Size
)

// Hash derives a new PBKDF2-SHA256 hash for password with a fresh random
// salt, formatted as "pbkdf2_sha256$<iters>$<salt_hex>$<hash_hex>".
func Hash(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	dk := pbkdf2.Key([]byte(password), salt, iterations, keyBytes, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", iterations, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// Verify checks password against a hash produced by Hash (or by the Python
// original, which uses the identical format/parameters). Uses a
// timing-safe comparison. Returns false (never an error) for a malformed
// stored value, so callers can treat any failure uniformly as "wrong
// password" without a separate error-handling path.
func Verify(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2.Key([]byte(password), salt, iters, len(want), sha256.New)
	return hmac.Equal(got, want)
}
