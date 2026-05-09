package proxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Authorizer decides whether a SOCKS5 client may use the proxy.
//
// AuthLoginPassword is consulted only when ShouldAuth returns true; the
// implementation is responsible for constant-time credential comparison.
type Authorizer interface {
	ShouldAuth() bool
	AuthLoginPassword(ctx context.Context, login string, password []byte) bool
}

// NoAuth grants every connection unconditionally. ShouldAuth returns false.
type NoAuth struct{}

// ShouldAuth implements Authorizer.
func (NoAuth) ShouldAuth() bool { return false }

// AuthLoginPassword implements Authorizer; always true (auth disabled).
func (NoAuth) AuthLoginPassword(context.Context, string, []byte) bool { return true }

// argon2idParams describes a hash; values are taken from the encoded PHC
// string and used to recompute the hash for verification.
type argon2idParams struct {
	memory      uint32
	timeCost    uint32
	parallelism uint8
	salt        []byte
	hash        []byte
}

// ArgonAuth is an Authorizer backed by argon2id PHC-encoded password hashes.
//
// Each user's stored credential is the standard PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
//
// AuthLoginPassword computes argon2id over the supplied password using the
// same parameters and salt extracted from the stored hash, then compares in
// constant time.
type ArgonAuth struct {
	enabled bool
	users   map[string]argon2idParams
}

// NewArgonAuth parses each stored credential and returns an authorizer ready
// for use. enabled toggles whether ShouldAuth returns true; when false the
// authorizer behaves like NoAuth (and an empty users map is acceptable).
func NewArgonAuth(enabled bool, users map[string]string) (*ArgonAuth, error) {
	parsed := make(map[string]argon2idParams, len(users))
	for login, encoded := range users {
		p, err := parsePHC(encoded)
		if err != nil {
			return nil, fmt.Errorf("auth: user %q: %w", login, err)
		}
		parsed[login] = p
	}
	return &ArgonAuth{enabled: enabled, users: parsed}, nil
}

// ShouldAuth implements Authorizer.
func (a *ArgonAuth) ShouldAuth() bool { return a.enabled }

// AuthLoginPassword implements Authorizer with constant-time credential
// comparison. To avoid leaking which logins exist, the function performs a
// dummy hash even when the login is unknown so timing across cases is
// equivalent.
func (a *ArgonAuth) AuthLoginPassword(_ context.Context, login string, password []byte) bool {
	if !a.enabled {
		return true
	}
	stored, ok := a.users[login]
	if !ok {
		// Defeat user-existence timing oracle by performing equivalent work
		// with the same salt length and hash output size used for real users.
		dummySalt := make([]byte, defaultSaltLen)
		argon2.IDKey(password, dummySalt, defaultTime, defaultMemory, defaultParallelism, defaultHashLen)
		return false
	}
	candidate := argon2.IDKey(
		password,
		stored.salt,
		stored.timeCost,
		stored.memory,
		stored.parallelism,
		uint32(len(stored.hash)),
	)
	return subtle.ConstantTimeCompare(candidate, stored.hash) == 1
}

// Argon2id parameter defaults used by HashPassword. These values are picked
// to take roughly 50 ms on a modern server CPU and consume 64 MiB of memory
// per verification — strong enough for password hashing in 2026 while
// keeping per-auth latency acceptable.
const (
	defaultTime        uint32 = 3
	defaultMemory      uint32 = 64 * 1024 // KiB → 64 MiB
	defaultParallelism uint8  = 4
	defaultSaltLen            = 16
	defaultHashLen     uint32 = 32
)

// HashPassword derives an argon2id hash for password and returns the PHC
// string. The salt is generated from crypto/rand.
func HashPassword(password []byte) (string, error) {
	salt := make([]byte, defaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	hash := argon2.IDKey(password, salt, defaultTime, defaultMemory, defaultParallelism, defaultHashLen)
	return encodePHC(argon2idParams{
		memory:      defaultMemory,
		timeCost:    defaultTime,
		parallelism: defaultParallelism,
		salt:        salt,
		hash:        hash,
	}), nil
}

func encodePHC(p argon2idParams) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.memory,
		p.timeCost,
		p.parallelism,
		base64.RawStdEncoding.EncodeToString(p.salt),
		base64.RawStdEncoding.EncodeToString(p.hash),
	)
}

// Argon2id parameter ceilings enforced when parsing PHC strings. Without
// caps, a malicious or corrupted config could request multi-terabyte memory
// or year-long iterations, turning each auth attempt into a DoS.
const (
	maxArgon2Memory      uint32 = 4 * 1024 * 1024 // 4 GiB (in KiB)
	maxArgon2TimeCost    uint32 = 100
	maxArgon2Parallelism uint8  = 64
	maxArgon2SaltLen            = 64
	maxArgon2HashLen            = 64
)

var (
	errPHCFormat  = errors.New("invalid PHC format")
	errPHCAlgo    = errors.New("not an argon2id hash")
	errPHCVersion = errors.New("unsupported argon2 version")
	errPHCParams  = errors.New("argon2id parameters out of range")
)

// parsePHC decodes a PHC argon2id string. It accepts both raw (unpadded)
// and padded base64 to be liberal in input.
func parsePHC(s string) (argon2idParams, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" {
		return argon2idParams{}, errPHCFormat
	}
	if parts[1] != "argon2id" {
		return argon2idParams{}, errPHCAlgo
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2idParams{}, fmt.Errorf("%w: %v", errPHCFormat, err)
	}
	if version != argon2.Version {
		return argon2idParams{}, errPHCVersion
	}
	var m uint32
	var t uint32
	var pCost uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &pCost); err != nil {
		return argon2idParams{}, fmt.Errorf("%w: params: %v", errPHCFormat, err)
	}
	if m == 0 || m > maxArgon2Memory {
		return argon2idParams{}, fmt.Errorf("%w: memory %d", errPHCParams, m)
	}
	if t == 0 || t > maxArgon2TimeCost {
		return argon2idParams{}, fmt.Errorf("%w: time cost %d", errPHCParams, t)
	}
	if pCost == 0 || pCost > maxArgon2Parallelism {
		return argon2idParams{}, fmt.Errorf("%w: parallelism %d", errPHCParams, pCost)
	}
	salt, err := decodeB64(parts[4])
	if err != nil {
		return argon2idParams{}, fmt.Errorf("%w: salt: %v", errPHCFormat, err)
	}
	if len(salt) == 0 || len(salt) > maxArgon2SaltLen {
		return argon2idParams{}, fmt.Errorf("%w: salt length %d", errPHCParams, len(salt))
	}
	hash, err := decodeB64(parts[5])
	if err != nil {
		return argon2idParams{}, fmt.Errorf("%w: hash: %v", errPHCFormat, err)
	}
	if len(hash) == 0 || len(hash) > maxArgon2HashLen {
		return argon2idParams{}, fmt.Errorf("%w: hash length %d", errPHCParams, len(hash))
	}
	return argon2idParams{
		memory:      m,
		timeCost:    t,
		parallelism: pCost,
		salt:        salt,
		hash:        hash,
	}, nil
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
