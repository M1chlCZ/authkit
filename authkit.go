// Package authkit hashes and verifies passwords with Argon2id and derives
// opaque authentication tokens.
//
// Passwords use NFC normalization, and hashes use PHC encoding. Verify
// reports whether a stored hash must be replaced. VerifyLogin adds dummy work
// for ineligible or malformed accounts, so response time does not show
// whether an account exists. Token helpers encode 32 raw bytes as unpadded
// base64url and return the SHA-256 hash for storage.
package authkit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

const (
	// TokenBytes is the raw length of an authentication token.
	TokenBytes = 32

	maxPHCBytes       = 256
	passwordHashBytes = 32
	passwordMinRunes  = 15
	passwordMaxRunes  = 256
	passwordMaxBytes  = 1024
	defaultMemoryKiB  = 64 * 1024
	legacyMemoryKiB   = 32 * 1024
	argonIterations   = 3
	argonParallelism  = 4
)

const mailDomainSeparator = "authkit.mail-token\x00v1\x00"

// Mail token purposes accepted by DeriveMailToken.
const (
	PurposeVerifyEmail     = "verify_email"
	PurposeResetPassword   = "reset_password"
	PurposeActivateAccount = "activate_account"
)

// ErrInvalidPassword reports a password that fails the policy or normalization.
var ErrInvalidPassword = errors.New("password is invalid")

// Profile is an Argon2id cost profile.
type Profile struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

// DefaultProfile returns the current recommended Argon2id profile.
func DefaultProfile() Profile {
	return Profile{
		Memory: defaultMemoryKiB, Iterations: argonIterations, Parallelism: argonParallelism,
	}
}

// LegacyProfile returns the previous profile. Verify accepts hashes from this
// profile and reports that they require a rehash.
func LegacyProfile() Profile {
	return Profile{
		Memory: legacyMemoryKiB, Iterations: argonIterations, Parallelism: argonParallelism,
	}
}

func rawURLEncoding() *base64.Encoding {
	return base64.RawURLEncoding.Strict()
}

// Config configures a Hasher. Current is required. An empty Legacy disables
// legacy hash verification. A nil Random uses crypto/rand.
type Config struct {
	Current Profile
	Legacy  Profile
	Random  io.Reader
}

// DefaultConfig returns the default profiles and crypto/rand for randomness.
func DefaultConfig() Config {
	return Config{Current: DefaultProfile(), Legacy: LegacyProfile()}
}

// New builds a Hasher from the config.
func New(config Config) (*Hasher, error) {
	return newHasher(config.Current, config.Legacy, config.Random)
}

// Hasher hashes and verifies passwords. It is safe for concurrent use and
// runs one Argon2id operation at a time.
type Hasher struct {
	work      chan struct{}
	current   Profile
	legacy    Profile
	random    io.Reader
	dummySalt [16]byte
	dummyHash [passwordHashBytes]byte
}

func newHasher(current, legacy Profile, random io.Reader) (*Hasher, error) {
	if !validProfile(current) {
		return nil, errors.New("invalid password hasher configuration")
	}
	if legacy != (Profile{}) && (!validProfile(legacy) || legacy == current) {
		return nil, errors.New("invalid legacy password profile")
	}
	if random == nil {
		random = rand.Reader
	}
	hasher := &Hasher{work: make(chan struct{}, 1), current: current, legacy: legacy, random: random}
	copy(hasher.dummySalt[:], "authkitdummysalt")
	dummy := argon2.IDKey(
		[]byte("invalid-login-password"), hasher.dummySalt[:],
		current.Iterations, current.Memory, current.Parallelism, passwordHashBytes,
	)
	copy(hasher.dummyHash[:], dummy)
	return hasher, nil
}

func validProfile(profile Profile) bool {
	return profile.Memory > 0 && profile.Iterations > 0 && profile.Parallelism > 0
}

// EncodeToken checks that raw contains TokenBytes, returns the unpadded
// base64url form, and returns the SHA-256 hash for storage.
func EncodeToken(raw []byte) (string, [sha256.Size]byte, error) {
	if len(raw) != TokenBytes {
		return "", [sha256.Size]byte{}, errors.New("auth token must contain 32 bytes")
	}
	return rawURLEncoding().EncodeToString(raw), sha256.Sum256(raw), nil
}

// NewToken reads TokenBytes from random and returns the encoded token, the
// raw bytes, and the SHA-256 hash. A nil reader uses crypto/rand.
func NewToken(random io.Reader) (string, [TokenBytes]byte, [sha256.Size]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	var raw [TokenBytes]byte
	if _, err := io.ReadFull(random, raw[:]); err != nil {
		return "", raw, [sha256.Size]byte{}, errors.New("generate auth token")
	}
	encoded, hash, err := EncodeToken(raw[:])
	return encoded, raw, hash, err
}

// DecodeToken reverses EncodeToken with strict base64url decoding.
func DecodeToken(encoded string) ([TokenBytes]byte, [sha256.Size]byte, error) {
	var raw [TokenBytes]byte
	encoding := rawURLEncoding()
	if len(encoded) != encoding.EncodedLen(TokenBytes) {
		return raw, [sha256.Size]byte{}, errors.New("invalid auth token")
	}
	decoded, err := encoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(raw) || encoding.EncodeToString(decoded) != encoded {
		return raw, [sha256.Size]byte{}, errors.New("invalid auth token")
	}
	copy(raw[:], decoded)
	return raw, sha256.Sum256(raw[:]), nil
}

// DeriveMailToken returns a purpose-bound token for a UUIDv7 record. The
// secret must contain at least TokenBytes.
func DeriveMailToken(
	secret []byte,
	purpose string,
	tokenID uuid.UUID,
) (string, [sha256.Size]byte, error) {
	if len(secret) < TokenBytes ||
		purpose != PurposeVerifyEmail && purpose != PurposeResetPassword &&
			purpose != PurposeActivateAccount ||
		tokenID.Version() != 7 ||
		tokenID.Variant() != uuid.RFC4122 {
		return "", [sha256.Size]byte{}, errors.New("invalid auth mail token input")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(mailDomainSeparator))
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(tokenID[:])
	return EncodeToken(mac.Sum(nil))
}

// DeriveCSRFToken returns a session-bound CSRF token. The secret must contain
// at least TokenBytes.
func DeriveCSRFToken(secret []byte, session [TokenBytes]byte) (string, [sha256.Size]byte, error) {
	if len(secret) < TokenBytes {
		return "", [sha256.Size]byte{}, errors.New("invalid CSRF secret")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(session[:])
	value := mac.Sum(nil)
	encoded, hash, _ := EncodeToken(value)
	return encoded, hash, nil
}

func normalizePassword(password string) (string, error) {
	if !utf8.ValidString(password) || len(password) > passwordMaxBytes {
		return "", ErrInvalidPassword
	}
	normalized := norm.NFC.String(password)
	count := utf8.RuneCountInString(normalized)
	if count < passwordMinRunes || count > passwordMaxRunes || len(normalized) > passwordMaxBytes {
		return "", ErrInvalidPassword
	}
	return normalized, nil
}

// Hash normalizes the password, applies the current profile, and returns a
// PHC encoded hash. It waits for a free slot and gives up when the context
// ends.
func (hasher *Hasher) Hash(ctx context.Context, password string) (string, error) {
	normalized, err := normalizePassword(password)
	if err != nil {
		return "", err
	}
	if acquireErr := hasher.acquire(ctx); acquireErr != nil {
		return "", acquireErr
	}
	defer hasher.release()
	var salt [16]byte
	if _, readFullErr := io.ReadFull(hasher.random, salt[:]); readFullErr != nil {
		return "", errors.New("generate password salt")
	}
	key := argon2.IDKey(
		[]byte(normalized), salt[:],
		hasher.current.Iterations, hasher.current.Memory, hasher.current.Parallelism, passwordHashBytes,
	)
	return formatPHC(hasher.current, salt[:], key), nil
}

// Verify checks a password against a stored PHC hash. The second result is
// true when the hash matched but does not use the current profile, so the
// caller can store a new hash.
func (hasher *Hasher) Verify(ctx context.Context, password, encoded string) (bool, bool, error) {
	normalized, err := normalizePassword(password)
	if err != nil {
		return false, false, err
	}
	profile, salt, expected, err := hasher.parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	if acquireErr := hasher.acquire(ctx); acquireErr != nil {
		return false, false, acquireErr
	}
	defer hasher.release()
	actual := argon2.IDKey(
		[]byte(normalized), salt,
		profile.Iterations, profile.Memory, profile.Parallelism, passwordHashBytes,
	)
	matched := subtle.ConstantTimeCompare(actual, expected) == 1
	return matched, matched && profile != hasher.current, nil
}

// VerifyLogin checks a login attempt. Ineligible, malformed, or out-of-policy
// input still performs dummy work with the current profile, so timing does
// not reveal account state. The second result has the same meaning as in
// Verify.
func (hasher *Hasher) VerifyLogin(
	ctx context.Context,
	password, encoded string,
	eligible bool,
) (bool, bool, error) {
	normalized, passwordErr := normalizePassword(password)
	profile, salt, expected, hashErr := hasher.parsePHC(encoded)
	if passwordErr != nil || hashErr != nil || !eligible {
		normalized = "invalid-login-password"
		profile = hasher.current
		salt = hasher.dummySalt[:]
		expected = hasher.dummyHash[:]
		eligible = false
	}
	if err := hasher.acquire(ctx); err != nil {
		return false, false, err
	}
	defer hasher.release()
	actual := argon2.IDKey(
		[]byte(normalized), salt, profile.Iterations, profile.Memory, profile.Parallelism, passwordHashBytes,
	)
	matched := subtle.ConstantTimeCompare(actual, expected) == 1 && eligible
	return matched, matched && profile != hasher.current, nil
}

func (hasher *Hasher) acquire(ctx context.Context) error {
	select {
	case hasher.work <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (hasher *Hasher) release() {
	<-hasher.work
}

func (hasher *Hasher) parsePHC(encoded string) (Profile, []byte, []byte, error) {
	if len(encoded) > maxPHCBytes {
		return Profile{}, nil, nil, errors.New("invalid password hash")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Profile{}, nil, nil, errors.New("invalid password hash")
	}
	profile, err := parsePasswordParams(parts[3])
	if err != nil ||
		!validProfile(profile) ||
		parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", profile.Memory, profile.Iterations, profile.Parallelism) ||
		profile != hasher.current && profile != hasher.legacy {
		return Profile{}, nil, nil, errors.New("invalid password hash")
	}
	salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	hash, hashErr := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if saltErr != nil || hashErr != nil || len(salt) != 16 || len(hash) != passwordHashBytes {
		return Profile{}, nil, nil, errors.New("invalid password hash")
	}
	return profile, salt, hash, nil
}

func parsePasswordParams(value string) (Profile, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "m=") || !strings.HasPrefix(parts[1], "t=") ||
		!strings.HasPrefix(parts[2], "p=") {
		return Profile{}, errors.New("invalid password parameters")
	}
	memory, errMemory := strconv.ParseUint(strings.TrimPrefix(parts[0], "m="), 10, 32)
	iterations, errIterations := strconv.ParseUint(strings.TrimPrefix(parts[1], "t="), 10, 32)
	parallelism, errParallelism := strconv.ParseUint(strings.TrimPrefix(parts[2], "p="), 10, 8)
	if errMemory != nil || errIterations != nil || errParallelism != nil {
		return Profile{}, errors.New("invalid password parameters")
	}
	return Profile{Memory: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}, nil
}

func formatPHC(profile Profile, salt, hash []byte) string {
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		profile.Memory, profile.Iterations, profile.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
}
