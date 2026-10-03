//nolint:testpackage // White-box tests exercise unexported normalizePassword, newHasher, maxPHCBytes and hasher internals.
package authkit

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
)

func TestTokenEncodingAndHashAreStrict(t *testing.T) {
	t.Parallel()

	raw := make([]byte, TokenBytes)
	for index := range raw {
		raw[index] = byte(255 - index)
	}
	encoded, hash, err := EncodeToken(raw)
	if err != nil {
		t.Fatalf("EncodeToken: %v", err)
	}
	if len(encoded) != 43 || strings.Contains(encoded, "=") {
		t.Fatalf("encoded token = %q, want 43 unpadded base64url characters", encoded)
	}
	decoded, decodedHash, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	if decoded != [TokenBytes]byte(raw) || decodedHash != hash || hash != sha256.Sum256(raw) {
		t.Fatal("token decode or SHA-256 hash changed the raw token")
	}

	for _, invalid := range []string{
		encoded + "=",
		encoded[:42],
		strings.Repeat("A", 42) + "B",
		strings.Repeat("-", 43),
		base64.RawStdEncoding.EncodeToString(raw),
	} {
		if _, _, decodeErr := DecodeToken(invalid); decodeErr == nil {
			t.Fatalf("DecodeToken accepted %q", invalid)
		}
	}
}

func TestDeriveCSRFIsStableAndSessionBound(t *testing.T) {
	t.Parallel()

	secret := []byte("0123456789abcdef0123456789abcdef")
	var first, second [TokenBytes]byte
	first[0], second[0] = 1, 2

	encoded1, hash1, err := DeriveCSRFToken(secret, first)
	if err != nil {
		t.Fatalf("DeriveCSRFToken: %v", err)
	}
	encodedAgain, hashAgain, err := DeriveCSRFToken(secret, first)
	if err != nil {
		t.Fatalf("DeriveCSRFToken: %v", err)
	}
	encoded2, hash2, err := DeriveCSRFToken(secret, second)
	if err != nil {
		t.Fatalf("DeriveCSRFToken: %v", err)
	}
	if len(encoded1) != 43 || encoded1 != encodedAgain || hash1 != hashAgain {
		t.Fatal("CSRF derivation is not stable")
	}
	if _, _, shortErr := DeriveCSRFToken(secret[:31], first); shortErr == nil {
		t.Fatal("DeriveCSRFToken accepted a short secret")
	}
	if encoded1 == encoded2 || hash1 == hash2 {
		t.Fatal("CSRF derivation is not bound to the raw session token")
	}
	if _, decodedHash, decodeErr := DecodeToken(encoded1); decodeErr != nil || decodedHash != hash1 {
		t.Fatalf("derived CSRF token is not a strict auth token: hash=%x err=%v", decodedHash, decodeErr)
	}
}

func TestAuthMailTokenDerivationIsStableAndDomainSeparated(t *testing.T) {
	t.Parallel()

	secret := []byte("0123456789abcdef0123456789abcdef")
	tokenID := uuid.MustParse("0190a9e8-75a0-7cc1-8000-000000000001")

	encoded, hash, err := DeriveMailToken(secret, "verify_email", tokenID)
	if err != nil {
		t.Fatalf("DeriveMailToken: %v", err)
	}
	if encoded != "3yJ21sm0TrYA3edp5ctqxQVd9o6vSepTLWRiXrXdKcU" {
		t.Fatalf("fixed token = %q", encoded)
	}
	if _, decodedHash, decodeErr := DecodeToken(encoded); decodeErr != nil || decodedHash != hash {
		t.Fatalf("derived token is not accepted by auth consumers: hash=%x err=%v", decodedHash, decodeErr)
	}

	reset, _, err := DeriveMailToken(secret, "reset_password", tokenID)
	if err != nil {
		t.Fatalf("derive reset token: %v", err)
	}
	otherID, _, err := DeriveMailToken(
		secret,
		"verify_email",
		uuid.MustParse("0190a9e8-75a0-7cc1-8000-000000000002"),
	)
	if err != nil {
		t.Fatalf("derive other token ID: %v", err)
	}
	if reset == encoded || otherID == encoded {
		t.Fatal("mail token derivation is not separated by purpose and token ID")
	}
	wrongVariant := tokenID
	wrongVariant[8] = 0
	for _, invalid := range []struct {
		secret  []byte
		purpose string
		id      uuid.UUID
	}{
		{secret[:31], "verify_email", tokenID},
		{secret, "unknown", tokenID},
		{secret, "verify_email", uuid.New()},
		{secret, "verify_email", wrongVariant},
	} {
		if _, _, deriveErr := DeriveMailToken(
			invalid.secret,
			invalid.purpose,
			invalid.id,
		); deriveErr == nil {
			t.Fatal("DeriveMailToken accepted invalid inputs")
		}
	}
}

func TestPasswordPolicyNormalizesNFCWithoutOtherRewriting(t *testing.T) {
	t.Parallel()

	decomposed := strings.Repeat("e\u0301", 15)
	normalized, err := normalizePassword(decomposed)
	if err != nil {
		t.Fatalf("normalizePassword: %v", err)
	}
	if normalized != strings.Repeat("é", 15) {
		t.Fatalf("normalized password = %q", normalized)
	}
	spaced := "  Password With Spaces 123  "
	if got, normalizePasswordErr := normalizePassword(spaced); normalizePasswordErr != nil || got != spaced {
		t.Fatalf("password was trimmed or rewritten: got=%q err=%v", got, normalizePasswordErr)
	}

	invalidUTF8 := string([]byte{0xff, 'a'})
	for _, invalid := range []string{
		strings.Repeat("a", 14),
		strings.Repeat("a", 257),
		strings.Repeat("😀", 256) + "a",
		invalidUTF8,
	} {
		if _, normalizePasswordErr2 := normalizePassword(invalid); normalizePasswordErr2 == nil {
			t.Fatalf(
				"normalizePassword accepted %d bytes/%d runes (valid=%t)",
				len(invalid),
				utf8.RuneCountInString(invalid),
				utf8.ValidString(invalid),
			)
		}
	}
}

func TestPasswordHasherAcceptsOnlyKnownBoundedProfiles(t *testing.T) {
	t.Parallel()

	profiles := testPasswordProfiles()
	hasher, err := newHasher(profiles.current, profiles.legacy, strings.NewReader(strings.Repeat("s", 128)))
	if err != nil {
		t.Fatalf("newHasher: %v", err)
	}
	password := strings.Repeat("correct horse ", 2)
	hash, err := hasher.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	matched, rehash, err := hasher.Verify(context.Background(), password, hash)
	if err != nil || !matched || rehash {
		t.Fatalf("Verify current hash = matched %t rehash %t err %v", matched, rehash, err)
	}
	matched, _, err = hasher.Verify(context.Background(), password+"x", hash)
	if err != nil || matched {
		t.Fatalf("Verify wrong password = matched %t err %v", matched, err)
	}

	legacyHash := hashWithProfileForTest(t, profiles.legacy, password)
	matched, rehash, err = hasher.Verify(context.Background(), password, legacyHash)
	if err != nil || !matched || !rehash {
		t.Fatalf("Verify legacy hash = matched %t rehash %t err %v", matched, rehash, err)
	}

	parts := strings.Split(hash, "$")
	for _, malformed := range []string{
		strings.Repeat("x", maxPHCBytes+1),
		strings.Replace(hash, "v=19", "v=16", 1),
		strings.Replace(hash, "m=8,t=1,p=1", "m=9,t=1,p=1", 1),
		strings.Replace(hash, "m=8,t=1,p=1", "m=08,t=1,p=1", 1),
		strings.Replace(hash, "m=8,t=1,p=1", "m=4294967295,t=1,p=1", 1),
		strings.Join(append(parts, "extra"), "$"),
		"$argon2id$v=19$m=8,t=1,p=1$bad$bad",
	} {
		if verifyMatched, _, verifyErr := hasher.Verify(
			context.Background(),
			password,
			malformed,
		); verifyErr == nil ||
			verifyMatched {
			t.Fatalf("Verify accepted malformed PHC %q", malformed)
		}
	}
}

func TestProductionPasswordProfileIsPinned(t *testing.T) {
	t.Parallel()

	if DefaultProfile() != (Profile{Memory: 65536, Iterations: 3, Parallelism: 4}) {
		t.Fatalf("current password profile = %#v", DefaultProfile())
	}
	if LegacyProfile() != (Profile{Memory: 32768, Iterations: 3, Parallelism: 4}) {
		t.Fatalf("legacy password profile = %#v", LegacyProfile())
	}
	config := DefaultConfig()
	if config.Current != DefaultProfile() || config.Legacy != LegacyProfile() || config.Random != nil {
		t.Fatalf("default config = %#v", config)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	for _, config := range []Config{
		{},
		{Current: Profile{Memory: 8, Iterations: 1, Parallelism: 1}, Legacy: Profile{Memory: 8, Iterations: 1, Parallelism: 1}},
		{Current: Profile{Memory: 8, Iterations: 1, Parallelism: 1}, Legacy: Profile{Memory: 8, Iterations: 0, Parallelism: 1}},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("New accepted %#v", config)
		}
	}
	hasher, err := New(DefaultConfig())
	if err != nil || hasher == nil {
		t.Fatalf("New(DefaultConfig()) = %v, %v", hasher, err)
	}
	noLegacy, err := New(Config{Current: Profile{Memory: 8, Iterations: 1, Parallelism: 1}})
	if err != nil || noLegacy == nil {
		t.Fatalf("New(config without legacy) = %v, %v", noLegacy, err)
	}
}

func TestVerifyRejectsZeroProfileHashWhenLegacyDisabled(t *testing.T) {
	t.Parallel()

	profiles := testPasswordProfiles()
	hasher, err := newHasher(profiles.current, Profile{}, strings.NewReader(strings.Repeat("z", 128)))
	if err != nil {
		t.Fatalf("newHasher: %v", err)
	}
	zeroProfileHash := "$argon2id$v=19$m=0,t=0,p=0$" +
		base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" +
		base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	password := strings.Repeat("valid-password", 2)
	if matched, rehash, verifyErr := hasher.Verify(
		context.Background(),
		password,
		zeroProfileHash,
	); verifyErr == nil || matched || rehash {
		t.Fatalf("Verify zero profile = %t/%t/%v", matched, rehash, verifyErr)
	}
	if matched, rehash, verifyErr := hasher.VerifyLogin(
		context.Background(),
		password,
		zeroProfileHash,
		true,
	); verifyErr != nil || matched || rehash {
		t.Fatalf("VerifyLogin zero profile = %t/%t/%v", matched, rehash, verifyErr)
	}
}

func TestPasswordHasherSemaphoreHonorsContext(t *testing.T) {
	t.Parallel()

	profiles := testPasswordProfiles()
	hasher, err := newHasher(profiles.current, profiles.legacy, strings.NewReader(strings.Repeat("r", 128)))
	if err != nil {
		t.Fatalf("newHasher: %v", err)
	}
	hasher.work <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, hashErr := hasher.Hash(ctx, strings.Repeat("a", 15))
	if hashErr == nil || !errors.Is(hashErr, context.Canceled) {
		t.Fatalf("Hash canceled error = %v", hashErr)
	}
	<-hasher.work
}

func TestLoginVerificationUsesDummyWorkForIneligibleAndMalformedAccounts(t *testing.T) {
	t.Parallel()

	profiles := testPasswordProfiles()
	hasher, err := newHasher(profiles.current, profiles.legacy, strings.NewReader(strings.Repeat("d", 128)))
	if err != nil {
		t.Fatalf("newHasher: %v", err)
	}
	password := strings.Repeat("valid-password", 2)
	hash, err := hasher.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	matched, rehash, err := hasher.VerifyLogin(context.Background(), password, hash, true)
	if err != nil || !matched || rehash {
		t.Fatalf("VerifyLogin eligible = %t/%t/%v", matched, rehash, err)
	}
	for _, probe := range []struct {
		stored   string
		eligible bool
		password string
	}{
		{stored: hash, eligible: false, password: password},
		{stored: "malformed", eligible: true, password: password},
		{stored: hash, eligible: true, password: "short"},
	} {
		if verifyLoginMatched, verifyLoginRehash, verifyLoginErr := hasher.VerifyLogin(
			context.Background(),
			probe.password,
			probe.stored,
			probe.eligible,
		); verifyLoginErr != nil || verifyLoginMatched ||
			verifyLoginRehash {
			t.Fatalf("VerifyLogin dummy path = %t/%t/%v", verifyLoginMatched, verifyLoginRehash, verifyLoginErr)
		}
	}

	hasher.work <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, verifyErr := hasher.VerifyLogin(ctx, password, "malformed", true)
	if !errors.Is(verifyErr, context.Canceled) {
		t.Fatalf("VerifyLogin malformed did not wait context-aware for dummy work: %v", verifyErr)
	}
	<-hasher.work
}

type profilePair struct {
	current Profile
	legacy  Profile
}

func testPasswordProfiles() profilePair {
	return profilePair{
		current: Profile{Memory: 8, Iterations: 1, Parallelism: 1},
		legacy:  Profile{Memory: 8, Iterations: 2, Parallelism: 1},
	}
}

func hashWithProfileForTest(t *testing.T, profile Profile, password string) string {
	t.Helper()
	hasher, err := newHasher(profile, Profile{}, strings.NewReader(strings.Repeat("l", 128)))
	if err != nil {
		t.Fatalf("newHasher legacy: %v", err)
	}
	hash, err := hasher.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash legacy: %v", err)
	}
	return hash
}
