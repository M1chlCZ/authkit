package authkit_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/m1chlcz/authkit"
)

func TestHashTokenIsDeterministicSHA256(t *testing.T) {
	t.Parallel()

	const (
		raw    = "session-token-sentinel"
		digest = "e7a139516a220913f74565e0310bd0b0c4760b148fdb9f78caa87cef96e0a6e7"
	)
	hash := authkit.HashToken(raw)
	if hash != authkit.HashToken(raw) {
		t.Fatal("HashToken is not deterministic")
	}
	if hex.EncodeToString(hash[:]) != digest {
		t.Fatalf("HashToken = %x, want %s", hash, digest)
	}
	if authkit.HashToken(raw+"x") == hash {
		t.Fatal("HashToken is not bound to the exact input")
	}
}

func TestHashTokenMatchesTheStorageDigestOfEncodeToken(t *testing.T) {
	t.Parallel()

	encoded, raw, stored, err := authkit.NewToken(strings.NewReader(strings.Repeat("t", authkit.TokenBytes)))
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	if authkit.HashToken(string(raw[:])) != authkit.TokenHash(stored) {
		t.Fatal("HashToken does not reproduce the stored digest of the raw token bytes")
	}
	decoded, decodedHash, err := authkit.DecodeToken(encoded)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	if authkit.HashToken(string(decoded[:])) != authkit.TokenHash(decodedHash) {
		t.Fatal("HashToken does not reproduce the digest returned by DecodeToken")
	}
}
