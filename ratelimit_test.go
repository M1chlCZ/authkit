package authkit_test

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/m1chlcz/authkit"
)

var _ authkit.Limiter = (*authkit.MemoryLimiter)(nil)

func TestMemoryLimiterUsesFixedNonSlidingWindows(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_000, 0)
	now := start
	limiter := authkit.NewMemoryLimiter(4, func() time.Time { return now })
	key := "login-ip:" + authkit.KeyHash("198.51.100.7")

	if err := limiter.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take first attempt: %v", err)
	}
	if err := limiter.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take second attempt: %v", err)
	}
	if err := limiter.Take(key, 2, time.Minute); !errors.Is(err, authkit.ErrRateLimited) {
		t.Fatalf("Take over the limit error = %v", err)
	}
	now = start.Add(time.Minute - time.Nanosecond)
	if err := limiter.Take(key, 2, time.Minute); !errors.Is(err, authkit.ErrRateLimited) {
		t.Fatalf("Take before the window end error = %v", err)
	}
	now = start.Add(time.Minute)
	if err := limiter.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take at the window end: %v", err)
	}
	if err := limiter.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take in the new window: %v", err)
	}
	if err := limiter.Take(key, 2, time.Minute); !errors.Is(err, authkit.ErrRateLimited) {
		t.Fatalf("Take over the new limit error = %v", err)
	}

	now = start
	sliding := authkit.NewMemoryLimiter(1, func() time.Time { return now })
	if err := sliding.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take first sliding attempt: %v", err)
	}
	now = start.Add(30 * time.Second)
	if err := sliding.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take second sliding attempt: %v", err)
	}
	now = start.Add(time.Minute)
	if err := sliding.Take(key, 2, time.Minute); err != nil {
		t.Fatalf("Take after the first window without sliding: %v", err)
	}
}

func TestMemoryLimiterCapacityPrunesOnlyExpiredEntries(t *testing.T) {
	t.Parallel()

	now := time.Unix(2_000, 0)
	limiter := authkit.NewMemoryLimiter(2, func() time.Time { return now })
	if err := limiter.Take("first", 2, time.Minute); err != nil {
		t.Fatalf("Take first key: %v", err)
	}
	now = now.Add(30 * time.Second)
	if err := limiter.Take("second", 2, time.Minute); err != nil {
		t.Fatalf("Take second key: %v", err)
	}
	if err := limiter.Take("first", 2, time.Minute); err != nil {
		t.Fatalf("Take tracked key at capacity: %v", err)
	}
	if err := limiter.Take("first", 2, time.Minute); !errors.Is(err, authkit.ErrRateLimited) {
		t.Fatalf("Take over the limit at capacity error = %v", err)
	}
	if err := limiter.Take("third", 1, time.Minute); !errors.Is(err, authkit.ErrLimiterCapacity) {
		t.Fatalf("Take while all entries are live error = %v", err)
	}

	now = now.Add(30 * time.Second)
	if err := limiter.Take("third", 1, time.Minute); err != nil {
		t.Fatalf("Take after pruning an expired entry: %v", err)
	}
	if err := limiter.Take("fourth", 1, time.Minute); !errors.Is(err, authkit.ErrLimiterCapacity) {
		t.Fatalf("Take while a live entry remains error = %v", err)
	}

	now = now.Add(time.Minute)
	if err := limiter.Take("fourth", 1, time.Minute); err != nil {
		t.Fatalf("Take after every entry expired: %v", err)
	}
}

func TestMemoryLimiterFailsClosedOnInvalidConfiguration(t *testing.T) {
	t.Parallel()

	limiter := authkit.NewMemoryLimiter(8, nil)
	for _, invalid := range []struct {
		key     string
		maximum int
		window  time.Duration
	}{
		{key: "", maximum: 1, window: time.Minute},
		{key: "key", maximum: 0, window: time.Minute},
		{key: "key", maximum: -1, window: time.Minute},
		{key: "key", maximum: 1, window: 0},
		{key: "key", maximum: 1, window: -time.Second},
	} {
		if err := limiter.Take(invalid.key, invalid.maximum, invalid.window); !errors.Is(err, authkit.ErrLimiterCapacity) {
			t.Fatalf("Take(%q, %d, %s) error = %v", invalid.key, invalid.maximum, invalid.window, err)
		}
	}
	for _, capacity := range []int{0, -1} {
		blocked := authkit.NewMemoryLimiter(capacity, nil)
		if err := blocked.Take("key", 1, time.Minute); !errors.Is(err, authkit.ErrLimiterCapacity) {
			t.Fatalf("Take with capacity %d error = %v", capacity, err)
		}
	}
}

func TestMemoryLimiterDefaultsToSystemClock(t *testing.T) {
	t.Parallel()

	limiter := authkit.NewMemoryLimiter(1, nil)
	if err := limiter.Take("key", 2, time.Hour); err != nil {
		t.Fatalf("Take with the default clock: %v", err)
	}
	if err := limiter.Take("key", 2, time.Hour); err != nil {
		t.Fatalf("Take second attempt with the default clock: %v", err)
	}
	if err := limiter.Take("key", 2, time.Hour); !errors.Is(err, authkit.ErrRateLimited) {
		t.Fatalf("Take with the default clock error = %v", err)
	}
}

func TestMemoryLimiterCountsExactlyTheLimitUnderConcurrency(t *testing.T) {
	t.Parallel()

	limiter := authkit.NewMemoryLimiter(4, nil)
	const (
		limit    = 8
		attempts = 96
	)
	var allowed, rejected atomic.Int64
	var waitGroup sync.WaitGroup
	for range attempts {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			switch err := limiter.Take("shared", limit, time.Hour); {
			case err == nil:
				allowed.Add(1)
			case errors.Is(err, authkit.ErrRateLimited):
				rejected.Add(1)
			default:
				t.Errorf("Take error = %v", err)
			}
		}()
	}
	waitGroup.Wait()
	if allowed.Load() != limit || rejected.Load() != attempts-limit {
		t.Fatalf(
			"allowed = %d rejected = %d, want %d and %d",
			allowed.Load(), rejected.Load(), limit, attempts-limit,
		)
	}
}

func TestKeyHashIsLowercaseHexSHA256(t *testing.T) {
	t.Parallel()

	const (
		value  = "sentinel@example.test"
		digest = "42f7980838a924a14044b86278ecbdc0bcdc2dced5053fddb3562e5ee94f0e10"
	)
	key := authkit.KeyHash(value)
	if key != digest {
		t.Fatalf("KeyHash = %q, want %q", key, digest)
	}
	if key != strings.ToLower(key) || strings.Contains(key, "@") || len(key) != 64 {
		t.Fatalf("KeyHash retained the raw value: %q", key)
	}
	if authkit.KeyHash(value) != key {
		t.Fatal("KeyHash is not deterministic")
	}
	if authkit.KeyHash(value+"x") == key || authkit.KeyHash(strings.ToUpper(value)) == key {
		t.Fatal("KeyHash is not bound to the exact input")
	}
}
