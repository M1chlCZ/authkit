package authkit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrRateLimited reports that a key reached its maximum inside the current
// window.
var ErrRateLimited = errors.New("rate limit exceeded")

// ErrLimiterCapacity reports that the limiter cannot track another key, or
// that the attempt configuration is invalid.
var ErrLimiterCapacity = errors.New("rate limiter capacity reached")

// Limiter counts keyed attempts inside fixed windows. Implementations must be
// safe for concurrent use.
type Limiter interface {
	// Take records one attempt for key inside window and reports whether it
	// is allowed.
	Take(key string, maximum int, window time.Duration) error
}

// MemoryLimiter is an in-memory, fixed-window Limiter. It tracks at most the
// configured number of keys and never evicts a live key.
type MemoryLimiter struct {
	mu       sync.Mutex
	entries  map[string]limitEntry
	capacity int
	now      func() time.Time
}

type limitEntry struct {
	count   int
	resetAt time.Time
}

// NewMemoryLimiter returns a limiter that tracks up to capacity keys. A nil
// clock uses time.Now.
func NewMemoryLimiter(capacity int, now func() time.Time) *MemoryLimiter {
	if now == nil {
		now = time.Now
	}
	return &MemoryLimiter{entries: make(map[string]limitEntry), capacity: capacity, now: now}
}

// Take implements Limiter. The first maximum attempts for a key inside window
// are allowed; further attempts return ErrRateLimited. The window starts with
// the first attempt and does not slide; when it ends, the next attempt starts
// a new window.
//
// An empty key, a maximum below one, a window of zero or less, and a capacity
// below one all return ErrLimiterCapacity, so a misconfigured limit fails
// closed. A zero or negative maximum is not "no limit".
//
// At capacity, expired entries are pruned before a new key is tracked. When
// every entry is still live, Take returns ErrLimiterCapacity and keeps the
// live entries.
func (limiter *MemoryLimiter) Take(key string, maximum int, window time.Duration) error {
	if key == "" || maximum < 1 || window <= 0 || limiter.capacity < 1 {
		return ErrLimiterCapacity
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	entry, exists := limiter.entries[key]
	if exists && !now.Before(entry.resetAt) {
		delete(limiter.entries, key)
		exists = false
	}
	if !exists {
		if len(limiter.entries) >= limiter.capacity {
			for candidate, current := range limiter.entries {
				if !now.Before(current.resetAt) {
					delete(limiter.entries, candidate)
				}
			}
		}
		if len(limiter.entries) >= limiter.capacity {
			return ErrLimiterCapacity
		}
		entry = limitEntry{resetAt: now.Add(window)}
	}
	if entry.count >= maximum {
		return ErrRateLimited
	}
	entry.count++
	limiter.entries[key] = entry
	return nil
}

// KeyHash returns the lowercase hex SHA-256 digest of value. Build rate-limit
// keys from e-mails, addresses, or other identifiers with it, so raw values
// never sit in limiter maps.
func KeyHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}
