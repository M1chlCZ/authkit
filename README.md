# authkit

Argon2id password hashing with PHC encoding, timing-equalized login checks, and strict token helpers.

## Features

- Argon2id with a pinned default profile: 64 MiB memory, 3 iterations, 4 lanes.
- PHC strings (`$argon2id$v=19$m=...`) for storage. No custom format.
- NFC normalization and a password policy: 15 to 256 characters and at most 1024 bytes.
- `Verify` reports when a stored hash uses the legacy profile, so the caller can rehash.
- `VerifyLogin` performs dummy work for unknown, ineligible, or malformed accounts. Response time does not show whether an account exists.
- One Argon2id operation at a time. The context waits for a free slot and gives up when it ends.
- Opaque token helpers: 32 raw bytes, unpadded base64url output, and the SHA-256 hash for storage.
- Purpose-bound mail tokens and session-bound CSRF tokens with HMAC-SHA256.
- `TokenHash` and `HashToken` return the SHA-256 digest of a raw token string for storage and lookup.
- Fixed-window rate limiting (`Limiter`, `MemoryLimiter`) with a bounded key map, an injectable clock, and fail-closed validation.
- `KeyHash` derives lowercase hex SHA-256 rate-limit keys, so raw e-mails and addresses never sit in limiter maps.

## Install

```
go get github.com/m1chlcz/authkit
```

Go 1.27 or later is required.

## Quick start

```go
hasher, err := authkit.New(authkit.DefaultConfig())
if err != nil {
	return err
}

stored, err := hasher.Hash(ctx, password)
if err != nil {
	return err
}

matched, needsRehash, err := hasher.VerifyLogin(ctx, attempt, stored, accountEligible)
if err != nil {
	return err
}
if matched && needsRehash {
	stored, err = hasher.Hash(ctx, attempt)
	if err != nil {
		return err
	}
}
```

## Profiles

| Profile | Memory | Iterations | Parallelism |
| --- | --- | --- | --- |
| `DefaultProfile()` | 64 MiB | 3 | 4 |
| `LegacyProfile()` | 32 MiB | 3 | 4 |

`New` rejects an invalid profile and a legacy profile equal to the current profile. The legacy profile is optional; an empty value disables legacy verification. A legacy hash that matches reports `needsRehash = true`.

```go
hasher, err := authkit.New(authkit.Config{
	Current: authkit.Profile{Memory: 64 * 1024, Iterations: 3, Parallelism: 4},
	Legacy:  authkit.LegacyProfile(),
})
```

## Login checks

`VerifyLogin(ctx, password, stored, eligible)` returns `(matched, needsRehash, error)`. When `eligible` is false, or the stored hash or the password is invalid, the hasher still runs one Argon2id operation with the current profile and a dummy salt. The first result is then always false. This keeps login timing similar for real and unknown accounts.

`Hash` and `Verify` return `authkit.ErrInvalidPassword` when the password fails the policy. Test `errors.Is` to detect this case.

## Tokens

```go
encoded, raw, hash, err := authkit.NewToken(nil)
raw, hash, err = authkit.DecodeToken(encoded)
encoded, hash, err = authkit.DeriveMailToken(secret, authkit.PurposeVerifyEmail, tokenID)
csrf, csrfHash, err := authkit.DeriveCSRFToken(secret, session)
```

Store only the hash. Send the encoded token to the user. `DeriveMailToken` requires a UUIDv7 record and a secret of at least 32 bytes. The accepted purposes are `PurposeVerifyEmail`, `PurposeResetPassword`, and `PurposeActivateAccount`.

## Token hashes

```go
hash := authkit.HashToken(rawToken)
```

`HashToken` returns the SHA-256 digest of the exact string it is given. Store the digest, never the raw token. `TokenHash` is a `[32]byte` value; slice it with `hash[:]` for `bytea` or blob columns. For tokens from `NewToken` or `EncodeToken`, the storage digest covers the raw 32 bytes, so `HashToken(string(raw[:]))` reproduces it.

## Session replacement

To replace a session when the same user logs in again, run these steps in one transaction:

1. Decode the presented old token with `DecodeToken` and reject the request when it is invalid. The returned hash is the key of the stored row.
2. Verify the old hash inside the transaction with `SELECT ... FOR UPDATE` and stop when no live row matches. The row lock rejects a replacement that races with a request still presenting the old token.
3. Insert the new session row with the new token hash and CSRF hash.
4. Delete the old row by its hash.
5. Commit, then send the new token to the client.

Both writes in one transaction mean a crash cannot leave two live sessions or none.

## Rate limiting

```go
limiter := authkit.NewMemoryLimiter(4096, nil)

err := limiter.Take("login-ip:"+authkit.KeyHash(ip), 10, 10*time.Minute)
if errors.Is(err, authkit.ErrRateLimited) {
	return tooManyRequests()
}
if errors.Is(err, authkit.ErrLimiterCapacity) {
	return serviceUnavailable()
}
```

`Take(key, maximum, window)` allows the first `maximum` attempts for a key inside a fixed window. The window starts with the first attempt and does not slide. Further attempts return `ErrRateLimited` until the window ends; the next attempt then starts a new window with a fresh count.

`MemoryLimiter` tracks at most the capacity given to `NewMemoryLimiter`. At capacity, `Take` prunes expired entries first. When every tracked entry is still live, it returns `ErrLimiterCapacity` and keeps the live entries, so the limiter never evicts an active limit. Size the capacity for the expected number of keys.

Validation is fail-closed: an empty key, a `maximum` below one, a `window` of zero or less, and a capacity below one all return `ErrLimiterCapacity`. A zero or negative maximum is not "no limit".

`KeyHash` is the lowercase hex SHA-256 digest. Hash e-mails, addresses, and other identifiers before building a key, so raw values never sit in the limiter map. `NewMemoryLimiter(capacity, nil)` uses `time.Now`; pass a clock in tests.

## Development

```
go test ./...
```

## License

MIT. See `LICENSE`.
