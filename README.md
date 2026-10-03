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

## Development

```
go test ./...
```

## License

MIT. See `LICENSE`.
