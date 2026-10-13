# Changelog

All notable changes to this package are documented in this file. The format
follows Keep a Changelog, and the project uses semantic versioning.

## [0.2.0] - 2026-10-13

### Added

- Fixed-window rate-limit hooks: the `Limiter` interface, `MemoryLimiter`
  with a bounded key map and an injectable clock (`NewMemoryLimiter`), the
  sentinel errors `ErrRateLimited` and `ErrLimiterCapacity`, and `KeyHash`
  for lowercase hex SHA-256 rate-limit keys.
- `TokenHash` and `HashToken` return the SHA-256 digest of a raw token string
  for storage and lookup, with a session-replacement recipe in the README.
