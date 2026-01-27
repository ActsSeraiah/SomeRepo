# security_utils

Small Rust crate with tiny security-themed utilities useful for tutorials and
examples. The crate intentionally stays small and dependency-light for
educational purposes.

**Features**
- Password hashing and verification (Argon2, PHC encoded)
- Constant-time byte comparison helper
- Compact random ASCII token generator

**Quick Start**

Hash a password and verify it:

```rust
let hash = security_utils::hash_password("s3cret").unwrap();
assert!(security_utils::verify_password(&hash, "s3cret").unwrap());
```

Generate a random token:

```rust
let token = security_utils::generate_token(32);
assert_eq!(token.len(), 32);
```

Run the unit tests (requires Rust and Cargo):

```bash
cargo test
```

Notes
- This is a small educational crate — do not treat it as a production-ready
	security library without review and hardening.
- The crate uses Argon2 via the `argon2` crate and stores/returns the encoded
	PHC string produced by the library.

Contribution
- Suggestions, bug reports, and PRs are welcome. Keep changes focused and
	small so the examples remain easy to follow.

License
- MIT
