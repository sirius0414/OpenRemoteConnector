# ADR 0001: Rust workspace implementation baseline

Date: 2026-10-18. Status: implemented development baseline, M0 release gates open.

The workspace uses Rust 2024 and Rust 1.99.1 (2026-10-13 compiler), pinned in `rust-toolchain.toml`. Dependencies are resolved in the committed `Cargo.lock`. The toolchain used for local checks was fetched from Rust's dated distribution manifest and its archive SHA-256 values were checked. Local verification ran on macOS arm64; execution crates were additionally checked against `x86_64-unknown-linux-gnu`.

The MCP uses the official `rmcp` 3.5.1 Streamable HTTP implementation behind per-request Axum authentication. OAuth PKCE uses `oxide-auth`; ORC implements persistence, resource binding, owner consent and token families. Device connections use mutual TLS 1.3 and Ed25519 challenge/signature verification. SQLite writes run on a dedicated bounded worker and security mutations retain an independent, synced hash-chain journal.

Initial systemd and dedicated rootless Docker integrations use bounded, argument-vector command adapters. They do not yet use the planned zbus/Bollard adapters. No user command is interpolated into a control shell. This is a documented design deviation, not evidence that the target backend passed acceptance. Isolated profiles require exact runtime, image, engine and kernel validation evidence and fail closed when unavailable.

Protocol timestamps are integer Unix seconds; execution deadlines use milliseconds. This differs from the ISO timestamp spelling in DESIGN's illustrative request. Tool schemas and runtime decoding use the same integer convention. Canonical JSON supports safe integers and Unicode with UTF-16 key ordering; floating point values are rejected.

This baseline does not establish release readiness. See `../validation/P0-STATUS.md` and `../validation/EXECUTION.md` for implementation gaps and target-environment acceptance gates. In particular, neither a signed public release nor successful Codex/ChatGPT production authentication is implied by library/unit tests.
