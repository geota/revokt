# native/

Rules that differ from the root `AGENTS.md`:

- `cargo build --locked` and `cargo test --locked` from this directory; `Cargo.lock` is committed; the toolchain is
  pinned in `rust-toolchain.toml`.
- These are oracles: they decide what revokt must agree with and are never shipped. Changing an oracle's behaviour is a
  `spec` PR when it changes an equivalence class (spec §3.2, §9.2).
- Every panic is caught at the FFI boundary (`catch_unwind`); a crash in an oracle never fails revokt's gate, it is
  reported upstream (spec §9.2).
- Go is not installed on the PR tier; the producer oracle builds only in the nightly `native` job.
