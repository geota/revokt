# native/

CI-only test oracles and the upki shim (spec §3, §9.2). **Nothing here is linked, bundled, published or reachable from
a published module** (CONTRIBUTING §3 "Oracles are tools, never shipped"); `verifyDependencyScopes` asserts it.

- `revokt-oracle`: Rust cdylib (Panama) and CLI over `clubcard-crlite`, `upki`, `rust-query-crlite`, `x509-parser`,
  the §9.2 TLV locator and `canonical_json`, with a `catch_unwind` shim.
- `revokt-upki-shim`: Rust cdylib statically linking the `upki` crate; exposes `revokt_upki_config_new/free` and
  `revokt_upki_check` (spec §3.2).
- `producer-oracle`: a Go CLI over Mozilla's `crlite/go/types` (`ParseCertificate`, `NewSerialFromCertificate`), run
  out of process over a pipe (spec §9.1).

Built by the nightly `native` job, never by `./gradlew check`. The crates are skeletons until the 0.1 oracle issue.
