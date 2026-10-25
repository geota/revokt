# native/

CI-only test oracles and the upki shim (spec §3, §9.2). **Nothing here is linked, bundled, published or reachable from
a published module** (CONTRIBUTING §3 "Oracles are tools, never shipped"); `verifyDependencyScopes` asserts it.

- `revokt-oracle`: Rust cdylib (Panama) and CLI over `clubcard-crlite`, `upki`, `rust-query-crlite`, `x509-parser`,
  the §9.2 TLV locator and `canonical_json`, with a `catch_unwind` shim. Today: the CLI subcommands `inspect`,
  `transcode`, `build-synthetic`, `gen-queries` and `goldens` over `clubcard-crlite 0.6.2`, which record the clubcard
  corpus goldens (docs/dev/corpus.md "Clubcard corpus"); the cdylib is still the ABI-version skeleton.
- `revokt-upki-shim`: Rust cdylib statically linking the `upki` crate; exposes `revokt_upki_config_new/free` and
  `revokt_upki_check` (spec §3.2).
- `producer-oracle`: a Go CLI over Mozilla's `crlite/go/types` (`ParseCertificate`, `NewSerialFromCertificate`), run
  out of process over a pipe (spec §9.1).
- `zlint-oracle`: a Go CLI over zlint, recording the pinned zlint result of every D8-gap entry (spec §9.2). It is its
  own module so that zlint's zcrypto never moves the producer's pin.

Built by the nightly `native` job, never by `./gradlew check`. `revokt-upki-shim` is a skeleton until the 0.1 oracle
issue.
