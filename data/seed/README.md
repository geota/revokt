# data/seed

The weekly seed job (spec §6.5, §7.2): fetches the Remote Settings `cert-revocations` changeset and attachments,
verifies Mozilla's content signature (spec §7.1), builds `index.bin` with the engine's `buildIndex`, and publishes
`revokt-seed-<channel>` under a **separate Portal account that owns only the data namespace**, through the
`seed-publish` environment, with an attestation that records the changeset timestamp, the record ids and each
attachment's SHA-256, then smoke-loads the artefact with the oldest supported engine minor (CONTRIBUTING §9).

Seed artifacts carry no code dependency; the engine floor lives in `seed.json`. Lands with milestone 0.2.
