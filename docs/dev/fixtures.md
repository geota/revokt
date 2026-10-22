# Fixtures and test names

Test names carry the spec's §9 fixture id so `./gradlew specStatus` can count them (CONTRIBUTING §6):

- with a §9 fixture: `` `<list> (<id>) <behaviour>` ``, where `<list>` is `walker` or `data-path` (the §9 bullet the
  id comes from; `walker (k) same-key decoy with garbage signature`);
- without one: `` `<area> <behaviour>` `` (`limits match the spec 5-1 table`; no `§` or other characters the native
  test runner rejects in a name).

Kotlin backtick names in test sources; no `@DisplayName`. A fixture test is never deleted: quarantine it
(`@Tag("quarantine")`, a `quarantine` issue, a separate `test(<scope>): quarantine <name>` PR) and it blocks the next
release after 14 days.

Walker fixtures run with the cross-call memo cleared; stuffing fixtures present their junk; (i), (s2), (t) and (y)
are walker-harness only (spec §9).
