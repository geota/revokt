// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0
//! `revokt-oracle` CLI: records clubcard goldens from `clubcard-crlite` for the committed corpus (spec §9,
//! docs/dev/corpus.md "Clubcard corpus"). Every line of a goldens file is produced by the upstream crate, never by
//! revokt; the Kotlin replay test compares with zero tolerance.
//!
//! ```text
//! revokt-oracle inspect <filter>
//! revokt-oracle transcode <filter> <out.v4>
//! revokt-oracle build-synthetic <outdir>
//! revokt-oracle gen-queries <filter> <count> <seed> <out.tsv>
//! revokt-oracle goldens <filter> <queries.tsv> <out.tsv>
//! revokt-oracle x509            (oracle 3a over a pipe; see x509.rs)
//! ```
//!
//! Query line: `issuer_spki_hash_hex \t serial_hex \t scts \t expected`, where `scts` is a comma-separated list of
//! `log_id_hex:timestamp` (empty allowed) and `expected` is one of `Good`, `Revoked`, `NotCovered`, `NotEnrolled`.

mod x509;

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use clubcard::builder::{ApproximateRibbon, ClubcardBuilder, ExactRibbon};
use clubcard_crlite::builder::CRLiteBuilderItem;
use clubcard_crlite::{
    CRLiteClubcard, CRLiteCoverage, CRLiteKey, CRLiteQuery, CRLiteStatus, Encoding, IssuerSpkiHash,
    LogId, Timestamp, TimestampInterval,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd hex length in {s:?}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex {s:?}: {e}")))
        .collect()
}

fn status_name(status: &CRLiteStatus) -> &'static str {
    match status {
        CRLiteStatus::Good => "Good",
        CRLiteStatus::Revoked => "Revoked",
        CRLiteStatus::NotCovered => "NotCovered",
        CRLiteStatus::NotEnrolled => "NotEnrolled",
    }
}

/// xorshift64*: deterministic, dependency-free; the seed is recorded in the corpus record.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn read_filter(path: &str) -> Result<CRLiteClubcard, String> {
    let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    CRLiteClubcard::from_bytes(&bytes).map_err(|e| format!("{path}: {e}"))
}

fn inspect(path: &str) -> Result<(), String> {
    let filter = read_filter(path)?;
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    println!("encoding: v{}", bytes.first().copied().unwrap_or(0));
    print!("{filter}");
    Ok(())
}

fn transcode(input: &str, output: &str) -> Result<(), String> {
    let filter = read_filter(input)?;
    let bytes = filter.to_bytes(Encoding::V4).map_err(|e| e.to_string())?;
    fs::write(output, bytes).map_err(|e| format!("{output}: {e}"))
}

fn serial_of(j: usize) -> Vec<u8> {
    j.to_le_bytes().to_vec()
}

/// Issuers 0..4 with 2^12 serials each; issuer 3 is inverted (3/4 revoked); issuer 4 has nothing revoked. Coverage:
/// log 0 over [1000, 2000], log 1 over [0, u64::MAX]. The queries file records members, nonmembers, an unknown
/// issuer, and timestamps inside, outside and on the edges of both intervals.
fn build_synthetic(outdir: &str) -> Result<(), String> {
    let universe_size = 1usize << 12;
    let revoked_counts = [1usize << 10, 1 << 8, 1 << 11, 3 * (1 << 10), 0];
    let inverted = [false, false, false, true, false];

    let mut builder = ClubcardBuilder::new();
    let mut approx_ribbons = vec![];
    for (i, n) in revoked_counts.iter().enumerate() {
        let issuer = IssuerSpkiHash([i as u8; 32]);
        let mut r = builder.new_approx_builder(&issuer.0);
        r.set_universe_size(universe_size);
        r.set_inverted(inverted[i]);
        for j in 0..universe_size {
            // An inverted block encodes the non-revoked serials (clubcard-crlite builder.rs tests).
            if j < *n && !inverted[i] {
                r.insert(CRLiteBuilderItem::revoked(issuer, serial_of(j)));
            } else if j >= *n && inverted[i] {
                r.insert(CRLiteBuilderItem::not_revoked(issuer, serial_of(j)));
            }
        }
        approx_ribbons.push(ApproximateRibbon::from(r));
    }
    builder.collect_approx_ribbons(approx_ribbons);

    let mut exact_ribbons = vec![];
    for (i, n) in revoked_counts.iter().enumerate() {
        let issuer = IssuerSpkiHash([i as u8; 32]);
        let mut r = builder.new_exact_builder(&issuer.0);
        for j in 0..universe_size {
            r.insert(if j < *n {
                CRLiteBuilderItem::revoked(issuer, serial_of(j))
            } else {
                CRLiteBuilderItem::not_revoked(issuer, serial_of(j))
            });
        }
        exact_ribbons.push(ExactRibbon::from(r));
    }
    builder.collect_exact_ribbons(exact_ribbons);

    // `CRLiteCoverage`'s map is crate-private; the builder reads Mozilla's ct-logs.json. With MMD = 0 and
    // MinEntry = 0 the interval is [MinTimestamp, MaxTimestamp] exactly (clubcard-crlite builder.rs).
    let ct_logs = format!(
        "[{{\"LogID\":\"{}\",\"MaxTimestamp\":2000,\"MinTimestamp\":1000,\"MMD\":0,\"MinEntry\":0}},\
         {{\"LogID\":\"{}\",\"MaxTimestamp\":{},\"MinTimestamp\":0,\"MMD\":0,\"MinEntry\":0}}]",
        BASE64_STANDARD.encode([0u8; 32]),
        BASE64_STANDARD.encode([1u8; 32]),
        u64::MAX
    );
    let coverage = CRLiteCoverage::from_mozilla_ct_logs_json(ct_logs.as_bytes());
    let clubcard = builder.build::<CRLiteQuery>(coverage, ());
    let crlite = CRLiteClubcard::from(clubcard);
    print!("{crlite}");

    let dir = Path::new(outdir);
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for (encoding, name) in [
        (Encoding::V3, "synthetic.v3.filter"),
        (Encoding::V4, "synthetic.v4.filter"),
    ] {
        let bytes = crlite.to_bytes(encoding).map_err(|e| e.to_string())?;
        fs::write(dir.join(name), bytes).map_err(|e| e.to_string())?;
    }

    // Queries: every (issuer, serial) at the revoked boundary, a sample across the universe, the unknown issuer 5,
    // and the coverage edges.
    let mut lines = vec![];
    let log0 = hex(&[0u8; 32]);
    let log1 = hex(&[1u8; 32]);
    let log9 = hex(&[9u8; 32]);
    let sct_sets: [&str; 9] = [
        "",
        &format!("{log0}:1500"),
        &format!("{log0}:1000"),
        &format!("{log0}:2000"),
        &format!("{log0}:999"),
        &format!("{log0}:2001"),
        &format!("{log1}:0"),
        &format!("{log9}:1500"),
        &format!("{log9}:1500,{log0}:1500"),
    ];
    let mut rng = Rng(0x5eed_c1ab_ca7d_0001);
    for (i, n) in revoked_counts.iter().enumerate() {
        let issuer = hex(&[i as u8; 32]);
        let mut serials: Vec<usize> = vec![0, 1, n.saturating_sub(1), *n, n + 1, universe_size - 1];
        for _ in 0..40 {
            serials.push(rng.below(universe_size as u64) as usize);
        }
        // Serials outside the universe: never inserted, their status is whatever the filter says.
        serials.push(universe_size);
        serials.push(usize::MAX);
        for s in serials {
            for scts in sct_sets {
                lines.push(format!("{issuer}\t{}\t{scts}", hex(&serial_of(s))));
            }
        }
    }
    let unknown = hex(&[5u8; 32]);
    for scts in sct_sets {
        lines.push(format!("{unknown}\t{}\t{scts}", hex(&serial_of(0))));
    }
    // Serials that are not 8 bytes: an empty serial and a 20-byte one.
    lines.push(format!("{}\t\t{log1}:0", hex(&[0u8; 32])));
    lines.push(format!(
        "{}\t{}\t{log1}:0",
        hex(&[0u8; 32]),
        hex(&rng.bytes(20))
    ));

    let queries = dir.join("queries.tsv");
    fs::write(&queries, lines.join("\n") + "\n").map_err(|e| e.to_string())?;
    goldens(
        &dir.join("synthetic.v3.filter").to_string_lossy(),
        &queries.to_string_lossy(),
        &dir.join("goldens.tsv").to_string_lossy(),
    )
}

/// Queries against a real filter: issuers from its index (every one at least once), random serials of realistic
/// lengths, timestamps inside, on the edges of and outside the filter's coverage, and unknown issuers and logs.
fn gen_queries(path: &str, count: usize, seed: u64, out: &str) -> Result<(), String> {
    let filter = read_filter(path)?;
    let mut rng = Rng(seed);
    let issuers: Vec<&Vec<u8>> = filter.index().keys().collect();
    // `CRLiteCoverage` is a HashMap with a per-process random order: sort so a seed reproduces its queries.
    let mut coverage: Vec<(&LogId, &TimestampInterval)> = filter.universe().iter().collect();
    coverage.sort_by_key(|(log, _)| log.0);
    if issuers.is_empty() || coverage.is_empty() {
        return Err("filter has an empty index or coverage".into());
    }
    let mut lines = vec![];
    // Every exception serial first, each with a covered SCT and a one-bit sibling, so the exception branch of
    // `unchecked_contains` is always exercised (independent review of PR #6).
    for (block, entry) in filter.index() {
        let (log, interval) = coverage[0];
        for serial in &entry.exceptions {
            let mut sibling = serial.clone();
            if let Some(last) = sibling.last_mut() {
                *last ^= 1;
            }
            for s in [serial, &sibling] {
                lines.push(format!(
                    "{}\t{}\t{}:{}",
                    hex(block),
                    hex(s),
                    hex(&log.0),
                    interval.low.0
                ));
            }
        }
    }
    for i in 0..count {
        let issuer: Vec<u8> = if i % 97 == 96 {
            rng.bytes(32)
        } else {
            issuers[if i < issuers.len() {
                i
            } else {
                rng.below(issuers.len() as u64) as usize
            }]
            .clone()
        };
        let serial_len = [8usize, 16, 20, 1, 9, 19][rng.below(6) as usize];
        let serial = rng.bytes(serial_len);
        let mut scts = vec![];
        for _ in 0..rng.below(3) + 1 {
            let (log, interval) = coverage[rng.below(coverage.len() as u64) as usize];
            let log_hex = if rng.below(13) == 0 {
                hex(&rng.bytes(32))
            } else {
                hex(&log.0)
            };
            let span = interval.high.0.saturating_sub(interval.low.0);
            let ts = match rng.below(8) {
                0 => interval.low.0,
                1 => interval.high.0,
                2 => interval.low.0.wrapping_sub(1),
                3 => interval.high.0.wrapping_add(1),
                _ => interval
                    .low
                    .0
                    .saturating_add(rng.below(span.saturating_add(1))),
            };
            scts.push(format!("{log_hex}:{ts}"));
        }
        if rng.below(29) == 0 {
            scts.clear();
        }
        lines.push(format!(
            "{}\t{}\t{}",
            hex(&issuer),
            hex(&serial),
            scts.join(",")
        ));
    }
    fs::write(out, lines.join("\n") + "\n").map_err(|e| format!("{out}: {e}"))
}

fn parse_scts(field: &str) -> Result<Vec<(LogId, Timestamp)>, String> {
    if field.is_empty() {
        return Ok(vec![]);
    }
    field
        .split(',')
        .map(|item| {
            let (log, ts) = item
                .split_once(':')
                .ok_or_else(|| format!("bad sct {item:?}"))?;
            let log = unhex(log)?;
            let log: [u8; 32] = log
                .try_into()
                .map_err(|_| format!("log id is not 32 bytes in {item:?}"))?;
            let ts: u64 = ts
                .parse()
                .map_err(|e| format!("bad timestamp in {item:?}: {e}"))?;
            Ok((LogId(log), Timestamp(ts)))
        })
        .collect()
}

fn goldens(filter_path: &str, queries_path: &str, out: &str) -> Result<(), String> {
    let filter = read_filter(filter_path)?;
    let text = fs::read_to_string(queries_path).map_err(|e| format!("{queries_path}: {e}"))?;
    let mut lines = vec![];
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 {
            return Err(format!(
                "{queries_path}:{}: expected 3 tab-separated fields",
                n + 1
            ));
        }
        let issuer = unhex(fields[0])?;
        let issuer: [u8; 32] = issuer
            .try_into()
            .map_err(|_| format!("{queries_path}:{}: issuer is not 32 bytes", n + 1))?;
        let issuer = IssuerSpkiHash(issuer);
        let serial = unhex(fields[1])?;
        let scts = parse_scts(fields[2])?;
        let key = CRLiteKey::new(&issuer, &serial);
        let status = filter.contains(&key, scts.into_iter());
        lines.push(format!(
            "{}\t{}\t{}\t{}",
            fields[0],
            fields[1],
            fields[2],
            status_name(&status)
        ));
    }
    fs::write(out, lines.join("\n") + "\n").map_err(|e| format!("{out}: {e}"))?;
    eprintln!("{} goldens written to {out}", lines.len());
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, path] if cmd == "inspect" => inspect(path),
        [cmd, input, output] if cmd == "transcode" => transcode(input, output),
        [cmd, outdir] if cmd == "build-synthetic" => build_synthetic(outdir),
        [cmd, path, count, seed, out] if cmd == "gen-queries" => {
            let count: usize = count.parse().map_err(|e| format!("count: {e}"))?;
            let seed: u64 = seed.parse().map_err(|e| format!("seed: {e}"))?;
            gen_queries(path, count, seed, out)
        }
        [cmd, filter, queries, out] if cmd == "goldens" => goldens(filter, queries, out),
        [cmd] if cmd == "x509" => x509::run(),
        _ => Err("usage: revokt-oracle inspect <filter> | transcode <filter> <out.v4> | build-synthetic <outdir> | gen-queries <filter> <count> <seed> <out.tsv> | goldens <filter> <queries.tsv> <out.tsv> | x509".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("revokt-oracle: {e}");
            ExitCode::FAILURE
        }
    }
}
