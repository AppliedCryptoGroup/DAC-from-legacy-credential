use clap::Parser;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(about = "Benchmark for delegatable ECDSA pipeline")]
pub struct BenchArgs {
    /// Number of real claims/attributes. Must be a nonzero power of two.
    ///
    /// The benchmarks always run the *full* version: the Merkle tree capacity
    /// (`num_max_attributes`) is fixed equal to `claims`, so every leaf is a
    /// real claim and there is no padding. This keeps the measured numbers
    /// representative of a fully-populated credential.
    #[arg(long)]
    pub claims: usize,

    /// Max claim/attribute size in bytes (must be a nonzero multiple of 4).
    #[arg(long)]
    pub max_claim_size: usize,

    /// If set, append a single CSV row with all metrics to this file on success.
    /// Header is written if the file is empty; if a header already exists it
    /// must match the one we'd generate, otherwise we refuse to append (so a
    /// stale schema can't silently corrupt the run).
    #[arg(long)]
    pub csv_out: Option<PathBuf>,

    /// Run index recorded in the CSV row (`run_idx` column). Useful for tagging
    /// the i-th run in a multi-run sweep. Defaults to 0 when omitted.
    #[arg(long)]
    pub run_idx: Option<usize>,

    /// Passed automatically by `cargo bench`; ignored.
    #[arg(long, hide = true)]
    pub bench: bool,
}

pub struct CircuitSizeEntry {
    pub label: &'static str,
    pub degree_bits: usize,
    /// Pre-padding (and pre-blinding) gate count, i.e. `builder.num_gates()`
    /// captured just before `.build()`. Lets us show how close the circuit
    /// is to spilling into `2^(degree_bits + 1)`.
    pub num_gates: usize,
}

pub struct TimingEntry {
    pub label: &'static str,
    pub duration: Duration,
}

pub struct ProofSizeEntry {
    pub label: &'static str,
    pub bytes: usize,
}

pub struct BenchResults {
    pub circuit_sizes: Vec<CircuitSizeEntry>,
    pub build: Vec<TimingEntry>,
    pub proving: Vec<TimingEntry>,
    pub verification: Vec<TimingEntry>,
    pub proof_sizes: Vec<ProofSizeEntry>,
}

impl BenchResults {
    pub fn new() -> Self {
        Self {
            circuit_sizes: Vec::new(),
            build: Vec::new(),
            proving: Vec::new(),
            verification: Vec::new(),
            proof_sizes: Vec::new(),
        }
    }

    pub fn add_circuit_size(&mut self, label: &'static str, degree_bits: usize, num_gates: usize) {
        self.circuit_sizes.push(CircuitSizeEntry {
            label,
            degree_bits,
            num_gates,
        });
    }

    pub fn add_build(&mut self, label: &'static str, duration: Duration) {
        self.build.push(TimingEntry { label, duration });
    }

    pub fn add_proving(&mut self, label: &'static str, duration: Duration) {
        self.proving.push(TimingEntry { label, duration });
    }

    pub fn add_verification(&mut self, label: &'static str, duration: Duration) {
        self.verification.push(TimingEntry { label, duration });
    }

    pub fn add_proof_size(&mut self, label: &'static str, bytes: usize) {
        self.proof_sizes.push(ProofSizeEntry { label, bytes });
    }
}

impl Default for BenchResults {
    fn default() -> Self {
        Self::new()
    }
}

/// Run a closure `n` times and return the average duration.
pub fn bench_verify<F: FnMut()>(mut f: F, n: usize) -> Duration {
    let start = std::time::Instant::now();
    for _ in 0..n {
        f();
    }
    start.elapsed() / n as u32
}

fn fmt_duration(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms >= 1000.0 {
        format!("{:.2} s", ms / 1000.0)
    } else {
        format!("{:.2} ms", ms)
    }
}

fn fmt_bytes(n: usize) -> String {
    if n >= 1024 {
        format!("{:.2} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

/// Raw integer count with `,` thousands separators, so every gate is visible:
/// 14_832 -> "14,832", 1_048_576 -> "1,048,576".
fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

const COL_L: usize = 33;
const COL_R: usize = 38;
const WIDTH: usize = COL_L + COL_R + 3; // +3 for the middle border chars

pub fn print_results(title: &str, args: &BenchArgs, results: &BenchResults, verify_iters: usize) {
    let w = WIDTH;

    // Top border
    println!("\u{250c}{}\u{2510}", "\u{2500}".repeat(w));

    // Title
    let title_line = format!("  Delegatable ECDSA \u{2014} {title}");
    println!("\u{2502}{:<w$}\u{2502}", title_line);

    // Config
    let config_line = format!(
        "  Claims: {}  \u{00b7}  Max claim size: {} bytes",
        args.claims, args.max_claim_size
    );
    println!("\u{2502}{:<w$}\u{2502}", config_line);

    // Circuit sizes section
    if !results.circuit_sizes.is_empty() {
        println!(
            "\u{251c}{}\u{252c}{}\u{2524}",
            "\u{2500}".repeat(COL_L),
            "\u{2500}".repeat(COL_R)
        );
        println!(
            "\u{2502}{:<cl$}\u{2502}{:>cr$}\u{2502}",
            "  Circuit Sizes",
            "",
            cl = COL_L,
            cr = COL_R
        );
        println!(
            "\u{251c}{}\u{253c}{}\u{2524}",
            "\u{2500}".repeat(COL_L),
            "\u{2500}".repeat(COL_R)
        );
        for entry in &results.circuit_sizes {
            let capacity = 1usize << entry.degree_bits;
            let pct = (entry.num_gates as f64 / capacity as f64) * 100.0;
            let size_str = format!(
                "2^{} ({} / {}, {:.0}%)",
                entry.degree_bits,
                fmt_count(entry.num_gates),
                fmt_count(capacity),
                pct,
            );
            println!(
                "\u{2502}{:<cl$}\u{2502}{:>cr$}\u{2502}",
                format!("  {}", entry.label),
                format!("  {}  ", size_str),
                cl = COL_L,
                cr = COL_R
            );
        }
    }

    // Timing sections
    let print_section = |header: &str, entries: &[TimingEntry], suffix: &str| {
        println!(
            "\u{251c}{}\u{252c}{}\u{2524}",
            "\u{2500}".repeat(COL_L),
            "\u{2500}".repeat(COL_R)
        );
        let hdr = format!("  {header}{suffix}");
        println!(
            "\u{2502}{:<cl$}\u{2502}{:>cr$}\u{2502}",
            hdr,
            "",
            cl = COL_L,
            cr = COL_R
        );
        println!(
            "\u{251c}{}\u{253c}{}\u{2524}",
            "\u{2500}".repeat(COL_L),
            "\u{2500}".repeat(COL_R)
        );
        for entry in entries {
            let time_str = fmt_duration(entry.duration);
            let label = format!("  {}", entry.label);
            println!(
                "\u{2502}{:<cl$}\u{2502}{:>cr$}\u{2502}",
                label,
                format!("{time_str}  "),
                cl = COL_L,
                cr = COL_R
            );
        }
    };

    print_section("Circuit Build Times", &results.build, "");
    print_section("Proving Times", &results.proving, " (single run)");
    print_section(
        "Verification Times",
        &results.verification,
        &format!(" (N={verify_iters})"),
    );

    // Proof sizes section (compressed serialization)
    if !results.proof_sizes.is_empty() {
        println!(
            "\u{251c}{}\u{252c}{}\u{2524}",
            "\u{2500}".repeat(COL_L),
            "\u{2500}".repeat(COL_R)
        );
        println!(
            "\u{2502}{:<cl$}\u{2502}{:>cr$}\u{2502}",
            "  Proof Sizes (compressed)",
            "",
            cl = COL_L,
            cr = COL_R
        );
        println!(
            "\u{251c}{}\u{253c}{}\u{2524}",
            "\u{2500}".repeat(COL_L),
            "\u{2500}".repeat(COL_R)
        );
        for entry in &results.proof_sizes {
            println!(
                "\u{2502}{:<cl$}\u{2502}{:>cr$}\u{2502}",
                format!("  {}", entry.label),
                format!("{}  ", fmt_bytes(entry.bytes)),
                cl = COL_L,
                cr = COL_R
            );
        }
    }

    // Bottom border
    println!(
        "\u{2514}{}\u{2534}{}\u{2518}",
        "\u{2500}".repeat(COL_L),
        "\u{2500}".repeat(COL_R)
    );
}

// ---------------------------------------------------------------------------
// CSV output
// ---------------------------------------------------------------------------

/// Slug a label into a CSV-safe identifier: lowercase, map non-alphanumeric to
/// `_`, collapse runs of underscores, trim leading/trailing underscores.
/// For example `"Pres. precompute (witness)"` becomes `"pres_precompute_witness"`.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_underscore = true; // start true so leading non-alnum is dropped
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_underscore = false;
        } else if !prev_underscore {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// Fixed leading columns. Everything after these is derived from results in
/// the same order they were inserted (which matches `print_results`'s layout).
const FIXED_COLS: &[&str] = &["claims", "max_claim_size", "run_idx", "timestamp_ms"];

/// Build the CSV header line (no trailing newline) for the given results.
fn csv_header(results: &BenchResults) -> String {
    let mut cols: Vec<String> = FIXED_COLS.iter().map(|s| s.to_string()).collect();
    for e in &results.circuit_sizes {
        let s = slugify(e.label);
        cols.push(format!("gates_{s}"));
        cols.push(format!("degree_bits_{s}"));
    }
    for e in &results.build {
        cols.push(format!("build_{}_s", slugify(e.label)));
    }
    for e in &results.proving {
        cols.push(format!("prove_{}_s", slugify(e.label)));
    }
    for e in &results.verification {
        cols.push(format!("verify_{}_s", slugify(e.label)));
    }
    for e in &results.proof_sizes {
        cols.push(format!("size_{}_bytes", slugify(e.label)));
    }
    cols.join(",")
}

/// Build the CSV data line (no trailing newline) matching `csv_header`.
fn csv_row(args: &BenchArgs, results: &BenchResults, timestamp_ms: u128) -> String {
    let mut cols: Vec<String> = Vec::with_capacity(
        FIXED_COLS.len()
            + results.circuit_sizes.len() * 2
            + results.build.len()
            + results.proving.len()
            + results.verification.len()
            + results.proof_sizes.len(),
    );
    cols.push(args.claims.to_string());
    cols.push(args.max_claim_size.to_string());
    cols.push(args.run_idx.unwrap_or(0).to_string());
    cols.push(timestamp_ms.to_string());
    for e in &results.circuit_sizes {
        cols.push(e.num_gates.to_string());
        cols.push(e.degree_bits.to_string());
    }
    // Use seconds with microsecond precision: enough resolution for everything
    // we measure here, and keeps the CSV human-scannable.
    let secs = |d: Duration| format!("{:.6}", d.as_secs_f64());
    for e in &results.build {
        cols.push(secs(e.duration));
    }
    for e in &results.proving {
        cols.push(secs(e.duration));
    }
    for e in &results.verification {
        cols.push(secs(e.duration));
    }
    for e in &results.proof_sizes {
        cols.push(e.bytes.to_string());
    }
    cols.join(",")
}

/// Append one row to `path`. Creates the file with a header if missing; if the
/// existing header doesn't match the one we'd write, refuses to append (we'd
/// rather error than silently produce a mixed-schema CSV).
///
/// The row + newline is written via a single `write_all` on an `O_APPEND` file,
/// so concurrent or interrupted writes can't produce a torn line for any row
/// that fits in `PIPE_BUF` (4 KB on Linux/macOS), which all our rows do.
pub fn append_csv_row(
    args: &BenchArgs,
    results: &BenchResults,
    path: &std::path::Path,
) -> io::Result<()> {
    let header = csv_header(results);
    let row = csv_row(
        args,
        results,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    );

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;

    let len = file.metadata()?.len();
    let mut payload = String::new();
    if len == 0 {
        payload.push_str(&header);
        payload.push('\n');
    } else {
        // Verify the existing header matches. Read just the first line.
        let mut buf = Vec::with_capacity(header.len() + 1);
        let mut tmp = [0u8; 4096];
        // Re-open for reading from the start; the appender's cursor is at EOF.
        let mut reader = std::fs::File::open(path)?;
        loop {
            let n = reader.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.contains(&b'\n') {
                break;
            }
        }
        let existing_header = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => std::str::from_utf8(&buf[..i]).unwrap_or("").to_string(),
            None => std::str::from_utf8(&buf).unwrap_or("").to_string(),
        };
        if existing_header != header {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "CSV header mismatch in {}\n  existing: {}\n  expected: {}",
                    path.display(),
                    existing_header,
                    header,
                ),
            ));
        }
    }
    payload.push_str(&row);
    payload.push('\n');
    file.write_all(payload.as_bytes())?;
    file.flush()?;
    Ok(())
}
