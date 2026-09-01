# Benchmarks

Timing, circuit size, and proof size for the full pipeline (base, wrapper,
delegation, presentation), parameterised by the number of claims and the
maximum claim value size.

## Running

A single configuration. `--max-claim-size` is the maximum claim value length in
bytes (a multiple of 4); `--claims` must be a power of two:

```bash
cargo bench --bench bench_jwt -- --claims 8 --max-claim-size 32
```

To collect repeated samples across several claim counts (writes one CSV row per
run under `results/`, and resumes if interrupted):

```bash
./run_batch.sh
```

Parameters are env-overridable, e.g. `CLAIMS_LIST="8 16" TARGET_RUNS=10 ./run_batch.sh`.

## Circuit sizes

Gate count (pre-padding) and circuit degree `2^k` for each pipeline circuit, at
`max_claim_size = 32`:

| Claims | Base (R_Base)      | Delegation (R_Del) | Wrapper (R_Wrap) | Presentation (R_Pres) |
|-------:|-------------------:|-------------------:|-----------------:|----------------------:|
|      8 |    390,509  (2^19) |     14,757  (2^14) |   14,142  (2^14) |         7,010  (2^13) |
|     16 |    444,886  (2^19) |     14,775  (2^14) |   14,142  (2^14) |         7,024  (2^13) |
|     32 |    554,458  (2^20) |     14,811  (2^14) |   14,377  (2^14) |         7,052  (2^13) |
|     64 |    805,832  (2^20) |     14,883  (2^14) |   14,377  (2^14) |         7,108  (2^13) |
|    128 |  1,416,358  (2^21) |     15,027  (2^14) |   14,605  (2^14) |         7,220  (2^13) |

Only the base circuit parses the JWT, so its size scales with the claim count.
The delegation, wrapper, and presentation circuits operate on fixed-size proofs
and Poseidon digests; their gate counts grow only slowly with the claim count
(the Merkle commitment spans more leaves), so they stay within their degree well
beyond the configurations benchmarked here.

The presentation circuit sits one degree lower than the other two recursive
circuits because it is built with an arity-2 FRI reduction strategy
(`ConstantArityBits(1, 0)`, set in `build_presentation_circuit` in
[`src/circuits/present.rs`](../src/circuits/present.rs)). Fewer FRI folding
points mean fewer zero-knowledge blinding gates, which dominate these small
recursive circuits: the strategy removes about 5,900 gates and brings the
circuit down to `2^13`.

## Timing
The timings below were measured on a single machine:

- **CPU:** Apple M4 Pro (12 cores)
- **RAM:** 48 GB
- **OS:** macOS 26.5.2 (arm64)
- **Rust:** 1.99.0-nightly (2026-08-12)

Mean over `N` runs, with `±` denoting the relative standard deviation. Raw data is in `results/` for transparency.

| Claims |   N | Base degree | Base prove     | Delegation step | Presentation prove | Presentation cached** | Delegation verify | Presentation verify*** | Presentation size |
|-------:|----:|------------:|---------------:|----------------:|-------------------:|----------------------:|------------------:|-----------------------:|------------------:|
|      8 |  10 |        2^19 | 19.1 s ± 3.0%  | 1.17 s ± 1.1%   | 0.51 s ± 1.1%      | 0.38 s ± 1.4%         | 2.70 ms ± 0.1%    | 3.29 ms ± 0.1%         |          181.5 KB |
|     16 |  10 |        2^19 | 19.4 s ± 1.7%  | 1.18 s ± 0.7%   | 0.52 s ± 1.7%      | 0.38 s ± 3.0%         | 2.70 ms ± 0.1%    | 3.29 ms ± 0.3%         |          181.8 KB |
|     32 |  10 |        2^20 | 38.3 s ± 3.9%  | 1.17 s ± 0.7%   | 0.52 s ± 0.8%      | 0.37 s ± 2.0%         | 2.70 ms ± 0.1%    | 3.29 ms ± 0.1%         |          182.3 KB |
|     64 |  10 |        2^20 | 39.2 s ± 1.5%  | 1.17 s ± 0.9%   | 0.52 s ± 1.1%      | 0.38 s ± 2.8%         | 2.70 ms ± 0.1%    | 3.30 ms ± 0.2%         |          183.3 KB |
|   128* |  10 |        2^21 | 204.8 s ± 9.3% | 1.18 s ± 4.3%   | 0.59 s ± 5.7%      | 0.38 s ± 2.7%         | 2.72 ms ± 1.6%    | 3.35 ms ± 2.2%         |          185.3 KB |

\* The base prove time roughly doubles at each degree step, so the 128-claim run
should take about twice the 64-claim time. It takes longer here because the prover
exceeds the machine's RAM and falls back on swap, which slows the computation.
This is not a problem in practice, as the base proof is a one-time step that can run
overnight, and all steps afterwards are unaffected.

\*\* Cached-witness path: the verifier nonce is reused, so the witness is
precomputed once (~0.14 s) and shared across presentation proofs, making each
subsequent proof cheaper than the full path.

\*\*\* The presentation proof verifies more slowly than the delegation proof
despite its lower degree: the arity-2 FRI reduction strategy that shrinks the
circuit also folds the FRI codeword in smaller steps, so the proof carries more
rounds of query openings. The same trade-off makes the presentation proof larger
than the 146.8 KB delegation proof. In exchange, the lower degree roughly halves
the presentation prove time, which is the cost paid on every presentation.
