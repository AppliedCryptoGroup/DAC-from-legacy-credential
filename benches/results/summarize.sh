#!/usr/bin/env bash
# Summarize the per-run benchmark CSVs into a single summary.csv with one row
# per setup. For every metric column it reports the mean and the +/- spread as
# a percentage (100 * sample-stddev / mean). `n_runs` is how many runs were
# averaged.
#
# Run from anywhere:  ./benches/results/summarize.sh

set -euo pipefail
cd "$(dirname "$0")"

OUT="summary.csv"

FILES=()
for n in 8 16 32 64 128; do
    f="jwt_claims${n}_size32.csv"
    [[ -f "$f" ]] && FILES+=("$f")
done
[[ ${#FILES[@]} -gt 0 ]] || { echo "no jwt_claims*_size32.csv inputs found"; exit 1; }

# Output header: fixed columns + <metric>_mean,<metric>_pct for each metric
# (metrics are columns 5..end; columns 1-4 are claims, max_claim_size, run_idx,
# timestamp_ms).
awk -F, 'NR==1 {
    printf "claims,max_claim_size,n_runs";
    for (i = 5; i <= NF; i++) printf ",%s_mean,%s_pct", $i, $i;
    printf "\n";
    exit;
}' "${FILES[0]}" > "$OUT"

# One summary row per setup.
for f in "${FILES[@]}"; do
    awk -F, '
        NR == 1 { nf = NF; next }
        {
            claims = $1; maxsz = $2; n++;
            for (i = 5; i <= nf; i++) { s[i] += $i; sq[i] += $i * $i }
        }
        END {
            if (n == 0) exit;
            printf "%s,%s,%d", claims, maxsz, n;
            for (i = 5; i <= nf; i++) {
                mean = s[i] / n;
                var = (n > 1) ? (sq[i] - s[i] * s[i] / n) / (n - 1) : 0;
                if (var < 0) var = 0;          # guard tiny negative from rounding
                pct = (mean != 0) ? 100 * sqrt(var) / mean : 0;
                printf ",%.10g,%.2f", mean, pct;
            }
            printf "\n";
        }
    ' "$f" >> "$OUT"
done

echo "wrote $OUT (${#FILES[@]} setups)"
