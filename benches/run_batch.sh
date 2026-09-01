#!/usr/bin/env bash
# Batch benchmark sweep: runs bench_jwt for each config in CLAIMS_LIST a total
# of TARGET_RUNS times, appending one CSV row per run.
#
# Resume support: if a CSV already has N data rows, the loop continues from
# run_idx=N. Delete the CSV (or move it aside) to start fresh.
#
# All parameters below can be overridden via env vars, e.g.:
#   CLAIMS_LIST="8 16" TARGET_RUNS=10 ./benches/run_batch.sh
#
# Usage (long sweeps run in the background):
#   nohup ./benches/run_batch.sh > benches/results/run.out 2>&1 &

set -euo pipefail

# ---- Config (override via env) ---------------------------------------------
CLAIMS_LIST="${CLAIMS_LIST:-8 16 32 64 128}"
MAX_CLAIM_SIZE="${MAX_CLAIM_SIZE:-32}"
TARGET_RUNS="${TARGET_RUNS:-100}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
LOGS_DIR="${LOGS_DIR:-$RESULTS_DIR/logs}"

mkdir -p "$RESULTS_DIR" "$LOGS_DIR"
cd "$REPO_ROOT"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { echo "[$(ts)] $*"; }

# ---- Pre-build once so individual runs don't pay the rebuild cost ----------
log "Pre-building bench binary (cargo bench --no-run)..."
cargo bench --bench bench_jwt --no-run

# ---- Main sweep ------------------------------------------------------------
OVERALL_START=$(date +%s)

for CLAIMS in $CLAIMS_LIST; do
    CSV="$RESULTS_DIR/jwt_claims${CLAIMS}_size${MAX_CLAIM_SIZE}.csv"
    LOG="$LOGS_DIR/jwt_claims${CLAIMS}_size${MAX_CLAIM_SIZE}.log"

    # Resume: count existing data rows (file lines minus header).
    if [[ -f "$CSV" ]]; then
        TOTAL_LINES=$(wc -l < "$CSV" | tr -d ' ')
        EXISTING=$(( TOTAL_LINES > 0 ? TOTAL_LINES - 1 : 0 ))
    else
        EXISTING=0
    fi

    log "=== claims=${CLAIMS} max_claim_size=${MAX_CLAIM_SIZE} | existing=${EXISTING}/${TARGET_RUNS} ==="

    RUN_IDX=$EXISTING
    while (( RUN_IDX < TARGET_RUNS )); do
        log "claims=${CLAIMS} run=${RUN_IDX}"
        echo "[$(ts)] --- claims=${CLAIMS} run=${RUN_IDX} ---" >> "$LOG"
        cargo bench --bench bench_jwt -- \
            --claims "$CLAIMS" \
            --max-claim-size "$MAX_CLAIM_SIZE" \
            --csv-out "$CSV" \
            --run-idx "$RUN_IDX" \
            >> "$LOG" 2>&1
        RUN_IDX=$(( RUN_IDX + 1 ))
    done

    log "=== claims=${CLAIMS} done: ${RUN_IDX} total rows in $(basename "$CSV") ==="
done

OVERALL_END=$(date +%s)
ELAPSED=$(( OVERALL_END - OVERALL_START ))
log "=== Sweep complete in ${ELAPSED}s (results: $RESULTS_DIR) ==="
