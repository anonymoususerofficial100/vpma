#!/usr/bin/env bash
# Install Phoronix Test Suite (if needed) and run the VPMA benchmark campaign.
# Run as the normal user (NOT root) — PTS config is per-user.
#
#   ./scripts/run_phoronix.sh [IDENTIFIER] [RESULTS_NAME]
#     IDENTIFIER    column label for this run   (default: host-secure)
#     RESULTS_NAME  saved result-file name       (default: vpma-bench)
#     FORCE_TIMES_TO_RUN=N  runs per test        (default: 3)
#
# Compare configs by re-running with a different IDENTIFIER into the same
# RESULTS_NAME (e.g. host-secure vs host-insecure), then:
#   phoronix-test-suite show-result <RESULTS_NAME>
set -u
IDENTIFIER="${1:-host-secure}"
RESULTS_NAME="${2:-vpma-bench}"
PTS=$(command -v phoronix-test-suite || echo /usr/bin/phoronix-test-suite)

# ---- install PTS if absent ----------------------------------------------------
if [ ! -x "$PTS" ]; then
  echo "[*] Installing phoronix-test-suite..."
  sudo apt-get update
  sudo apt-get install -y php-cli php-xml wget
  wget -q https://phoronix-test-suite.com/releases/repo/pts.debian/files/phoronix-test-suite_10.8.4_all.deb -O /tmp/pts.deb
  sudo dpkg -i /tmp/pts.deb || sudo apt-get install -f -y
  rm -f /tmp/pts.deb
  PTS=$(command -v phoronix-test-suite)
fi

# ---- batch config: save results, no browser/upload/prompts, NO run-all --------
# (RunAllTestCombinations=TRUE silently overrides PRESET_OPTIONS — must be n.)
"$PTS" batch-setup <<'EOF'
y
n
n
n
n
n
n
EOF

echo "[*] Installing test profiles..."
"$PTS" batch-install pts/sysbench pts/stress-ng pts/c-ray pts/compress-7zip pts/fio pts/iperf </dev/null

export TEST_RESULTS_NAME="$RESULTS_NAME"
export TEST_RESULTS_IDENTIFIER="$IDENTIFIER"
export FORCE_TIMES_TO_RUN="${FORCE_TIMES_TO_RUN:-3}"
run() {                       # run <profile> <preset-options>
  echo "=================================================================="
  echo ">>> $1   [$2]"
  PRESET_OPTIONS="$2" "$PTS" batch-run "$1" </dev/null
}

# ---- CPU ----------------------------------------------------------------------
run pts/sysbench      "run-test=cpu"
run pts/stress-ng     "test=--cpu -1 --cpu-method all --no-rand-seed"
run pts/c-ray         "resolution=3840x2160"
run pts/compress-7zip ""
# ---- storage (FIO: io_uring, direct, 4K, /home) ------------------------------
for t in randread randwrite read write; do
  run pts/fio "type=${t};engine=io_uring;direct=1;size=4k;auto-disk-mount-points=/home"
done
# ---- network (iPerf TCP, 60s, localhost) -------------------------------------
IPERF3="$HOME/.phoronix-test-suite/installed-tests/pts/iperf-1.2.0/iperf-install/bin/iperf3"
IPERF_PID=""
[ -x "$IPERF3" ] && { "$IPERF3" -s -p 5201 >/tmp/iperf3_server.log 2>&1 & IPERF_PID=$!; sleep 1; }
run pts/iperf "server-address=127.0.0.1;positive-number=5201;duration=60;test=;parallel=1"
[ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null

echo
echo "DONE. View results:  phoronix-test-suite show-result $RESULTS_NAME"
