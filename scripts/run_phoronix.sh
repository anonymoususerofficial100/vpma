#!/usr/bin/env bash
set -u
IDENTIFIER="${1:-host-secure}"
RESULTS_NAME="${2:-vpma-bench}"
PTS=$(command -v phoronix-test-suite || echo /usr/bin/phoronix-test-suite)

if [ ! -x "$PTS" ]; then
  echo "[*] Installing phoronix-test-suite..."
  sudo apt-get update
  sudo apt-get install -y php-cli php-xml wget
  wget -q https://phoronix-test-suite.com/releases/repo/pts.debian/files/phoronix-test-suite_10.8.4_all.deb -O /tmp/pts.deb
  sudo dpkg -i /tmp/pts.deb || sudo apt-get install -f -y
  rm -f /tmp/pts.deb
  PTS=$(command -v phoronix-test-suite)
fi

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
run() {
  echo "=================================================================="
  echo ">>> $1   [$2]"
  PRESET_OPTIONS="$2" "$PTS" batch-run "$1" </dev/null
}

run pts/sysbench      "run-test=cpu"
run pts/stress-ng     "test=--cpu -1 --cpu-method all --no-rand-seed"
run pts/c-ray         "resolution=3840x2160"
run pts/compress-7zip ""
for t in randread randwrite read write; do
  run pts/fio "type=${t};engine=io_uring;direct=1;size=4k;auto-disk-mount-points=/home"
done
IPERF3="$HOME/.phoronix-test-suite/installed-tests/pts/iperf-1.2.0/iperf-install/bin/iperf3"
IPERF_PID=""
[ -x "$IPERF3" ] && { "$IPERF3" -s -p 5201 >/tmp/iperf3_server.log 2>&1 & IPERF_PID=$!; sleep 1; }
run pts/iperf "server-address=127.0.0.1;positive-number=5201;duration=60;test=;parallel=1"
[ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null

echo
echo "DONE. View results:  phoronix-test-suite show-result $RESULTS_NAME"
