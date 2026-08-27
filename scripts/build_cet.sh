#!/usr/bin/env bash
set -euo pipefail

FEATURES="${1:-use_sgx,use_sgx_vm,tpm_attestation,qemu,json,gpu}"
TRIPLE=x86_64-unknown-linux-gnu

mkdir -p target/release
if [ ! -f target/release/libscaphandre_sgx_vm.a ]; then
  printf 'int _scaphandre_sgx_vm_stub(void){return 0;}\n' > /tmp/_sgxvm_stub.c
  cc -c /tmp/_sgxvm_stub.c -o /tmp/_sgxvm_stub.o
  ar crus target/release/libscaphandre_sgx_vm.a /tmp/_sgxvm_stub.o
fi

RUSTFLAGS="-Zcf-protection=full -Crelocation-model=pic" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
cargo build -Zbuild-std -Zbuild-std-features --release --target "$TRIPLE" \
  --no-default-features --features "$FEATURES"

BIN="target/$TRIPLE/release/scaphandre"
echo "----------------------------------------------------------------"
echo "Built: $BIN"
echo "CET property : $(readelf -n "$BIN" 2>/dev/null | grep -o 'IBT, SHSTK' || echo MISSING)"
echo "ENDBR pads   : $(objdump -d "$BIN" 2>/dev/null | grep -c endbr64)"
echo "----------------------------------------------------------------"
echo "NOTE: when the GPU sensor dlopens the non-CET libnvidia-ml, glibc may relax IBT"
echo "enforcement for the process (legacy region). The CPU/RAPL build (no such dlopen)"
echo "keeps IBT fully enforced. SHSTK (return protection) is unaffected."
