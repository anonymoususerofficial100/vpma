# VPMA — Verifiable Power Metrics Architecture

A hardened Scaphandre fork: energy measurements are computed inside an SGX enclave,
bound to a TPM2 quote + IMA binary-hash attestation, HMAC/Merkle chained, and stored
for offline cryptographic verification. Host reads RAPL (CPU) or NVML (GPU); guests
read host-measured energy over a 9p share and attest remotely.

## Prerequisites

- Rust `nightly` + `stable`, both with the `x86_64-fortanix-unknown-sgx` target
- SGX hardware + driver (`/dev/sgx_enclave` on FLC, or legacy `isgx` + `aesmd` on non-FLC)
- `fortanix-sgx-tools` + `sgxs-tools` (`cargo install`), `clang`/`llvm` + `libclang`, `cmake`
- `libbpfcc-dev` (eBPF), `tpm2-tools`, `openssl`
- Running **ImmuDB** (TLS, `127.0.0.1:8443`) for the hash registry; **Redis** (TLS, `:6379`) for the GPU block store
- An enclave signing key: `openssl genrsa -3 -out ~/enclave-keys/enclave-signing.pem 3072`

The enclaves and host embed TLS certs at compile time (`enclave_ca.pem`, `immudb_ca.pem`,
`sgx*/enclave_{cert,key}.pem`). **Placeholder certs ship with the artifact — replace them with
your own (matching your live ImmuDB/Redis) before building.**

## Build

**Host binary** (`build_cet.sh` takes the feature set):

```bash
# CPU
./scripts/build_cet.sh "use_sgx,tpm_attestation,qemu,json,with_ebpf_kernel_read"
# GPU
./scripts/build_cet.sh "gpu_secure,with_gpu_ebpf,with_ebpf_guard"
# output: target/x86_64-unknown-linux-gnu/release/scaphandre
cp target/x86_64-unknown-linux-gnu/release/scaphandre target/release/scaphandre
```

**Enclaves** (`sgx/` = host verifier, `sgx_vm/` = guest verifier):

```bash
make enclaves        # builds both, elf2sgxs, operator-signs -> sgx.sgxs / sgx_vm.sgxs (+ .sig)
```

Adjust for your machine: `LIBCLANG_PATH` (default `llvm-14`), `SGX_HEAP_HOST` (must fit your EPC —
the host verifier parses the full IMA log, so size accordingly), `SGX_SIGNING_KEY`. On a **non-FLC**
CPU, debug-sign instead: `sgxs-sign -d --key <key> <name>.sgxs <name>.sig`.

## Register (required — the enclave refuses an unregistered binary)

The AK registry makes a signed TPM2 quote mandatory. Register the AK once, then the binary hash
after **every** rebuild (the hash changes each time):

```bash
export IMMUDB_ADDR=127.0.0.1:8443 COLLECTION_NAME=binary_hashes_v3 DEPLOYMENT_TYPE=host
TPM_PATH=/dev/shm/scaph_tpm VM_HOSTNAME=$(hostname) bash scripts/register_ak.sh
bash scripts/register_binary_hash.sh          # reads ./target/release/scaphandre
bash scripts/register_hypervisor_hashes.sh    # host only: qemu + swtpm TCB hashes
```

## Run (needs root)

**CPU — host:**

```bash
sudo env TPM_PATH=/dev/shm/scaph_tpm IMMUDB_ADDR=127.0.0.1:8443 \
  IMMUDB_CA_CERT=/path/to/immudb_ca.crt \
  SGX_ENCLAVE_PATH=$PWD/target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs \
  ./target/x86_64-unknown-linux-gnu/release/scaphandre qemu
```

**GPU — host:**

```bash
sudo env TPM_PATH=/dev/shm/scaph_tpm IMMUDB_ADDR=127.0.0.1:8443 \
  IMMUDB_CA_CERT=/path/to/immudb_ca.crt REDIS_URL=redis://127.0.0.1:6379 \
  SGX_ENCLAVE_PATH=$PWD/target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs \
  SGX_VM_ENCLAVE_PATH=$PWD/target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs \
  SCAPH_GPU_STEP_MS=500 ./target/release/scaphandre --sensor gpu gpu-db
```

**Guest** (built on the host, copied into the VM; runs against the host's `sgx_vm` enclave in remote mode):
register with `scripts/register_guest_binary_hash.sh`, then run `scaphandre --vm db` (CPU) or
`scaphandre --sensor gpu gpu-db` (GPU) with `IMMUDB_ADDR` pointing at the host.

A successful boot logs `Verification PASSED inside real SGX enclave` and then emits per-cycle
`VM energy computed inside REAL SGX enclave` with an advancing chain counter.

## Offline verification

Recorded energy blocks are re-checked out of the enclave using its own verified encoders:

```bash
cargo build -p vpma-verified-ffi --release      # builds libvpma_ffi.so (required by the auditors)
python3 scripts/verify_redis_data.py --all      # CPU chain; --block/--record/--chain for scopes
python3 scripts/verify_redis_gpu.py --all       # GPU chain
python3 scripts/anchor_verify.py <tenant>       # verify the enclave-signed chain-head anchor
```

## Layout

- `src/` host collector + exporters, `sgx/` host enclave, `sgx_vm/` guest enclave
- `verified/` Verus-verified core, `verified-ffi/` C-ABI shim for the offline auditors
- `scripts/` registration, attack demo, power-overhead, offline verification
- `sapic/` Tamarin formal proofs
- `*.c` eBPF file-access guards + memory-protection probes
