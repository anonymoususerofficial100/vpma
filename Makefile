TRIPLE := x86_64-unknown-linux-gnu
BIN    := target/$(TRIPLE)/release/scaphandre

.PHONY: all secure safestack gpu-ebpf cpu verify clean enclaves

all: secure

SGX_TARGET  := x86_64-fortanix-unknown-sgx
SGX_ENV     := LIBCLANG_PATH=/usr/lib/llvm-14/lib \
               BINDGEN_EXTRA_CLANG_ARGS="-idirafter /usr/lib/gcc/x86_64-linux-gnu/12/include" \
               CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-Clinker=cc" \
               CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
               CARGO_TARGET_X86_64_FORTANIX_UNKNOWN_SGX_RUSTFLAGS="-Crelocation-model=pic"

SGX_HEAP_HOST := 0x30000000
SGX_HEAP_VM   := 0x4000000

SGX_SIGNING_KEY ?= /home/user/enclave-keys/enclave-signing.pem

enclaves:
	cd sgx    && $(SGX_ENV) cargo build --release --target $(SGX_TARGET) --features use_mbedtls
	cd sgx_vm && $(SGX_ENV) cargo build --release --target $(SGX_TARGET) --features use_mbedtls
	ftxsgx-elf2sgxs target/$(SGX_TARGET)/release/sgx \
	    --heap-size $(SGX_HEAP_HOST) --stack-size 0x100000 --threads 16 \
	    -o target/$(SGX_TARGET)/release/sgx.sgxs
	ftxsgx-elf2sgxs target/$(SGX_TARGET)/release/sgx_vm \
	    --heap-size $(SGX_HEAP_VM) --stack-size 0x100000 --threads 16 \
	    -o target/$(SGX_TARGET)/release/sgx_vm.sgxs
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@
	@if [ ! -r "$(SGX_SIGNING_KEY)" ]; then \
	    echo "ERROR: no enclave signing key at $(SGX_SIGNING_KEY)."; \
	    echo "       Refusing to ship enclaves that would load DEBUG under the crate's public dummy key."; \
	    echo "       Generate one:  openssl genrsa -3 -out $(SGX_SIGNING_KEY) 3072 && chmod 600 $(SGX_SIGNING_KEY)"; \
	    exit 1; \
	fi
	sgxs-sign --key $(SGX_SIGNING_KEY) target/$(SGX_TARGET)/release/sgx.sgxs    target/$(SGX_TARGET)/release/sgx.sig
	sgxs-sign --key $(SGX_SIGNING_KEY) target/$(SGX_TARGET)/release/sgx_vm.sgxs target/$(SGX_TARGET)/release/sgx_vm.sig
	@echo
	@ls -l target/$(SGX_TARGET)/release/sgx.sgxs target/$(SGX_TARGET)/release/sgx_vm.sgxs \
	       target/$(SGX_TARGET)/release/sgx.sig target/$(SGX_TARGET)/release/sgx_vm.sig
	@echo "Signed non-debug. Deploy the .sig ALONGSIDE the .sgxs -- enclave-runner looks for"
	@echo "<name>.sig next to <name>.sgxs, and silently falls back to the crate's public dummy"
	@echo "key (and DEBUG) if it is missing."
	@echo "Both enclave images rebuilt. Point the runtime at these exact paths with"
	@echo "SGX_ENCLAVE_PATH / SGX_VM_ENCLAVE_PATH (a set-but-missing path is now fatal, not silently"
	@echo "replaced by whatever else is on disk)."

secure:
	./scripts/build_cet.sh "gpu_secure"

safestack:
	RUSTFLAGS="-Zsanitizer=safestack -Crelocation-model=pic" \
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
	cargo build -Zbuild-std --release --target $(TRIPLE) --no-default-features --features "gpu_secure"

gpu-ebpf:
	./scripts/build_cet.sh "gpu_secure,with_gpu_ebpf"

cfi:
	./cfi-setup.sh

cpu:
	./scripts/build_cet.sh "use_sgx,tpm_attestation,qemu,json"

verify:
	@echo "CET markers  : $$(readelf -n $(BIN) 2>/dev/null | grep -o 'IBT, SHSTK' | head -1 || echo MISSING)"
	@echo "ENDBR pads   : $$(objdump -d $(BIN) 2>/dev/null | grep -c endbr64)"
	@echo "kernel       : $$(uname -r)  (userspace CET needs >= 6.6)"
	@echo "CPU CET      : $$(grep -oE 'user_shstk|cet_ss|cet_ibt' /proc/cpuinfo | sort -u | paste -sd' ' - || echo 'none advertised')"
	@echo "ENFORCED?    : $$(grep -qE 'user_shstk|ibt' /proc/cpuinfo && echo 'CPU+kernel expose CET — likely enforced' || echo 'NO — markers are inert NOPs on this CPU/kernel (see CFI_NOTES.md §3)')"

clean:
	cargo clean
