#!/usr/bin/env python3
import subprocess, hmac, hashlib, sys

import os as _os
RC = ["docker", "exec", "redis-sgx", "redis-cli", "--tls", "--cacert", "/certs/ca.crt",
      "-p", "6379",
      "--user", _os.environ.get("REDIS_USER", "auditor"),
      "--pass", _os.environ.get("REDIS_PASS", "changeme")]

def rc(*args):
    return subprocess.run(RC + list(args), capture_output=True, text=True).stdout.strip()

MASTER = bytes(32)

def derive_key(tenant: str) -> bytes:
    return hmac.new(MASTER, b"vm:" + tenant.encode(), hashlib.sha256).digest()

def sign(tenant: str, block_number: int, chained_root: bytes) -> str:
    key = derive_key(tenant)
    msg = b"checkpoint-v1|" + tenant.encode() + b"|" + block_number.to_bytes(8, "little") + chained_root
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def main():
    tenant = sys.argv[1] if len(sys.argv) > 1 else "e5gpu"
    print(f"=== Chain-head anchor audit (tenant={tenant}) ===")

    line = rc("GET", f"gpu_checkpoint:{tenant}")
    if not line:
        print(f"[ANCHOR] FAIL: no anchor for '{tenant}' (fail-closed)")
        sys.exit(1)
    try:
        _, t, bn_s, root_hex, sig_hex = line.split("|")
        bn = int(bn_s)
    except ValueError:
        print(f"[ANCHOR] FAIL: malformed anchor: {line!r}")
        sys.exit(1)

    expect = sign(t, bn, bytes.fromhex(root_hex))
    sig_ok = hmac.compare_digest(expect, sig_hex)
    print(f"[ANCHOR] signature: {'OK VALID' if sig_ok else 'FAIL INVALID (forged anchor)'}")
    print(f"[ANCHOR] anchored: block_number={bn} chained_root={root_hex[:16]}...")

    keys = [k for k in rc("KEYS", "block:*").split() if k]
    latest_bn, latest_root, matched_root = -1, None, None
    for k in keys:
        if rc("HGET", k, "vm_name") != t:
            continue
        kbn = int(rc("HGET", k, "block_number"))
        kroot = rc("HGET", k, "chained_root")
        if kbn > latest_bn:
            latest_bn, latest_root = kbn, kroot
        if kbn == bn:
            matched_root = kroot

    head_ok = (matched_root == root_hex)
    latest_ok = (bn == latest_bn)
    print(f"[ANCHOR] redis block {bn} chained_root: "
          f"{'OK MATCH' if head_ok else 'FAIL MISMATCH (' + str(matched_root)[:16] + '...)'}")
    print(f"[ANCHOR] anchor is the latest head: "
          f"{'OK YES' if latest_ok else 'FAIL NO (latest block=' + str(latest_bn) + ')'}")

    ok = sig_ok and head_ok and latest_ok
    print("=" * 60)
    if ok:
        print("[ANCHOR] OK VERIFIED - Redis chain head matches the SGX-signed anchor")
    else:
        print("[ANCHOR] FAIL TAMPERED - Redis chain head does NOT match the SGX-signed anchor")
    sys.exit(0 if ok else 2)

if __name__ == "__main__":
    main()
