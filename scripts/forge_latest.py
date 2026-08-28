#!/usr/bin/env python3
import subprocess, hashlib, sys, json, os

RC = ["docker", "exec", "redis-sgx", "redis-cli", "--tls", "--cacert", "/certs/ca.crt",
      "-p", "6379", "--user", "sgx", "--pass", "changeme"]

def rc(*args):
    return subprocess.run(RC + list(args), capture_output=True, text=True).stdout.strip()

def leaf_hash(pid, cpu_time, energy, power, vm_name, timestamp):
    s = f"{pid}|{float(cpu_time):.6f}|{float(energy):.6f}|{float(power):.6f}|{vm_name}|{timestamp}"
    return hashlib.sha256(s.encode()).digest()

def build_merkle_root(leaves):
    if not leaves:
        return b"\x00" * 32
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0]

def latest_block_id(tenant):
    best_id, best_bn = None, -1
    for k in rc("KEYS", "block:*").split():
        if rc("HGET", k, "vm_name") != tenant:
            continue
        bn = int(rc("HGET", k, "block_number"))
        if bn > best_bn:
            best_bn, best_id = bn, k.split(":")[1]
    return best_id, best_bn

def main():
    tenant = sys.argv[1] if len(sys.argv) > 1 else "e5gpu"
    bk = f"/tmp/forge_backup_{tenant}.json"

    if len(sys.argv) > 2 and sys.argv[2] == "restore":
        b = json.load(open(bk))
        rc("LSET", f"records:{b['id']}", "0", b["rec0"])
        rc("HSET", f"block:{b['id']}", "merkle_root", b["merkle"])
        rc("HSET", f"block:{b['id']}", "chained_root", b["chained"])
        print(f"restored block:{b['id']}")
        return

    bid, bn = latest_block_id(tenant)
    if bid is None:
        print("no block for tenant"); sys.exit(1)
    recs = rc("LRANGE", f"records:{bid}", "0", "-1").splitlines()
    prev_chained = rc("HGET", f"block:{bid}", "prev_chained_root")
    rec0 = recs[0]
    json.dump({"id": bid, "rec0": rec0,
               "merkle": rc("HGET", f"block:{bid}", "merkle_root"),
               "chained": rc("HGET", f"block:{bid}", "chained_root")}, open(bk, "w"))

    lh, pid, cpu, energy, power, vm, ts = rec0.split("|", 6)
    new_energy = float(energy) * 2.0
    new_leaf = leaf_hash(pid, cpu, new_energy, power, vm, ts)
    new_rec0 = f"{new_leaf.hex()}|{pid}|{cpu}|{new_energy}|{power}|{vm}|{ts}"

    leaves = [new_leaf] + [bytes.fromhex(r.split("|", 1)[0]) for r in recs[1:]]
    new_merkle = build_merkle_root(leaves)
    new_chained = hashlib.sha256(bytes.fromhex(prev_chained) + new_merkle).digest()

    rc("LSET", f"records:{bid}", "0", new_rec0)
    rc("HSET", f"block:{bid}", "merkle_root", new_merkle.hex())
    rc("HSET", f"block:{bid}", "chained_root", new_chained.hex())
    print(f"FORGED block:{bid} (block_number={bn}): energy {energy} -> {new_energy} J")
    print(f"  new merkle_root  = {new_merkle.hex()[:16]}...  (recomputed, internally consistent)")
    print(f"  new chained_root = {new_chained.hex()[:16]}...  (= SHA256(prev||merkle))")
    print("  --all/--chain will PASS (consistent); the signed anchor will NOT match.")

if __name__ == "__main__":
    main()
