#!/usr/bin/env bash
set -uo pipefail

ADDR="${IMMUDB_ADDR:-127.0.0.1:8443}"
COLL="${COLLECTION_NAME:-binary_hashes_v3}"
HOST="${VM_NAME:-$(hostname)}"
DTYPE="${DEPLOYMENT_TYPE:-host}"
IMA="${IMA_LOG:-/home/user/ima_snap/ascii_runtime_measurements}"
TAMPER=""
[ "${1:-}" = "--tamper" ] && TAMPER="${2:-}"

[ -r "$IMA" ] || { echo "ERROR: cannot read $IMA (need a readable IMA log/snapshot)" >&2; exit 1; }

declare -A LATEST
while read -r _pcr _tdigest _tmpl fielddata path; do
    base="${path##*/}"
    stem="${base%.real}"
    case "$base" in
        swtpm|swtpm_setup) key="$base" ;;
        *)
            case "$stem" in
                qemu-system-*)
                    case "$stem" in *.*) continue ;; esac
                    key="$base" ;;
                *) continue ;;
            esac ;;
    esac
    LATEST["$key"]="${fielddata#sha256:}"
done < "$IMA"

[ "${#LATEST[@]}" -gt 0 ] && echo "Found ${#LATEST[@]} hypervisor component(s) in $IMA" || {
    echo "No qemu/swtpm measurements in $IMA." >&2
    echo "They are measured at execve, so the log must have been captured AFTER the VM was" >&2
    echo "started. Refresh it with: sudo scripts/ima_snapshot.sh" >&2
    exit 1
}

SID=$(curl -sk "https://$ADDR/api/v2/authorization/session/open" -H "Content-Type: application/json" \
      -d '{"username":"immudb","password":"immudb","database":"defaultdb"}' \
      | grep -o '"sessionID":"[^"]*"' | cut -d'"' -f4)
[ -n "$SID" ] || { echo "ERROR: could not open an ImmuDB session at $ADDR" >&2; exit 1; }

retire() {
    local name="$1" keep="$2"
    local active
    active=$(curl -sk -X POST "https://$ADDR/api/v2/collection/$COLL/documents/search" \
        -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
        -d "{\"page\":1,\"pageSize\":100,\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"$name\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"active\",\"operator\":\"EQ\",\"value\":true}]}]}}" \
        | grep -o '"hash_value":"[^"]*"' | cut -d'"' -f4 | sort -u)
    for old in $active; do
        [ "$old" = "$keep" ] && continue
        curl -sk -X PUT "https://$ADDR/api/v2/collection/$COLL/documents/replace" \
            -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
            -d "{\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"$name\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},{\"field\":\"hash_value\",\"operator\":\"EQ\",\"value\":\"$old\"}]}]},\"document\":{\"binary_name\":\"$name\",\"hostname\":\"$HOST\",\"deployment_type\":\"$DTYPE\",\"active\":false,\"hash_value\":\"$old\",\"pcr0\":\"\",\"pcr7\":\"\",\"pcr10\":\"\"}}" \
            >/dev/null 2>&1
        echo "    retired ${old:0:24}…"
    done
}

for key in "${!LATEST[@]}"; do
    hash="${LATEST[$key]}"
    if [ -n "$TAMPER" ] && [ "$key" = "$TAMPER" ]; then
        first="${hash:0:1}"; rest="${hash:1}"
        case "$first" in 0) new=1;; *) new=0;; esac
        hash="${new}${rest}"
        echo "  ⚠ $key registered with a DELIBERATELY WRONG hash (tamper test)"
    fi
    retire "$key" "$hash"
    curl -sk -X POST "https://$ADDR/api/v2/collection/$COLL/documents" \
        -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
        -d "{\"documents\":[{\"binary_name\":\"$key\",\"hash_value\":\"$hash\",\"hostname\":\"$HOST\",\"deployment_type\":\"$DTYPE\",\"active\":true,\"pcr0\":\"\",\"pcr7\":\"\",\"pcr10\":\"\"}]}" \
        >/dev/null 2>&1
    printf "  %-14s %s…\n" "$key" "${hash:0:32}"
    if ! IMMUDB_ADDR="$ADDR" bash "$(dirname "$0")/immudb_confirm.sh" \
            "$key" "$HOST" "$DTYPE" "$COLL" "$hash" >/dev/null 2>&1; then
        echo "    ✗ NOT VISIBLE to the $DTYPE enclave" >&2
        FAILED=$((FAILED + 1))
    fi
done
if [ "${FAILED:-0}" -gt 0 ]; then
    echo >&2
    echo "ERROR: $FAILED component(s) written but NOT visible to the enclave — they would be skipped." >&2
    exit 1
fi

echo
echo "Done. The host enclave now REJECTS (-12) a mismatch in any of these, instead of"
echo "logging it. swtpm in particular is the guest's root of trust, so a swap here would"
echo "otherwise have been invisible to both the host's and the guest's attestation."
