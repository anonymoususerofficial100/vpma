#!/usr/bin/env bash
set -uo pipefail

NAME="${1:-}"; HOST="${2:-}"; DTYPE="${3:-}"; COLL="${4:-}"; WANT="${5:-}"
ADDR="${IMMUDB_ADDR:-127.0.0.1:8443}"

[ -n "$NAME" ] && [ -n "$HOST" ] && [ -n "$DTYPE" ] && [ -n "$COLL" ] || {
    echo "usage: $0 <binary_name> <hostname> <deployment_type> <collection> [expected_hash]" >&2
    exit 2; }

SID=$(curl -sk "https://$ADDR/api/v2/authorization/session/open" -H "Content-Type: application/json" \
      -d '{"username":"immudb","password":"immudb","database":"defaultdb"}' \
      | grep -o '"sessionID":"[^"]*"' | cut -d'"' -f4)
[ -n "$SID" ] || { echo "CONFIRM FAIL: no ImmuDB session at $ADDR" >&2; exit 1; }

FOUND=$(curl -sk -X POST "https://$ADDR/api/v2/collection/$COLL/documents/search" \
    -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
    -d "{\"page\":1,\"pageSize\":20,\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"$NAME\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},{\"field\":\"active\",\"operator\":\"EQ\",\"value\":true}]}]}}" \
    | grep -o '"hash_value":"[^"]*"' | cut -d'"' -f4)

COUNT=$(printf '%s' "$FOUND" | grep -c . || true)

if [ "$COUNT" -eq 0 ]; then
    echo "CONFIRM FAIL: nothing active matches ($NAME, $HOST, $DTYPE) in $COLL." >&2
    echo "  The enclave will treat this component as UNREGISTERED and skip verifying it." >&2
    echo "  Usual cause: wrong deployment_type or wrong collection." >&2
    echo "    host  enclave reads binary_hashes_v3, deployment_type 'host'" >&2
    echo "    guest enclave reads binary_hashes_v2, deployment_type 'vm'" >&2
    exit 1
fi

if [ "$COUNT" -gt 1 ]; then
    UNIQ=$(printf '%s\n' "$FOUND" | sort -u | grep -c . || true)
    if [ "$UNIQ" -gt 1 ]; then
        echo "CONFIRM FAIL: $COUNT active rows with $UNIQ DIFFERENT hashes for $NAME." >&2
        echo "  The enclave asks for one and gets an arbitrary one — retire the stale rows:" >&2
        echo "    scripts/immudb_retire.sh $NAME $HOST <hash-to-keep>" >&2
        exit 1
    fi
fi

GOT=$(printf '%s\n' "$FOUND" | head -1)
if [ -n "$WANT" ] && [ "$GOT" != "$WANT" ]; then
    echo "CONFIRM FAIL: $NAME resolves to ${GOT:0:24}… but ${WANT:0:24}… was expected." >&2
    exit 1
fi

echo "  confirmed: $NAME -> ${GOT:0:24}… (visible to the $DTYPE enclave via $COLL)"
exit 0
