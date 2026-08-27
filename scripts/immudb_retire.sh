#!/usr/bin/env bash
set -uo pipefail

NAME="${1:-}"
HOST="${2:-}"
KEEP="${3:-}"
ADDR="${IMMUDB_ADDR:-10.0.2.2:8443}"
COLL="${COLLECTION_NAME:-binary_hashes_v2}"
DTYPE="${DEPLOYMENT_TYPE:-vm}"

[ -n "$NAME" ] && [ -n "$HOST" ] || {
    echo "usage: $0 <binary_name> <hostname> [keep_hash]" >&2; exit 1; }

SID=$(curl -sk "https://$ADDR/api/v2/authorization/session/open" -H "Content-Type: application/json" \
      -d '{"username":"immudb","password":"immudb","database":"defaultdb"}' \
      | grep -o '"sessionID":"[^"]*"' | cut -d'"' -f4)
[ -n "$SID" ] || { echo "ERROR: could not open an ImmuDB session at $ADDR" >&2; exit 1; }

ACTIVE=$(curl -sk -X POST "https://$ADDR/api/v2/collection/$COLL/documents/search" \
    -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
    -d "{\"page\":1,\"pageSize\":100,\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"$NAME\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},{\"field\":\"active\",\"operator\":\"EQ\",\"value\":true}]}]}}" \
    | grep -o '"hash_value":"[^"]*"' | cut -d'"' -f4 | sort -u)

[ -n "$ACTIVE" ] || { echo "no active '$NAME' registrations for $HOST"; exit 0; }

n=0
for h in $ACTIVE; do
    if [ -n "$KEEP" ] && [ "$h" = "$KEEP" ]; then
        echo "  keeping  ${h:0:24}…"
        continue
    fi
    curl -sk -X PUT "https://$ADDR/api/v2/collection/$COLL/documents/replace" \
        -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
        -d "{\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"$NAME\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},{\"field\":\"hash_value\",\"operator\":\"EQ\",\"value\":\"$h\"}]}]},\"document\":{\"binary_name\":\"$NAME\",\"hostname\":\"$HOST\",\"deployment_type\":\"$DTYPE\",\"active\":false,\"hash_value\":\"$h\",\"pcr0\":\"\",\"pcr7\":\"\",\"pcr10\":\"\"}}" \
        >/dev/null 2>&1
    echo "  retired  ${h:0:24}…"
    n=$((n + 1))
done
echo "Retired $n stale '$NAME' registration(s) for $HOST."
