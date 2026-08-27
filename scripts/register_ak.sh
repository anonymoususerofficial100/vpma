#!/usr/bin/env bash
set -uo pipefail

ADDR="${IMMUDB_ADDR:-10.0.2.2:8443}"
HOST="${VM_HOSTNAME:-$(hostname)}"
COLL="${COLLECTION_NAME:-binary_hashes_v2}"
DTYPE="${DEPLOYMENT_TYPE:-vm}"
AKDIR="${TPM_PATH:-/var/lib/scaphandre/tpm}"
MODE="${1:-}"

command -v tpm2_createak >/dev/null 2>&1 || { echo "ERROR: tpm2-tools not installed" >&2; exit 1; }
command -v openssl      >/dev/null 2>&1 || { echo "ERROR: openssl not installed" >&2; exit 1; }

mkdir -p "$AKDIR" || exit 1

if [ ! -f "$AKDIR/ak.ctx" ]; then
    echo "Creating a new Attestation Key under $AKDIR"
    tpm2_createek -c "$AKDIR/ek.ctx" -G rsa -u "$AKDIR/ek.pub" >/dev/null 2>&1 \
      || { echo "ERROR: tpm2_createek failed" >&2; exit 1; }
    tpm2_createak -C "$AKDIR/ek.ctx" -c "$AKDIR/ak.ctx" -G rsa -g sha256 -s rsassa \
                  -u "$AKDIR/ak.pub" -f pem -n "$AKDIR/ak.name" >/dev/null 2>&1 \
      || { echo "ERROR: tpm2_createak failed" >&2; exit 1; }
else
    echo "Reusing the existing AK at $AKDIR/ak.ctx"
fi
tpm2_readpublic -c "$AKDIR/ak.ctx" -f pem -o "$AKDIR/ak_pub.pem" >/dev/null 2>&1 \
  || { echo "ERROR: could not read the AK public key" >&2; exit 1; }

if [ "$MODE" = "--tamper" ]; then
    openssl genrsa -out "$AKDIR/wrong.key" 2048 >/dev/null 2>&1
    openssl rsa -in "$AKDIR/wrong.key" -pubout -outform DER -out "$AKDIR/wrong.der" >/dev/null 2>&1
    B64=$(base64 -w0 < "$AKDIR/wrong.der")
    echo "  ⚠ registering a DELIBERATELY WRONG public key (tamper test)"
else
    openssl pkey -pubin -in "$AKDIR/ak_pub.pem" -outform DER -out "$AKDIR/ak_pub.der" >/dev/null 2>&1 \
      || { echo "ERROR: could not convert the AK public key to DER" >&2; exit 1; }
    B64=$(base64 -w0 < "$AKDIR/ak_pub.der")
fi
[ -n "$B64" ] || { echo "ERROR: empty key material" >&2; exit 1; }

SID=$(curl -sk "https://$ADDR/api/v2/authorization/session/open" -H "Content-Type: application/json" \
      -d '{"username":"immudb","password":"immudb","database":"defaultdb"}' \
      | grep -o '"sessionID":"[^"]*"' | cut -d'"' -f4)
[ -n "$SID" ] || { echo "ERROR: could not open an ImmuDB session at $ADDR" >&2; exit 1; }

STALE=$(curl -sk -X POST "https://$ADDR/api/v2/collection/$COLL/documents/search" \
    -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
    -d "{\"page\":1,\"pageSize\":100,\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"ak_pub\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"active\",\"operator\":\"EQ\",\"value\":true}]}]}}" \
    | grep -o '"hash_value":"[^"]*"' | cut -d'"' -f4 | sort -u)
for old in $STALE; do
    curl -sk -X PUT "https://$ADDR/api/v2/collection/$COLL/documents/replace" \
        -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
        -d "{\"query\":{\"expressions\":[{\"fieldComparisons\":[{\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"ak_pub\"},{\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOST\"},{\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},{\"field\":\"hash_value\",\"operator\":\"EQ\",\"value\":\"$old\"}]}]},\"document\":{\"binary_name\":\"ak_pub\",\"hostname\":\"$HOST\",\"deployment_type\":\"$DTYPE\",\"active\":false,\"hash_value\":\"$old\",\"pcr0\":\"\",\"pcr7\":\"\",\"pcr10\":\"\"}}" \
        >/dev/null 2>&1
    echo "  retired a previous AK registration (${old:0:24}…)"
done

curl -sk -X POST "https://$ADDR/api/v2/collection/$COLL/documents" \
    -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $SID" \
    -d "{\"documents\":[{\"binary_name\":\"ak_pub\",\"hash_value\":\"$B64\",\"hostname\":\"$HOST\",\"deployment_type\":\"$DTYPE\",\"active\":true,\"pcr0\":\"\",\"pcr7\":\"\",\"pcr10\":\"\"}]}" \
    >/dev/null 2>&1

echo "Registered AK for hostname '$HOST' (deployment_type=$DTYPE), ${#B64} base64 chars"
echo "  fingerprint: $(printf '%s' "$B64" | sha256sum | cut -c1-32)…"
echo
echo "The enclave now REQUIRES a TPM2_Quote from this node. A request carrying bare"
echo "PCR values, or a quote over a nonce the enclave did not issue, is refused."
