#!/usr/bin/env bash
set -uo pipefail
A="${IMMUDB_ADDR:-10.0.2.2:8443}"
HOSTN="${VM_HOSTNAME:-vpma-guest1}"
BIN="${VM_BINARY_PATH:-/home/vpma/scaphandre}"
COLL=binary_hashes_v2
DTYPE=vm

HASH=$(sha256sum "$BIN" | cut -d' ' -f1)
echo "  binary   $BIN"
echo "  hash     $HASH"
echo "  hostname $HOSTN   collection $COLL   deployment_type $DTYPE"
echo

TOK=$(curl -sk -X POST "https://$A/api/v2/authorization/session/open" \
  -H "Content-Type: application/json" \
  -d '{"username":"immudb","password":"immudb","database":"defaultdb"}' \
  | grep -o '"sessionID":"[^"]*"' | cut -d'"' -f4)
[ -n "$TOK" ] || { echo "  ERROR: could not open immudb session at $A"; exit 1; }

search() {
  curl -sk -X POST "https://$A/api/v2/collection/$COLL/documents/search" \
    -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $TOK" \
    -d "{\"page\":1,\"pageSize\":50,\"query\":{\"expressions\":[{\"fieldComparisons\":[
        {\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"scaphandre\"},
        {\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOSTN\"},
        {\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},
        {\"field\":\"active\",\"operator\":\"EQ\",\"value\":true}]}]}}"
}

echo "BEFORE:"
search | python3 -c '
import sys,json
d=json.load(sys.stdin); revs=d.get("revisions",[])
print("  %d active row(s)" % len(revs))
for r in revs:
    doc=r.get("document",{})
    print("    " + str(doc.get("hash_value"))[:64])
'

OLD=$(search | python3 -c '
import sys,json
d=json.load(sys.stdin)
for r in d.get("revisions",[]):
    h=str(r.get("document",{}).get("hash_value",""))
    if h: print(h)
' 2>/dev/null | sort -u)

for old in $OLD; do
  echo "  retiring $old"
  curl -sk -X PUT "https://$A/api/v2/collection/$COLL/documents/replace" \
    -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $TOK" \
    -d "{\"query\":{\"expressions\":[{\"fieldComparisons\":[
          {\"field\":\"binary_name\",\"operator\":\"EQ\",\"value\":\"scaphandre\"},
          {\"field\":\"hostname\",\"operator\":\"EQ\",\"value\":\"$HOSTN\"},
          {\"field\":\"deployment_type\",\"operator\":\"EQ\",\"value\":\"$DTYPE\"},
          {\"field\":\"hash_value\",\"operator\":\"EQ\",\"value\":\"$old\"}]}]},
        \"document\":{\"binary_name\":\"scaphandre\",\"hostname\":\"$HOSTN\",
          \"deployment_type\":\"$DTYPE\",\"active\":false,\"hash_value\":\"$old\",
          \"pcr0\":\"\",\"pcr7\":\"\",\"pcr10\":\"\"}}" >/dev/null
done

PCRS="${VPMA_PLATFORM_PCRS:-4,2}"
PCR_A="${PCRS%%,*}"; PCR_B="${PCRS##*,}"
PCRDIR=/sys/class/tpm/tpm0/pcr-sha256
PCR0=""; PCR7=""
if [ -r "$PCRDIR/$PCR_A" ] && [ -r "$PCRDIR/$PCR_B" ]; then
  PCR0=$(tr 'A-Z' 'a-z' < "$PCRDIR/$PCR_A" | tr -d '[:space:]')
  PCR7=$(tr 'A-Z' 'a-z' < "$PCRDIR/$PCR_B" | tr -d '[:space:]')
fi
if [ -z "$PCR0" ] || [ -z "$PCR7" ]; then
  echo "  WARNING: PCR$PCR_A/PCR$PCR_B unreadable — registering WITHOUT them."
  echo "           admit_boot accepts unrecorded PCRs, so this weakens the check silently."
else
  echo "  platform PCRs: $PCR_A,$PCR_B  (must match VPMA_PLATFORM_PCRS in the collector)"
  echo "    PCR$PCR_A = ${PCR0:0:24}...   (boot loader, if 4)"
  echo "    PCR$PCR_B = ${PCR7:0:24}...   (option ROMs / GPU VBIOS, if 2)"
  if [ "$PCR0" = "$PCR7" ]; then
    echo "  WARNING: the two values are IDENTICAL — that is the signature of separator-only"
    echo "           extends. You are probably registering PCRs this firmware does not measure."
  fi
fi

echo "  registering $HASH"
curl -sk -X POST "https://$A/api/v2/collection/$COLL/documents" \
  -H "Content-Type: application/json" -H "Grpc-Metadata-SessionID: $TOK" \
  -d "{\"documents\":[{\"binary_name\":\"scaphandre\",\"hash_value\":\"$HASH\",
        \"hostname\":\"$HOSTN\",\"deployment_type\":\"$DTYPE\",\"active\":true,
        \"pcr0\":\"$PCR0\",\"pcr7\":\"$PCR7\",\"pcr10\":\"\"}]}" >/dev/null

echo
echo "AFTER:"
search | WANT="$HASH" python3 -c '
import sys,json,os
want=os.environ["WANT"]
d=json.load(sys.stdin); revs=d.get("revisions",[])
print("  %d active row(s)" % len(revs))
ok=False
for r in revs:
    h=str(r.get("document",{}).get("hash_value",""))
    mark = " <-- the new binary" if h==want else ""
    if h==want: ok=True
    print("    "+h[:64]+mark)
print("  RESULT:", "exactly one active row and it is the new binary" if (ok and len(revs)==1)
      else ("MORE THAN ONE ACTIVE ROW - the enclave may pick the wrong one" if ok else "NEW HASH NOT ACTIVE - registration did not take"))
'
