#!/usr/bin/env bash
# Manual checks for GET /v1/events/samples against a running app with generated data.
#
# Usage:
#   ./scripts/check-samples.sh                    # app on http://localhost:8080
#   BASE_URL=http://host:8080 ./scripts/check-samples.sh
#
# Needs: curl, python3 (to read the JSON)

BASE_URL="${BASE_URL:-http://localhost:8080}"
SAMPLES="$BASE_URL/v1/events/samples"
STATS="$BASE_URL/v1/stats/summary"

# ISO-8601 UTC time, shifted by N hours from now (works on macOS and Linux)
hours_from_now() {
  date -u -v"${1}H" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} hours" +%Y-%m-%dT%H:%M:%SZ
}

# Reads one field from the JSON on stdin, e.g. json_field total
json_field() {
  python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"
}

echo "Samples checks against $SAMPLES"

echo
echo "=== 1. Defaults (expect limit 20, offset 0, 20 events) ==="
curl -s "$SAMPLES" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("total =", d["total"], " limit =", d["limit"], " offset =", d["offset"], " events returned =", len(d["events"]))'

echo
echo "=== 2. One event in full (nested rule and geoLocation, plus enrichment) ==="
curl -s "$SAMPLES?limit=1" | python3 -m json.tool

echo
echo "=== 3. Newest first (timestamps must go down) ==="
curl -s "$SAMPLES?limit=100" | python3 -c '
import sys, json
times = [e["timestamp"] for e in json.load(sys.stdin)["events"]]
print("first:", times[0], " last:", times[-1])
print("sorted newest first:", all(times[i] >= times[i + 1] for i in range(len(times) - 1)))'

echo
echo "=== 4. Paging (page 1 and page 2 of size 5 must not overlap) ==="
PAGE1=$(curl -s "$SAMPLES?limit=5&offset=0")
PAGE2=$(curl -s "$SAMPLES?limit=5&offset=5")
echo "Page 1: $(echo "$PAGE1" | python3 -c 'import sys,json; print([e["eventId"] for e in json.load(sys.stdin)["events"]])')"
echo "Page 2: $(echo "$PAGE2" | python3 -c 'import sys,json; print([e["eventId"] for e in json.load(sys.stdin)["events"]])')"
python3 -c '
import sys, json
p1 = {e["eventId"] for e in json.loads(sys.argv[1])["events"]}
p2 = {e["eventId"] for e in json.loads(sys.argv[2])["events"]}
print("overlap:", p1 & p2 or "none")' "$PAGE1" "$PAGE2"

echo
echo "=== 5. Filters: totals per category add up to the overall total ==="
TOTAL=$(curl -s "$SAMPLES?limit=1" | json_field total)
SUM=0
for CATEGORY in INJECTION XSS PROTOCOL_VIOLATION DATA_LEAKAGE BOT DOS RATE_LIMIT; do
  COUNT=$(curl -s "$SAMPLES?category=$CATEGORY&limit=1" | json_field total)
  printf "%-20s %s\n" "$CATEGORY" "$COUNT"
  SUM=$((SUM + COUNT))
done
echo "Sum: $SUM (should equal $TOTAL)"

echo
echo "=== 6. Combined filters (every returned event must match) ==="
curl -s "$SAMPLES?configId=14227&category=INJECTION&action=DENY&limit=100" | python3 -c '
import sys, json
d = json.load(sys.stdin)
ok = all(e["configId"] == 14227 and e["rule"]["category"] == "INJECTION" and e["action"] == "DENY" for e in d["events"])
print("configId=14227 + INJECTION + DENY: total =", d["total"], " returned =", len(d["events"]), " all match:", ok)'

echo
echo "=== 7. Samples and stats agree on the same window ==="
FROM=$(hours_from_now -3)
TO=$(hours_from_now +1)
SAMPLES_TOTAL=$(curl -s "$SAMPLES?from=$FROM&to=$TO&limit=1" | json_field total)
STATS_TOTAL=$(curl -s "$STATS?from=$FROM&to=$TO" | json_field totalEvents)
echo "$FROM -> $TO: samples total = $SAMPLES_TOTAL, stats total = $STATS_TOTAL"

echo
echo "=== 8. Enrichment is consistent (attackType matches category, score 0-100) ==="
curl -s "$SAMPLES?limit=100" | python3 -c '
import sys, json
expected = {"INJECTION": "SQL/Command Injection", "XSS": "Cross-Site Scripting",
            "PROTOCOL_VIOLATION": "Protocol Anomaly", "DATA_LEAKAGE": "Data Exfiltration",
            "BOT": "Bot Activity", "DOS": "Denial of Service", "RATE_LIMIT": "Rate Limiting"}
events = json.load(sys.stdin)["events"]
print("attackType matches category:", all(expected[e["rule"]["category"]] == e["attackType"] for e in events))
print("threatScore within 0-100:", all(0 <= e["threatScore"] <= 100 for e in events))'

echo
echo "=== 9. Bad requests (expect HTTP 400) ==="
check_400() {
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "$2")
  echo "$1: HTTP $CODE"
}
check_400 "limit=0           " "$SAMPLES?limit=0"
check_400 "limit=101         " "$SAMPLES?limit=101"
check_400 "offset=-1         " "$SAMPLES?offset=-1"
check_400 "Unknown category  " "$SAMPLES?category=SQLI"
check_400 "Unknown action    " "$SAMPLES?action=BLOCK"
check_400 "from after to     " "$SAMPLES?from=$TO&to=$FROM"
check_400 "Bad date format   " "$SAMPLES?from=yesterday"
