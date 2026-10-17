#!/usr/bin/env bash
# Manual checks for GET /v1/stats/summary against a running app with generated data.
#
# Usage:
#   ./scripts/check-stats.sh                      # app on http://localhost:8080
#   BASE_URL=http://host:8080 ./scripts/check-stats.sh
#
# Needs: curl, python3 (to read the JSON)

BASE_URL="${BASE_URL:-http://localhost:8080}"
STATS="$BASE_URL/v1/stats/summary"

# ISO-8601 UTC time, shifted by N hours from now (works on macOS and Linux)
hours_from_now() {
  date -u -v"${1}H" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} hours" +%Y-%m-%dT%H:%M:%SZ
}

# Reads one field from the JSON on stdin, e.g. json_field totalEvents
json_field() {
  python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"
}

# The generator creates events over the last 6 hours, so this window covers all of them
FROM=$(hours_from_now -7)
TO=$(hours_from_now +1)

echo "Stats checks against $STATS"
echo "Window: $FROM -> $TO"

echo
echo "=== 1. Totals ==="
TOTAL=$(curl -s "$STATS?from=$FROM&to=$TO" | json_field totalEvents)
echo "All configs: $TOTAL"
SUM=0
for CONFIG in 14227 14228 31001; do
  COUNT=$(curl -s "$STATS?configId=$CONFIG&from=$FROM&to=$TO" | json_field totalEvents)
  echo "Config $CONFIG: $COUNT"
  SUM=$((SUM + COUNT))
done
echo "Sum of configs: $SUM (should equal $TOTAL)"

echo
echo "=== 2. byAction adds up to totalEvents ==="
curl -s "$STATS?from=$FROM&to=$TO" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(d["byAction"], "sum =", sum(d["byAction"].values()), "total =", d["totalEvents"])'

echo
echo "=== 3. byCategory (all 7 categories, zero-filled) ==="
curl -s "$STATS?from=$FROM&to=$TO" | python3 -c '
import sys, json
for name, s in json.load(sys.stdin)["byCategory"].items():
    print("%-20s count=%5d  avg=%s" % (name, s["count"], s["avgThreatScore"]))'

echo
echo "=== 4. Top attackers (expect mostly wave IPs 198.51.100.x) ==="
curl -s "$STATS?from=$FROM&to=$TO" | python3 -c '
import sys, json
for a in json.load(sys.stdin)["topAttackers"]:
    print("%-16s count=%4d  avg=%s" % (a["clientIp"], a["count"], a["avgThreatScore"]))'

echo
echo "=== 5. Top targeted paths (expect wave paths on top) ==="
curl -s "$STATS?from=$FROM&to=$TO" | python3 -c '
import sys, json
for p in json.load(sys.stdin)["topTargetedPaths"]:
    print("%-16s count=%d" % (p["path"], p["count"]))'

echo
echo "=== 6. Events per hour ==="
for H in 7 6 5 4 3 2 1; do
  F=$(hours_from_now -$H)
  T=$(hours_from_now -$((H - 1)))
  COUNT=$(curl -s "$STATS?from=$F&to=$T" | json_field totalEvents)
  echo "$F -> $T: $COUNT"
done

echo
echo "=== 7. Empty results (expect 0, not an error) ==="
echo -n "Yesterday: "
curl -s "$STATS?from=$(hours_from_now -48)&to=$(hours_from_now -24)" | json_field totalEvents
echo -n "Unknown config 99999: "
curl -s "$STATS?configId=99999&from=$FROM&to=$TO" | json_field totalEvents

echo
echo "=== 8. Bad requests (expect HTTP 400) ==="
check_400() {
  CODE=$(curl -s -o /dev/null -w '%{http_code}' "$2")
  echo "$1: HTTP $CODE"
}
check_400 "Missing from      " "$STATS?to=$TO"
check_400 "Missing to        " "$STATS?from=$FROM"
check_400 "from after to     " "$STATS?from=$TO&to=$FROM"
check_400 "from equals to    " "$STATS?from=$FROM&to=$FROM"
check_400 "Bad date format   " "$STATS?from=yesterday&to=$TO"
check_400 "Non-numeric config" "$STATS?configId=abc&from=$FROM&to=$TO"
