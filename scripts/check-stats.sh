#!/usr/bin/env bash
# Checks GET /v1/stats/summary against a running app with generated data.
# Every line prints: PASS/FAIL, what is checked, the expected value and the actual value.
#
# Usage:
#   ./scripts/check-stats.sh                      # app on http://localhost:8080
#   BASE_URL=http://host:8080 ./scripts/check-stats.sh
#
# Needs: curl, python3 (to read the JSON)

BASE_URL="${BASE_URL:-http://localhost:8080}"
STATS="$BASE_URL/v1/stats/summary"
PASSED=0
FAILED=0

# ISO-8601 UTC time, shifted by N hours from now (works on macOS and Linux)
hours_from_now() {
  date -u -v"${1}H" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} hours" +%Y-%m-%dT%H:%M:%SZ
}

# check "what is checked" expected actual
check() {
  if [ "$2" = "$3" ]; then
    echo "PASS  $1 | expected: $2 | actual: $3"
    PASSED=$((PASSED + 1))
  else
    echo "FAIL  $1 | expected: $2 | actual: $3"
    FAILED=$((FAILED + 1))
  fi
}

# Runs a Python expression on the JSON from stdin; the JSON is available as d
py() {
  python3 -c "import sys, json; d = json.load(sys.stdin); print($1)"
}

# The generator creates events over the last 6 hours, so this window covers all of them
FROM=$(hours_from_now -7)
TO=$(hours_from_now +1)
SUMMARY=$(curl -s "$STATS?from=$FROM&to=$TO")
TOTAL=$(echo "$SUMMARY" | py 'd["totalEvents"]')

echo "Stats checks against $STATS"
echo "Window: $FROM -> $TO, total events: $TOTAL"
echo

echo "--- Totals ---"
SUM=0
for CONFIG in 14227 14228 31001; do
  COUNT=$(curl -s "$STATS?configId=$CONFIG&from=$FROM&to=$TO" | py 'd["totalEvents"]')
  SUM=$((SUM + COUNT))
done
check "The 3 configs add up to the total" "$TOTAL" "$SUM"
check "configId is null when not given" "None" "$(echo "$SUMMARY" | py 'd["configId"]')"

echo
echo "--- byCategory and byAction ---"
check "byCategory has all 7 categories" "7" "$(echo "$SUMMARY" | py 'len(d["byCategory"])')"
check "byCategory counts add up to the total" "$TOTAL" "$(echo "$SUMMARY" | py 'sum(c["count"] for c in d["byCategory"].values())')"
check "byAction has all 3 actions" "3" "$(echo "$SUMMARY" | py 'len(d["byAction"])')"
check "byAction counts add up to the total" "$TOTAL" "$(echo "$SUMMARY" | py 'sum(d["byAction"].values())')"
check "Averages are between 0 and 100" "True" "$(echo "$SUMMARY" | py 'all(0 <= c["avgThreatScore"] <= 100 for c in d["byCategory"].values())')"

echo
echo "--- Top attackers and paths ---"
check "topAttackers has 10 entries" "10" "$(echo "$SUMMARY" | py 'len(d["topAttackers"])')"
check "topAttackers sorted by count, highest first" "True" "$(echo "$SUMMARY" | py 'all(a["count"] >= b["count"] for a, b in zip(d["topAttackers"], d["topAttackers"][1:]))')"
check "Top attacker is a wave IP (198.51.100.x)" "True" "$(echo "$SUMMARY" | py 'd["topAttackers"][0]["clientIp"].startswith("198.51.100.")')"
check "topTargetedPaths has 10 entries" "10" "$(echo "$SUMMARY" | py 'len(d["topTargetedPaths"])')"
check "topTargetedPaths sorted by count, highest first" "True" "$(echo "$SUMMARY" | py 'all(a["count"] >= b["count"] for a, b in zip(d["topTargetedPaths"], d["topTargetedPaths"][1:]))')"
check "Top path is a wave path" "True" "$(echo "$SUMMARY" | py 'd["topTargetedPaths"][0]["path"] in ("/login", "/api/v1/login", "/admin", "/search")')"

echo
echo "--- Empty results ---"
check "A window with no events returns 0" "0" "$(curl -s "$STATS?from=$(hours_from_now -48)&to=$(hours_from_now -24)" | py 'd["totalEvents"]')"
check "An unknown config returns 0" "0" "$(curl -s "$STATS?configId=99999&from=$FROM&to=$TO" | py 'd["totalEvents"]')"

echo
echo "--- Bad requests ---"
status() {
  curl -s -o /dev/null -w '%{http_code}' "$1"
}
check "Missing from returns 400" "400" "$(status "$STATS?to=$TO")"
check "Missing to returns 400" "400" "$(status "$STATS?from=$FROM")"
check "from after to returns 400" "400" "$(status "$STATS?from=$TO&to=$FROM")"
check "from equal to to returns 400" "400" "$(status "$STATS?from=$FROM&to=$FROM")"
check "Bad date format returns 400" "400" "$(status "$STATS?from=yesterday&to=$TO")"
check "Non-numeric configId returns 400" "400" "$(status "$STATS?configId=abc&from=$FROM&to=$TO")"

echo
echo "Result: $PASSED passed, $FAILED failed"
