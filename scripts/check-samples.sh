#!/usr/bin/env bash
# Checks GET /v1/events/samples against a running app with generated data.
# Every line prints: PASS/FAIL, what is checked, the expected value and the actual value.
#
# Usage:
#   ./scripts/check-samples.sh                    # app on http://localhost:8080
#   BASE_URL=http://host:8080 ./scripts/check-samples.sh
#
# Needs: curl, python3 (to read the JSON)

BASE_URL="${BASE_URL:-http://localhost:8080}"
SAMPLES="$BASE_URL/v1/events/samples"
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

DEFAULT_PAGE=$(curl -s "$SAMPLES")
TOTAL=$(echo "$DEFAULT_PAGE" | py 'd["total"]')
PAGE_100=$(curl -s "$SAMPLES?limit=100")

echo "Samples checks against $SAMPLES"
echo "Total events: $TOTAL"
echo

echo "--- Defaults ---"
check "Default limit is 20" "20" "$(echo "$DEFAULT_PAGE" | py 'd["limit"]')"
check "Default offset is 0" "0" "$(echo "$DEFAULT_PAGE" | py 'd["offset"]')"
check "Returns 20 events" "20" "$(echo "$DEFAULT_PAGE" | py 'len(d["events"])')"

echo
echo "--- Event shape ---"
check "Every event has a nested rule with category" "True" "$(echo "$PAGE_100" | py 'all("category" in e["rule"] for e in d["events"])')"
check "Every event has a nested geoLocation with country" "True" "$(echo "$PAGE_100" | py 'all("country" in e["geoLocation"] for e in d["events"])')"
check "Every event has attackType and threatScore" "True" "$(echo "$PAGE_100" | py 'all(e["attackType"] and e["threatScore"] is not None for e in d["events"])')"

echo
echo "--- Order and paging ---"
check "Events sorted newest first" "True" "$(echo "$PAGE_100" | py 'all(a["timestamp"] >= b["timestamp"] for a, b in zip(d["events"], d["events"][1:]))')"
PAGE1=$(curl -s "$SAMPLES?limit=5&offset=0")
PAGE2=$(curl -s "$SAMPLES?limit=5&offset=5")
IDS1=$(echo "$PAGE1" | py '",".join(e["eventId"] for e in d["events"])')
IDS2=$(echo "$PAGE2" | py '",".join(e["eventId"] for e in d["events"])')
check "Page 2 echoes offset 5" "5" "$(echo "$PAGE2" | py 'd["offset"]')"
check "Page 1 and page 2 share no events" "True" "$(python3 -c "print(not set('$IDS1'.split(',')) & set('$IDS2'.split(',')))")"
check "Page 1 + page 2 = the first 10 events" "$(echo "$PAGE_100" | py '",".join(e["eventId"] for e in d["events"][:10])')" "$IDS1,$IDS2"
check "An offset past the end returns no events" "0" "$(curl -s "$SAMPLES?offset=$TOTAL" | py 'len(d["events"])')"

echo
echo "--- Filters ---"
SUM=0
for CATEGORY in INJECTION XSS PROTOCOL_VIOLATION DATA_LEAKAGE BOT DOS RATE_LIMIT; do
  COUNT=$(curl -s "$SAMPLES?category=$CATEGORY&limit=1" | py 'd["total"]')
  SUM=$((SUM + COUNT))
done
check "The 7 category totals add up to the total" "$TOTAL" "$SUM"
FILTERED=$(curl -s "$SAMPLES?configId=14227&category=INJECTION&action=DENY&limit=100")
check "configId + category + action: every event matches" "True" "$(echo "$FILTERED" | py 'all(e["configId"] == 14227 and e["rule"]["category"] == "INJECTION" and e["action"] == "DENY" for e in d["events"])')"
FROM=$(hours_from_now -3)
TO=$(hours_from_now +1)
check "Samples total = stats total for the same window" \
  "$(curl -s "$STATS?from=$FROM&to=$TO" | py 'd["totalEvents"]')" \
  "$(curl -s "$SAMPLES?from=$FROM&to=$TO&limit=1" | py 'd["total"]')"

echo
echo "--- Enrichment ---"
check "attackType matches the category" "True" "$(echo "$PAGE_100" | py 'all({"INJECTION": "SQL/Command Injection", "XSS": "Cross-Site Scripting", "PROTOCOL_VIOLATION": "Protocol Anomaly", "DATA_LEAKAGE": "Data Exfiltration", "BOT": "Bot Activity", "DOS": "Denial of Service", "RATE_LIMIT": "Rate Limiting"}[e["rule"]["category"]] == e["attackType"] for e in d["events"])')"
check "threatScore is between 0 and 100" "True" "$(echo "$PAGE_100" | py 'all(0 <= e["threatScore"] <= 100 for e in d["events"])')"
check "No event happens after it was received" "True" "$(echo "$PAGE_100" | py 'all(e["timestamp"] <= e["receivedAt"] for e in d["events"])')"

echo
echo "--- Bad requests ---"
status() {
  curl -s -o /dev/null -w '%{http_code}' "$1"
}
check "limit=0 returns 400" "400" "$(status "$SAMPLES?limit=0")"
check "limit=101 returns 400" "400" "$(status "$SAMPLES?limit=101")"
check "offset=-1 returns 400" "400" "$(status "$SAMPLES?offset=-1")"
check "Unknown category returns 400" "400" "$(status "$SAMPLES?category=SQLI")"
check "Unknown action returns 400" "400" "$(status "$SAMPLES?action=BLOCK")"
check "from after to returns 400" "400" "$(status "$SAMPLES?from=$TO&to=$FROM")"
check "Bad date format returns 400" "400" "$(status "$SAMPLES?from=yesterday")"

echo
echo "Result: $PASSED passed, $FAILED failed"
