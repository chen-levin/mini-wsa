#!/usr/bin/env bash
# Demo cases for the stats and samples APIs.
# Each case prints the curl command, then the full formatted JSON response and the HTTP status.
# Every printed command can be copied and run on its own.
#
# Run it against an app that already has generated data:
#   java generator/EventGenerator.java 10000 --send
#   ./scripts/demo-cases.sh | less
#
# Needs: curl, python3 (to format the JSON)

BASE_URL="${BASE_URL:-http://localhost:8080}"

# ISO-8601 UTC time, shifted by N hours from now (works on macOS and Linux)
hours_from_now() {
  date -u -v"${1}H" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} hours" +%Y-%m-%dT%H:%M:%SZ
}

FROM=$(hours_from_now -7)
TO=$(hours_from_now +1)

# case_ "title" "curl command": prints the title and the command, runs it,
# then prints the full formatted JSON response and the HTTP status
case_() {
  echo
  echo "=================================================================="
  echo "$1"
  echo "=================================================================="
  echo "\$ $2"
  echo
  local response
  response=$(eval "$2 -s -w '\n%{http_code}'")
  echo "$response" | sed '$d' | python3 -m json.tool
  echo "HTTP $(echo "$response" | tail -n 1)"
}

echo "############################## STATS ##############################"

case_ "Stats 1. All configs, last 7 hours" \
  "curl '$BASE_URL/v1/stats/summary?from=$FROM&to=$TO'"

case_ "Stats 2. One config (14228)" \
  "curl '$BASE_URL/v1/stats/summary?configId=14228&from=$FROM&to=$TO'"

case_ "Stats 3. Last hour only" \
  "curl '$BASE_URL/v1/stats/summary?from=$(hours_from_now -1)&to=$TO'"

case_ "Stats 4. A window with no events (all zeros, empty top lists)" \
  "curl '$BASE_URL/v1/stats/summary?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z'"

case_ "Stats 5. An unknown config (all zeros)" \
  "curl '$BASE_URL/v1/stats/summary?configId=99999&from=$FROM&to=$TO'"

case_ "Stats 6. Missing 'from' (400)" \
  "curl '$BASE_URL/v1/stats/summary?to=$TO'"

case_ "Stats 7. Bad date format (400)" \
  "curl '$BASE_URL/v1/stats/summary?from=yesterday&to=$TO'"

echo
echo "############################# SAMPLES #############################"

case_ "Samples 1. The 3 newest events (newest first)" \
  "curl '$BASE_URL/v1/events/samples?limit=3'"

case_ "Samples 2. Only BOT events" \
  "curl '$BASE_URL/v1/events/samples?category=BOT&limit=2'"

case_ "Samples 3. Only DENY events (status 403, responseSize 0)" \
  "curl '$BASE_URL/v1/events/samples?action=DENY&limit=2'"

case_ "Samples 4. Only MONITOR events (status 200, real responseSize)" \
  "curl '$BASE_URL/v1/events/samples?action=MONITOR&limit=2'"

case_ "Samples 5. All filters together: config 31001, DOS, ALERT, last 7 hours" \
  "curl '$BASE_URL/v1/events/samples?configId=31001&category=DOS&action=ALERT&from=$FROM&to=$TO&limit=2'"

case_ "Samples 6. Paging: XSS events, page 1 (offset 0)" \
  "curl '$BASE_URL/v1/events/samples?category=XSS&limit=2&offset=0'"

case_ "Samples 7. Paging: XSS events, page 2 (offset 2)" \
  "curl '$BASE_URL/v1/events/samples?category=XSS&limit=2&offset=2'"

case_ "Samples 8. An offset past the end (empty list)" \
  "curl '$BASE_URL/v1/events/samples?offset=1000000'"

case_ "Samples 9. Unknown category (400)" \
  "curl '$BASE_URL/v1/events/samples?category=SQLI'"

case_ "Samples 10. limit=0 (400)" \
  "curl '$BASE_URL/v1/events/samples?limit=0'"
