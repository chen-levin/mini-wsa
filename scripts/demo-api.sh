#!/usr/bin/env bash
# A walkthrough of the Mini WSA APIs: prints each curl command, then its formatted response.
# Every printed command can be copied and run on its own (from the project root).
#
# Run it against an app that already has generated data:
#   java generator/EventGenerator.java 10000 --send
#   ./scripts/demo-api.sh
#
# Needs: curl, python3 (to format the JSON)

BASE_URL="${BASE_URL:-http://localhost:8080}"

# ISO-8601 UTC time, shifted by N hours from now (works on macOS and Linux)
hours_from_now() {
  date -u -v"${1}H" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${1} hours" +%Y-%m-%dT%H:%M:%SZ
}

FROM=$(hours_from_now -7)
TO=$(hours_from_now +1)

# show "title" "curl command": prints the title and the command, runs it,
# then prints the formatted JSON response and the HTTP status
show() {
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

# --- Ingestion ---

show "1. Ingest one event, the sample DLR from the spec (expect 201)" \
  "curl -H 'Content-Type: application/json' -d @scripts/examples/event.json '$BASE_URL/v1/events/ingest'"

show "2. Ingest an invalid event: no hostname, no rule.severity (expect 400 with details)" \
  "curl -H 'Content-Type: application/json' -d @scripts/examples/invalid-event.json '$BASE_URL/v1/events/ingest'"

# --- Stats ---

show "3. Stats for all configs, last 7 hours" \
  "curl '$BASE_URL/v1/stats/summary?from=$FROM&to=$TO'"

show "4. Stats for one config (14227)" \
  "curl '$BASE_URL/v1/stats/summary?configId=14227&from=$FROM&to=$TO'"

show "5. Stats with 'from' after 'to' (expect 400)" \
  "curl '$BASE_URL/v1/stats/summary?from=$TO&to=$FROM'"

# --- Samples ---

show "6. The 2 newest events (newest first)" \
  "curl '$BASE_URL/v1/events/samples?limit=2'"

show "7. Filtered samples: config 14227, INJECTION, DENY" \
  "curl '$BASE_URL/v1/events/samples?configId=14227&category=INJECTION&action=DENY&limit=2'"

show "8. The next page of the same filter (offset=2)" \
  "curl '$BASE_URL/v1/events/samples?configId=14227&category=INJECTION&action=DENY&limit=2&offset=2'"

show "9. Samples with limit above 100 (expect 400)" \
  "curl '$BASE_URL/v1/events/samples?limit=101'"
