#!/usr/bin/env bash
# Compares ingesting the same number of events in ONE request vs in batches of 500.
# WARNING: empties the security_event table before each test.
#
# Usage (app and PostgreSQL running with docker compose):
#   ./scripts/compare-ingest.sh            # 10,000 events
#   ./scripts/compare-ingest.sh 5000
#
# Needs: java, curl, docker

COUNT="${1:-10000}"
BASE_URL="${BASE_URL:-http://localhost:8080}"
POSTGRES_CONTAINER="mini-wsa-postgres-1"
EVENTS_FILE="events.json"

empty_table() {
  docker exec "$POSTGRES_CONTAINER" psql -U miniwsa -d miniwsa -q -c "TRUNCATE security_event RESTART IDENTITY"
}

count_rows() {
  docker exec "$POSTGRES_CONTAINER" psql -U miniwsa -d miniwsa -t -A -c "SELECT count(*) FROM security_event"
}

echo "Comparing ingestion of $COUNT events"

echo
echo "=== Test 1: one request with all $COUNT events ==="
empty_table
java generator/EventGenerator.java "$COUNT" "$EVENTS_FILE" > /dev/null
echo "Rows before: $(count_rows)"
START=$(date +%s)
curl -s -H 'Content-Type: application/json' --data-binary "@$EVENTS_FILE" "$BASE_URL/v1/events/ingest"
echo
END=$(date +%s)
ONE_REQUEST_SECONDS=$((END - START))
ONE_REQUEST_ROWS=$(count_rows)
echo "Rows after:  $ONE_REQUEST_ROWS"
echo "Time:        $ONE_REQUEST_SECONDS seconds"

echo
echo "=== Test 2: the same number of events in batches of 500 ==="
empty_table
echo "Rows before: $(count_rows)"
START=$(date +%s)
java generator/EventGenerator.java "$COUNT" --send "$BASE_URL" | tail -n 1
END=$(date +%s)
BATCH_SECONDS=$((END - START))
BATCH_ROWS=$(count_rows)
echo "Rows after:  $BATCH_ROWS"
echo "Time:        $BATCH_SECONDS seconds"

echo
echo "=== Summary ==="
printf "%-28s %8s %8s\n" "Test" "Rows" "Seconds"
printf "%-28s %8s %8s\n" "1 request of $COUNT" "$ONE_REQUEST_ROWS" "$ONE_REQUEST_SECONDS"
printf "%-28s %8s %8s\n" "Batches of 500" "$BATCH_ROWS" "$BATCH_SECONDS"
