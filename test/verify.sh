#!/usr/bin/env bash
# Check a running site against the multipart block, whatever the web server is.
#   test/verify.sh https://staging.example.test [/upload]
# The second argument is an upload route that must keep working. Run it against staging,
# not production: it sends harmless empty POST and PUT requests.
set -u
BASE="${1:?usage: verify.sh BASE_URL [UPLOAD_PATH]}"
BASE="${BASE%/}"
UPLOAD="${2:-}"
pass=0; fail=0

code() { curl -s -o /dev/null -m 15 -w '%{http_code}' "$@"; }

# blocked = 403, 400 or 000 (connection dropped, as with nginx 444)
is_blocked() { case "$1" in 403|400|000) return 0;; *) return 1;; esac; }

expect_blocked() {
  local got; got="$(code "${@:2}")"
  if is_blocked "$got"; then echo "[OK]   blocked ($got)  $1"; pass=$((pass+1)); else echo "[FAIL] not blocked ($got)  $1"; fail=$((fail+1)); fi
}
expect_passes() {
  local got; got="$(code "${@:2}")"
  if is_blocked "$got"; then echo "[FAIL] blocked ($got)  $1"; fail=$((fail+1)); else echo "[OK]   passes ($got)  $1"; pass=$((pass+1)); fi
}

MP='Content-Type: multipart/form-data; boundary=x'
expect_blocked "POST multipart"                 -X POST -H "$MP" --data-binary '' "$BASE/"
expect_blocked "POST multipart, comma variant"  -X POST -H 'Content-Type: multipart/form-data,boundary=x' --data-binary '' "$BASE/"
expect_blocked "POST multipart, upper case"     -X POST -H 'Content-Type: MULTIPART/FORM-DATA; boundary=x' --data-binary '' "$BASE/"
expect_blocked "PUT multipart"                  -X PUT  -H "$MP" --data-binary '' "$BASE/"
expect_passes  "GET"                            "$BASE/"
expect_passes  "POST urlencoded"                -X POST -d a=1 "$BASE/"
expect_passes  "POST json"                      -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/"
[ -n "$UPLOAD" ] && expect_passes "POST multipart on upload route $UPLOAD" -X POST -H "$MP" --data-binary '' "$BASE$UPLOAD"

echo
echo "RESULT: $([ "$fail" -eq 0 ] && echo PASS || echo "FAIL ($fail)")  pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
