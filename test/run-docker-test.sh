#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=18089; NAME=php2shell-nginx-test; IMG=nginx:1.24-alpine
echo "[*] waiting for the Docker daemon..."
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && { echo "[*] Docker UP"; break; }; sleep 3; done
docker info >/dev/null 2>&1 || { echo "[FAIL] Docker not reachable"; exit 2; }
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "[*] pulling $IMG"; docker pull -q "$IMG" || { echo "[FAIL] pull"; exit 2; }; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
body(){ curl -s "$@"; }
run_nginx(){ docker rm -f "$NAME" >/dev/null 2>&1; docker run -d --name "$NAME" -p ${PORT}:80 -v "$1:/etc/nginx/nginx.conf:ro" "$IMG" >/dev/null || return 1; for _ in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/" && return 0; sleep 1; done; return 0; }
B="http://127.0.0.1:${PORT}"
pass=0; fail=0
chk(){ local exp="$1" got="$2" d="$3"; if [ "$got" = "$exp" ]; then echo "[OK]  $got (expected $exp)  $d"; pass=$((pass+1)); else echo "[FAIL] $got (expected $exp)  $d"; fail=$((fail+1)); fi; }

echo "=== FIXED conf (with error_page + the errpage/volatile guard)"
run_nginx "$HERE/nginx-test.conf" || { echo "[FAIL] run fixed"; exit 2; }
chk 200 "$(code $B/)"                                                   "GET /"
chk 200 "$(code -X POST -d a=1 $B/)"                                    "POST urlencoded /"
chk 403 "$(code -X POST -F a=1 $B/)"                                    "POST multipart / -> 403 (NOT 500: no loop)"
case "$(body -X POST -F a=1 $B/)" in *BLOCKED-403*) echo "[OK]  error-page body served  POST multipart / shows /error/403.html"; pass=$((pass+1));; *) echo "[FAIL] error-page body missing"; fail=$((fail+1));; esac
chk 200 "$(code -X POST -F a=1 $B/upload)"                              "POST multipart /upload (exception)"
chk 403 "$(code -X POST -F a=1 $B/uploads-x)"                          "POST multipart /uploads-x (NOT an upload route)"
chk 403 "$(code -X POST -H 'Content-Type: multipart/form-data,boundary=x' --data-binary 'x' $B/)" "COMMA variant /"
chk 403 "$(code -X PUT  -F a=1 $B/)"                                    "PUT multipart /"
chk 200 "$(code -X POST -H 'Content-Type: application/json' -d '{}' $B/)" "POST json /"

echo "=== BROKEN conf (old rule: must return 500, proves the test catches the bug)"
run_nginx "$HERE/nginx-test-broken.conf" || { echo "[FAIL] run broken"; exit 2; }
chk 500 "$(code -X POST -F a=1 $B/)"                                    "POST multipart / -> 500 (error_page loop, expected bug)"

docker rm -f "$NAME" >/dev/null 2>&1
echo; echo "RESULT: $([ $fail -eq 0 ] && echo PASS || echo "FAIL ($fail)")  pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
