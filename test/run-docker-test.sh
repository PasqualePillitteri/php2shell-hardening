#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT=18089; NAME=php2shell-nginx-test; IMG=nginx:1.24-alpine
echo "[*] attendo il daemon Docker..."
for i in $(seq 1 60); do docker info >/dev/null 2>&1 && { echo "[*] Docker UP"; break; }; sleep 3; done
docker info >/dev/null 2>&1 || { echo "[FAIL] Docker non raggiungibile"; exit 2; }
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "[*] pull $IMG"; docker pull -q "$IMG" || { echo "[FAIL] pull"; exit 2; }; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
body(){ curl -s "$@"; }
run_nginx(){ docker rm -f "$NAME" >/dev/null 2>&1; docker run -d --name "$NAME" -p ${PORT}:80 -v "$1:/etc/nginx/nginx.conf:ro" "$IMG" >/dev/null || return 1; for i in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/" && return 0; sleep 1; done; return 0; }
B="http://127.0.0.1:${PORT}"
pass=0; fail=0
chk(){ local exp="$1" got="$2" d="$3"; if [ "$got" = "$exp" ]; then echo "[OK]  $got (atteso $exp)  $d"; pass=$((pass+1)); else echo "[FAIL] $got (atteso $exp)  $d"; fail=$((fail+1)); fi; }

echo "=== FIXED conf (con error_page + guardia errpage/volatile)"
run_nginx "$HERE/nginx-test.conf" || { echo "[FAIL] run fixed"; exit 2; }
chk 200 "$(code $B/)"                                                   "GET /"
chk 200 "$(code -X POST -d a=1 $B/)"                                    "POST urlencoded /"
chk 403 "$(code -X POST -F a=1 $B/)"                                    "POST multipart / -> 403 (NON 500: niente ciclo)"
case "$(body -X POST -F a=1 $B/)" in *BLOCKED-403*) echo "[OK]  body error-page servita  POST multipart / mostra /error/403.html"; pass=$((pass+1));; *) echo "[FAIL] body error-page mancante"; fail=$((fail+1));; esac
chk 200 "$(code -X POST -F a=1 $B/upload)"                              "POST multipart /upload (eccezione)"
chk 403 "$(code -X POST -F a=1 $B/uploads-x)"                          "POST multipart /uploads-x (NON upload)"
chk 403 "$(code -X POST -H 'Content-Type: multipart/form-data,boundary=x' --data-binary 'x' $B/)" "variante VIRGOLA /"
chk 403 "$(code -X PUT  -F a=1 $B/)"                                    "PUT multipart /"
chk 200 "$(code -X POST -H 'Content-Type: application/json' -d '{}' $B/)" "POST json /"

echo "=== BROKEN conf (regola vecchia: deve dare 500, prova che il test rileva il bug)"
run_nginx "$HERE/nginx-test-broken.conf" || { echo "[FAIL] run broken"; exit 2; }
chk 500 "$(code -X POST -F a=1 $B/)"                                    "POST multipart / -> 500 (ciclo error_page, bug atteso)"

docker rm -f "$NAME" >/dev/null 2>&1
echo; echo "RESULT: $([ $fail -eq 0 ] && echo PASS || echo "FAIL ($fail)")  pass=$pass fail=$fail"
exit $([ $fail -eq 0 ] && echo 0 || echo 1)
