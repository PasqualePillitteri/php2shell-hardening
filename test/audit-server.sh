#!/usr/bin/env bash
# Read-only audit of a PHP-FPM server against the php2shell settings in this repository.
#   sudo bash test/audit-server.sh
# It changes nothing: it reads the configuration with php-fpm -tt, nginx -T, apachectl -M
# and systemctl show. Prints PASS, WARN or SKIP per check and exits 1 on any WARN.
set -u
warns=0
pass() { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; warns=$((warns+1)); }
skip() { printf 'SKIP  %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || echo "note: not running as root, some files and commands may be unreadable"

is_off() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in ''|0|off|false|no) return 0;; esac; return 1; }

if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = cgroup2fs ]; then cgv=2; else cgv=1; fi

# php-fpm -tt prints "[date] NOTICE: [section]" and "[date] NOTICE: <tab>key = value".
# Output: section|key|value
parse_dump() {
  awk '
    { sub(/^.*NOTICE: /, "") }
    /^\[[^]]*\]$/ { sec = substr($0, 2, length($0) - 2); next }
    /^\t/ {
      line = substr($0, 2); i = index(line, " =")
      if (i) { v = substr(line, i + 2); sub(/^ /, "", v); print sec "|" substr(line, 1, i - 1) "|" v }
    }'
}

master_pid() {
  local pid exe
  for pid in $(pgrep -f '^php-fpm: master process' 2>/dev/null); do
    exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null) || continue
    [ "$exe" = "$1" ] && { echo "$pid"; return 0; }
  done
  return 1
}

check_limits() {
  local label="$1" pid="$2" what soft
  for what in 'Max address space' 'Max data size'; do
    soft=$(awk -v w="$what" 'index($0, w) == 1 { n = split(w, a, " "); print $(n + 1) }' "/proc/$pid/limits" 2>/dev/null)
    if [ -z "$soft" ]; then
      skip "$label: cannot read /proc/$pid/limits"
    elif [ "$soft" = unlimited ]; then
      pass "$label: $what unlimited"
    else
      warn "$label: $what is $soft, an RLIMIT_AS/RLIMIT_DATA cap makes mmap() fail, remove it"
    fi
  done
}

check_unit() {
  local fpm="$1" unit="$2" props mmax mlimit oom las ldata
  props=$(systemctl show -p MemoryMax -p MemoryLimit -p OOMPolicy -p LimitAS -p LimitDATA "$unit" 2>/dev/null)
  mmax=$(printf '%s\n' "$props" | sed -n 's/^MemoryMax=//p')
  mlimit=$(printf '%s\n' "$props" | sed -n 's/^MemoryLimit=//p')
  oom=$(printf '%s\n' "$props" | sed -n 's/^OOMPolicy=//p')
  las=$(printf '%s\n' "$props" | sed -n 's/^LimitAS=//p')
  ldata=$(printf '%s\n' "$props" | sed -n 's/^LimitDATA=//p')

  if [ "$cgv" = 2 ]; then
    if [ -n "$mmax" ] && [ "$mmax" != infinity ]; then pass "$fpm: $unit MemoryMax=$mmax"
    else warn "$fpm: $unit has no MemoryMax=, memory_limit=-1 has no cap (see systemd/php-fpm-memory.conf)"; fi
    case "$oom" in
      continue) pass "$fpm: $unit OOMPolicy=continue" ;;
      '') skip "$fpm: systemd too old for OOMPolicy=" ;;
      *) warn "$fpm: $unit OOMPolicy=$oom, the first OOM kill of a worker stops the whole service" ;;
    esac
  else
    if [ -n "$mlimit" ] && [ "$mlimit" != infinity ]; then pass "$fpm: $unit MemoryLimit=$mlimit (cgroup v1)"
    else warn "$fpm: $unit has no MemoryLimit= on cgroup v1, memory_limit=-1 has no cap"; fi
    skip "$fpm: OOMPolicy not checked, systemd does not see OOM kills on cgroup v1"
  fi

  if [ "${las:-infinity}" = infinity ] && [ "${ldata:-infinity}" = infinity ]; then
    pass "$fpm: $unit has no LimitAS= or LimitDATA="
  else
    warn "$fpm: $unit sets LimitAS=$las LimitDATA=$ldata, remove them"
  fi
}

check_fpm() {
  local fpm="$1" conf pid dump parsed pct n bad upl_ini pool mem upl mr worker unit
  pid=$(master_pid "$(readlink -f "$fpm")")
  conf=""
  [ -n "$pid" ] && conf=$(ps -o args= -p "$pid" | sed -n 's/.*master process (\(.*\)).*/\1/p')

  if [ -n "$conf" ]; then dump=$("$fpm" -y "$conf" -tt 2>&1); else dump=$("$fpm" -tt 2>&1); fi
  if ! printf '%s\n' "$dump" | grep -q 'test is successful'; then
    warn "$fpm: php-fpm -tt failed: $(printf '%s\n' "$dump" | grep -E 'ERROR|error' | head -1)"
    return
  fi
  parsed=$(printf '%s\n' "$dump" | parse_dump)

  pct=$(printf '%s\n' "$parsed" | awk -F'|' '$1 == "global" && $2 == "process_control_timeout" { print $3; exit }')
  pct=${pct%%[!0-9]*}
  if [ "${pct:-0}" -gt 0 ]; then pass "$fpm: process_control_timeout = ${pct}s"
  else warn "$fpm: process_control_timeout is 0, a reload drops the requests in flight (see php-fpm/global-php2shell.conf)"; fi

  upl_ini=$("$fpm" -i 2>/dev/null | sed 's/<[^>]*>/ /g' | awk '$1 == "session.upload_progress.enabled" { print $NF; exit }')

  n=0; bad=0
  while IFS='|' read -r pool mem upl mr; do
    [ -n "$pool" ] || continue
    n=$((n+1))
    if [ "$mem" != "-1" ]; then
      bad=$((bad+1))
      if [ "$mem" = unset ]; then warn "$fpm: pool $pool has no php_admin_value[memory_limit] = -1"
      else warn "$fpm: pool $pool has php_admin_value[memory_limit] = $mem, use -1 with a cgroup cap"; fi
    fi
    if [ "$upl" = unset ]; then
      bad=$((bad+1))
      if is_off "$upl_ini"; then warn "$fpm: pool $pool: session.upload_progress off only in php.ini, set php_admin_flag[session.upload_progress.enabled] = off"
      else warn "$fpm: pool $pool: session.upload_progress.enabled is on (CVE-2026-109619 and CVE-2026-115560)"; fi
    elif ! is_off "$upl"; then
      bad=$((bad+1)); warn "$fpm: pool $pool sets php_admin_flag[session.upload_progress.enabled] on"
    fi
    if [ "${mr:-0}" = 0 ]; then
      bad=$((bad+1)); warn "$fpm: pool $pool has pm.max_requests = 0, workers are never recycled (500 is a cheap middle ground)"
    fi
  done <<EOF
$(printf '%s\n' "$parsed" | awk -F'|' '
  $1 == "global" { next }
  { pools[$1] = 1 }
  $2 == "php_admin_value[memory_limit]" { mem[$1] = $3 }
  $2 == "php_admin_value[session.upload_progress.enabled]" { upl[$1] = $3; has[$1] = 1 }
  $2 == "pm.max_requests" { mr[$1] = $3 }
  END { for (p in pools) print p "|" ((p in mem) ? mem[p] : "unset") "|" ((p in has) ? upl[p] : "unset") "|" mr[p] }')
EOF
  if [ "$n" -eq 0 ]; then warn "$fpm: no pools found in php-fpm -tt output"
  elif [ "$bad" -eq 0 ]; then pass "$fpm: all $n pool(s) set memory_limit -1 and session.upload_progress off as php_admin_*, pm.max_requests > 0"; fi

  n=$("$fpm" -m 2>&1 | grep -ciE 'warning|unable|already loaded')
  if [ "$n" -eq 0 ]; then pass "$fpm: no startup warnings"
  else
    warn "$fpm: $n startup warnings, fix them (duplicate extension= lines in php.ini and conf.d are the usual cause):"
    "$fpm" -m 2>&1 | grep -iE 'warning|unable|already loaded' | head -5 | sed 's/^/      /'
  fi

  if [ -z "$pid" ]; then
    skip "$fpm: not running, limits and systemd unit not checked"
    return
  fi
  check_limits "$fpm master" "$pid"
  worker=$(pgrep -P "$pid" | head -1)
  [ -n "$worker" ] && check_limits "$fpm worker" "$worker"

  unit=$(grep -o '[^/]*\.service' "/proc/$pid/cgroup" 2>/dev/null | head -1)
  if [ -n "$unit" ] && have systemctl; then check_unit "$fpm" "$unit"
  else skip "$fpm: no systemd unit, cgroup cap and OOMPolicy not checked"; fi
}

echo "== PHP-FPM"
seen=" "; found=0
for b in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /opt/php-*/sbin/php-fpm /opt/remi/php*/root/usr/sbin/php-fpm; do
  [ -f "$b" ] && [ -x "$b" ] || continue
  r=$(readlink -f "$b")
  case "$seen" in *" $r "*) continue ;; esac
  seen="$seen$r "; found=1
  check_fpm "$b"
done
[ "$found" -eq 1 ] || skip "no php-fpm binary found"

echo "== nginx"
if have nginx && dump=$(nginx -T 2>/dev/null) && [ -n "$dump" ]; then
  # file:line of the matches in nginx -T output, comments ignored
  nginx_grep() {
    printf '%s\n' "$dump" | awk -v re="$1" '
      /^# configuration file .*:$/ { f = $0; sub(/^# configuration file /, "", f); sub(/:$/, "", f); n = 0; next }
      { n++; l = $0; sub(/#.*/, "", l); if (l ~ re) print f ":" n ": " $0 }'
  }
  hits=$(nginx_grep 'fastcgi_param[[:space:]]+PHP_(ADMIN_)?VALUE')
  if [ -z "$hits" ]; then pass "nginx passes no PHP_VALUE or PHP_ADMIN_VALUE"
  else
    warn "nginx passes PHP_VALUE/PHP_ADMIN_VALUE to PHP, move those settings to the pool:"
    printf '%s\n' "$hits" | sed 's/^/      /'
  fi
  hits=$(nginx_grep 'client_max_body_size[[:space:]]+0[kKmMgG]?[[:space:]]*;')
  if [ -z "$hits" ]; then pass "no client_max_body_size 0 (unlimited body)"
  else
    warn "client_max_body_size 0 leaves the request body unlimited:"
    printf '%s\n' "$hits" | sed 's/^/      /'
  fi
else
  skip "nginx not installed or nginx -T failed"
fi

echo "== Apache"
ctl=""
for c in apache2ctl apachectl httpd; do have "$c" && { ctl=$c; break; }; done
if [ -z "$ctl" ] && [ ! -d /etc/apache2 ] && [ ! -d /etc/httpd ]; then
  skip "Apache not installed"
else
  modphp=""
  [ -n "$ctl" ] && modphp=$("$ctl" -M 2>/dev/null | grep -oE 'php[0-9]?_module' | head -1)
  files=$( { ls /etc/apache2/mods-enabled/php*.load 2>/dev/null
             grep -lE '^[[:space:]]*LoadModule[[:space:]]+php' /etc/httpd/conf.modules.d/*.conf 2>/dev/null; } )
  if pgrep -x apache2 >/dev/null 2>&1 || pgrep -x httpd >/dev/null 2>&1; then state=running; else state=stopped; fi
  if [ -z "$modphp" ] && [ -z "$files" ]; then
    pass "mod_php not loaded (Apache $state)"
  else
    where=$(printf '%s %s' "$modphp" "$(echo "$files" | tr '\n' ' ')" | sed 's/^ *//; s/ *$//')
    if [ "$state" = running ]; then warn "mod_php is loaded in the running Apache: $where"
    else warn "mod_php is enabled and loads on the next Apache start: $where"; fi
    hits=$(find /var/www -xdev -name .htaccess -type f -exec grep -HnE '^[[:space:]]*php_(admin_)?(value|flag)' {} + 2>/dev/null | head -20)
    [ -n "$hits" ] && { warn "php_value/php_flag in .htaccess, applied before request startup with mod_php:"; printf '%s\n' "$hits" | sed 's/^/      /'; }
  fi
  hits=$(grep -rnIE '^[^#]*PHP_(ADMIN_)?VALUE' /etc/apache2 /etc/httpd 2>/dev/null | head -20)
  if [ -z "$hits" ]; then pass "Apache passes no PHP_VALUE or PHP_ADMIN_VALUE"
  else
    warn "Apache passes PHP_VALUE/PHP_ADMIN_VALUE to PHP, move those settings to the pool:"
    printf '%s\n' "$hits" | sed 's/^/      /'
  fi
fi

echo
if [ "$warns" -eq 0 ]; then echo "RESULT: PASS"; exit 0; fi
echo "RESULT: $warns warning(s)"
exit 1
