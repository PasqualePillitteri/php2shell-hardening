# php2shell-hardening

Unofficial edge rules that stop `multipart/form-data` requests before they reach PHP, as a
stopgap for CVE-2026-109618 and CVE-2026-109619 ("php2shell") on installations that cannot
be updated yet. Covers Nginx, Apache, ModSecurity, Caddy, lighttpd, FrankenPHP, Cloudflare and
`php.ini`, with a test suite.

These rules are provisional. They block legitimate uploads and multipart forms, so use them
only on routes that do not need uploads and try them in staging first. The PHP project says
that only an update is a complete fix, and that none of the configuration measures below
make an installation safe.

## What PHP published

On 21 October 2026 PHP released 8.5.12, 8.4.27, 8.3.36 and 8.2.35 and published an
[advisory](https://www.php.net/archive/2026.php) with two critical issues, CVSS v4.0 9.2:

- CVE-2026-109618, RCE via OOM corruption:
  [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w).
  An out-of-memory failure can interrupt PHP while request data is only partly initialized.
  A complete exploit was demonstrated on Apache mod_php; for FPM it is source analysis only.
- CVE-2026-109619, RCE via stale global state:
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
  Request state can survive after its memory is freed and be used by a later request on the
  same worker. `session.upload_progress` is a confirmed path, on mod_php and on FPM.

PHP 8.1 and older no longer get updates from the project. For 7.4, 8.0 and 8.1 the security
team published minimal source backports for people who build from source:
[7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619),
[8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619),
[8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619).
Linux distributions and LTS vendors received the patches in advance, so check your vendor
first. Packages with a backport keep the old version number.

## If you cannot update

The risks, the cases where the flaws trigger and why a login or a missing upload form does
not protect you are covered in
[PHP2Shell, what to do if you can't update PHP](https://pasqualepillitteri.it/en/news/26241/php2shell-cant-update-php-legacy-apps).
The steps below, in order, from the strongest to the weakest.

1. Use a vendor package that contains the fix, or build from one of the backport branches above.
2. Try the smallest jump to a supported branch in staging, with `error_reporting = E_ALL`.
3. Put authentication in front of PHP, so an unauthorized request is rejected before the
   engine reads its body. Application-level login does not help: PHP parses the request
   before your script runs.
4. Limit request size at the edge and block multipart where it is not needed (the rules in
   this repository).
5. Apply the PHP settings below.

### Authentication before PHP

Nginx, basic auth or an allow-list:

```nginx
location / {
    auth_basic           "restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;
    # or: allow 203.0.113.0/24; deny all;
}
```

Apache 2.4:

```apache
<Location "/">
    Require ip 203.0.113.0/24
</Location>
```

### Request limits at the edge

PHP asks for limits on decoded request size, field count, multipart part count, header count
and nesting depth, enforced also on requests without a usable `Content-Length`. Nginx and
Apache cover only part of that:

```nginx
client_max_body_size 8m;
```

```apache
LimitRequestBody 8388608
LimitRequestFields 50
```

With Nginx in front of PHP-FPM the body is buffered and forwarded with a `Content-Length`;
check that `fastcgi_request_buffering` is not off. Per-part header and part counts are not
configurable in either server, which is the reason this repository blocks multipart outright
where it is not needed. Test in staging.

### PHP settings

Set them where the application cannot override them (`php_admin_value` and `php_admin_flag` in
the FPM pool or in the Apache configuration), not with `ini_set()` or `.user.ini`, and restart
every worker.

```ini
; PHP-FPM pool
php_admin_value[memory_limit] = -1
php_admin_value[post_max_size] = 8M
php_admin_flag[session.upload_progress.enabled] = off
; PHP 8.5 only
php_admin_flag[fatal_error_backtraces] = off
; optional, costs performance: the worker is recreated after every request
pm.max_requests = 1
```

- `memory_limit = -1` removes the limit an attacker could trip on purpose, but an underlying
  allocation failure can still reach the vulnerable path. Pair it with a container or cgroup
  limit that kills only the affected worker.
- Do not use `RLIMIT_AS` or `RLIMIT_DATA` (`ulimit -v`) as a memory cap. They make `mmap()`
  fail, which is the failure that triggers the vulnerable path.
- `post_max_size = 8M` is for applications without uploads. If uploads are needed PHP suggests
  32M, with `upload_max_filesize` below it.
- `session.upload_progress.enabled = off` blocks the confirmed session paths and not other
  variants. Keep it off after the update if you do not use the feature.
- Remove or fix settings that emit diagnostics before initialization, and fix fatal errors
  and execution timeouts an attacker can reach. Hiding messages with `error_reporting`,
  `display_errors` or `@` does not help.

Verify values from the web SAPI with a temporary `phpinfo()` page, not from the CLI, then
delete it.

## What's here

- `nginx/php2shell-maps.conf`: `map` blocks for `http{}`, flags multipart POST, PUT and PATCH
  minus an upload-route allowlist
- `nginx/php2shell-server-snippet.conf`: the `if` that returns 403, for `server{}`
- `apache/.htaccess`: `mod_rewrite` rule that returns 403 on multipart POST, PUT and PATCH
- `apache/modsecurity-php2shell.conf`: ModSecurity rule on the `PHP_SESSION_UPLOAD_PROGRESS` field
- `cloudflare/custom-rule.md`: custom-rule expression, scoped, and what not to do
- `caddy/php2shell.caddyfile`: matcher that returns 403 on multipart except upload routes
- `frankenphp/Caddyfile-snippet`: disables session upload progress
- `lighttpd/php2shell.conf`: multipart block, to scope per vhost
- `php-fpm/99-php2shell.ini`: session hardening for `php.ini`
- `test/`: decision-table check and a self-contained Nginx container test

## Why multipart

The advisory lists multipart requests as a way to exhaust memory for CVE-2026-109618, and
session upload progress, which PHP processes when a multipart POST carries the field named in
`session.upload_progress.name` (`PHP_SESSION_UPLOAD_PROGRESS` by default), as a confirmed
path for CVE-2026-109619. The parser runs before the application script and before any login.
Blocking multipart at the edge where it is not needed removes those paths. It does not cover
an application-specific out-of-memory condition caused by other input.

## Why the regex catches the comma variant

PHP lowercases the `Content-Type` and truncates it at the first `;`, `,` or space before it
matches a post handler, then looks for `boundary` anywhere in the header. So
`Content-Type: multipart/form-data,boundary=x` is multipart to PHP, and a rule that only
matches `multipart/form-data` followed by `;` or whitespace is bypassable with a comma.
Sources (PHP 8.4.26):

- method gate (only `POST` in `sapi_activate`): [`main/SAPI.c#L463-L470`](https://github.com/php/php-src/blob/php-8.4.26/main/SAPI.c#L463-L470)
- Content-Type lowercase and truncation at `;` `,` space: [`main/SAPI.c#L180-L197`](https://github.com/php/php-src/blob/php-8.4.26/main/SAPI.c#L180-L197)
- boundary via `strstr`: [`main/rfc1867.c#L708`](https://github.com/php/php-src/blob/php-8.4.26/main/rfc1867.c#L708)
- `request_parse_body()` reads the body by Content-Type with no `POST` gate (PHP 8.4+): [`ext/standard/http.c#L349`](https://github.com/php/php-src/blob/php-8.4.26/ext/standard/http.c#L349)

## Limits

- Per-route exceptions do not protect those routes. The multipart parser runs before your
  application code and before authentication, so any route you allow stays exposed.
- The exploit was demonstrated end to end on mod_php only. For FPM, FrankenPHP and LSAPI the
  first issue is source analysis, and "not demonstrated" does not mean "not exploitable".
- PHP gives no list of affected versions below 7.4. Treat PHP 5.x and 7.3 as exposed.
- `.htaccess` can be silently ignored: insufficient `AllowOverride`, `ProxyPassMatch` or
  `SetHandler proxy:fcgi` setups, nested `.htaccess` with their own `RewriteEngine`, or a rule
  placed after an earlier `[L]`. Use `%{HTTP:Content-Type}`, not `%{CONTENT_TYPE}`.
- From PHP 8.4 `request_parse_body()` parses multipart on PUT and PATCH too, so the rules
  include them.
- Nginx with an `error_page` cycle: with `error_page 403 ...` and `recursive_error_pages on`
  (the ISPConfig default) a plain `if ... return 403;` turns into HTTP 500 through an internal
  redirect. The `$pp_errpage` map keyed on `$uri`, plus `volatile`, prevents it. Verified in
  production and on an isolated nginx 1.24.
- A WAF parses multipart differently from PHP. The ModSecurity rule is a layer, not a fix.
- An empty error log does not prove the server is safe.

## Test

```bash
# decision table, no server needed
python3 test/test_logic.py

# full Nginx container test (needs Docker)
bash test/run-docker-test.sh
```

## After the update

Update PHP to a patched release and remove these rules where you can. Keep them only for
branches that will not be patched, and re-check against the advisory.

## Detection

- PHP worker crashes (PHP-FPM or LiteSpeed's `lsphp`) with SIGSEGV or SIGABRT in the logs,
  especially close to multipart POSTs.
- Access-log multipart POSTs carrying a `PHP_SESSION_UPLOAD_PROGRESS` field on routes that
  never accept uploads.
- Session files in `session.save_path` with upload-progress entries for sessions that never
  uploaded, or rewritten unusually often.
- Enable `log_errors`, a working `error_log` and `error_reporting = E_ALL` in an isolated
  environment to find fatal errors and timeouts reachable from outside.

## Read more on pasqualepillitteri.it

- [PHP2Shell, what to do if you can't update PHP (legacy apps)](https://pasqualepillitteri.it/en/news/26241/php2shell-cant-update-php-legacy-apps)
- [php2shell, block PHP attacks with Nginx and Apache before the patch](https://pasqualepillitteri.it/en/news/26086/php2shell-nginx-apache-rules-block-php-before-patch)
- [PHP RCE flaws leak, patch arrives October 21](https://pasqualepillitteri.it/en/news/26058/php-rce-flaws-leak-patch-october-21)
- [Drupal patches two critical RCE flaws, update before the exploits](https://pasqualepillitteri.it/en/news/25257/drupal-critical-rce-flaws-field-ui-entity-list)
- [Nextcloud, PHP web shell via Collabora CODE](https://pasqualepillitteri.it/en/news/24056/nextcloud-collabora-code-web-shells-cve)
- [NGINX, five vulnerabilities fixed in 1.31.7 and 1.30.6](https://pasqualepillitteri.it/en/news/23956/nginx-vulnerabilities-cve-2026-97205-1-31-7-en)
- [October 2026 Patch Tuesday, record 1,411 flaws and three zero-days](https://pasqualepillitteri.it/en/news/23803/october-2026-patch-tuesday-record-1411-flaws-three-zero-days)

## License

MIT, see [LICENSE](LICENSE).
