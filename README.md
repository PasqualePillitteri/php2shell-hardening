# php2shell-hardening

Unofficial, provisional edge rules to block `multipart/form-data` requests before they
reach PHP, as a stopgap for **CVE-2026-109618 / CVE-2026-109619** ("php2shell") while you
wait to update PHP. Covers **Nginx, Apache, ModSecurity and `php.ini`**, with a test suite.

> ### Read this first
> - **These rules are UNOFFICIAL and PROVISIONAL.** As of 21 October 2026 PHP had not
>   published the root cause, the affected versions, or the CVE-to-bug mapping. The link to
>   `multipart` / `session.upload_progress` comes from a leaked PoC and third-party analysis,
>   **not** confirmed by PHP.
> - **The real fix is to update PHP** to the patched release. These rules buy time; they are
>   not a substitute for the vendor patch.
> - **They block legitimate uploads and multipart forms.** Apply them only to routes that do
>   not need uploads, and **test in staging first**. A wrong or bypassable block rule in
>   production does damage.

## Why multipart

The leaked PoC ("php2shell") reaches PHP's multipart handling, including the
`session.upload_progress` callback, **before the application script runs**, by sending a
`multipart/form-data` POST (in most public PoCs a field named `PHP_SESSION_UPLOAD_PROGRESS`).
Blocking that request type at the edge, where you do not need it, removes the entry path.
This is attribution from researchers, unverified by PHP.

## What's here

| Path | What it does |
|---|---|
| `nginx/php2shell-maps.conf` | `map` blocks in `http{}`: flags POST/PUT/PATCH multipart, minus an upload-route allowlist |
| `nginx/php2shell-server-snippet.conf` | the `if (...) return 403;` to include in `server{}` |
| `apache/.htaccess` | `mod_rewrite` rule that 403s multipart POST/PUT/PATCH |
| `apache/modsecurity-php2shell.conf` | ModSecurity rule that denies the `PHP_SESSION_UPLOAD_PROGRESS` field |
| `cloudflare/custom-rule.md` | Cloudflare custom-rule expression (multipart block, scoped) + what NOT to do |
| `caddy/php2shell.caddyfile` | Caddy matcher that 403s multipart except upload routes |
| `frankenphp/Caddyfile-snippet` | FrankenPHP: disable session upload progress |
| `lighttpd/php2shell.conf` | lighttpd multipart block (scope per vhost) |
| `php-fpm/99-php2shell.ini` | `session.upload_progress.enabled = Off` |
| `test/test_logic.py` | fast check of the Nginx decision table (no server needed) |
| `test/` | self-contained Nginx container test (see below) |

## Why the regex catches the comma variant

PHP lowercases the `Content-Type` and truncates it at the first `;`, `,` or space before it
matches a post handler, then looks for `boundary` anywhere in the header. So
`Content-Type: multipart/form-data,boundary=x` **is multipart to PHP**. A rule that only
matches `multipart/form-data` followed by `;` or whitespace is bypassable with a comma.
Sources (PHP 8.4.26):

- method gate (only `POST` in `sapi_activate`): [`main/SAPI.c#L463-L470`](https://github.com/php/php-src/blob/php-8.4.26/main/SAPI.c#L463-L470)
- Content-Type lowercase + truncate at `;` `,` ` `: [`main/SAPI.c#L180-L197`](https://github.com/php/php-src/blob/php-8.4.26/main/SAPI.c#L180-L197)
- boundary via `strstr`: [`main/rfc1867.c#L708`](https://github.com/php/php-src/blob/php-8.4.26/main/rfc1867.c#L708)
- `request_parse_body()` reads the body by Content-Type with no `POST` gate (PHP 8.4+): [`ext/standard/http.c#L349`](https://github.com/php/php-src/blob/php-8.4.26/ext/standard/http.c#L349)

## Limits (honest)

- **Per-route exceptions do not protect those routes.** The multipart parser runs before your
  app code and before authentication, so any route you allow stays exposed.
- **`session.upload_progress.enabled = Off`** is `PHP_INI_PERDIR` (so `ini_set()` cannot change
  it) and, per one researcher, closes only **one** of the two suspected bugs. Verify from the
  **web** SAPI with `phpinfo()`, not the CLI, then delete the test file. Reload PHP-FPM.
- **`.htaccess` can be silently ignored**: insufficient `AllowOverride`, `ProxyPassMatch` /
  `SetHandler proxy:fcgi` setups, nested `.htaccess` with their own `RewriteEngine`, or a rule
  placed after an earlier `[L]`. Use `%{HTTP:Content-Type}`, not `%{CONTENT_TYPE}`.
- **PUT/PATCH**: from PHP 8.4 `request_parse_body()` parses multipart on those methods too, so
  these rules include them.
- **Nginx + `error_page` cycle (fixed here).** With `error_page 403 ...` + `recursive_error_pages on` (ISPConfig default), a plain `if ... return 403;` turns into HTTP 500 via an internal-redirect cycle. The `$pp_errpage` map (keyed on `$uri`) plus `volatile` prevents it. Verified in production and on isolated nginx 1.24.
- **PHP 8.1 and older** will not get an official fix. There these stopgaps may need to stay.
- **A WAF parses multipart differently from PHP.** The ModSecurity rule is a layer, not a fix.

## Test

```bash
# fast decision-table check, no server:
python3 test/test_logic.py

# full Nginx container test (needs Docker):
bash test/run-docker-test.sh
```

## After the official patch

Update PHP to the patched release and remove these rules where you can. Keep them only for
branches that will not be patched (EOL 8.1 and earlier), and re-check against PHP's advisory.

## Detection

Until you patch, watch for signs that someone is probing:

- PHP worker crashes (PHP-FPM or LiteSpeed's `lsphp`) with SIGSEGV/SIGABRT in the logs, especially correlated with multipart POSTs.
- Access-log multipart POSTs carrying a `PHP_SESSION_UPLOAD_PROGRESS` field to routes that never accept uploads.
- Session files in `session.save_path` with upload-progress entries for sessions that never uploaded, or rewritten unusually often.

## Read more on pasqualepillitteri.it

This repo accompanies the guide on pasqualepillitteri.it:

- [php2shell, block PHP attacks with Nginx and Apache before the patch](https://pasqualepillitteri.it/en/news/26086/php2shell-nginx-apache-rules-block-php-before-patch)

More related security coverage:

- [PHP RCE flaws leak, patch arrives October 21](https://pasqualepillitteri.it/en/news/26058/php-rce-flaws-leak-patch-october-21)
- [Drupal patches two critical RCE flaws, update before the exploits](https://pasqualepillitteri.it/en/news/25257/drupal-critical-rce-flaws-field-ui-entity-list)
- [Nextcloud, PHP web shell via Collabora CODE](https://pasqualepillitteri.it/en/news/24056/nextcloud-collabora-code-web-shells-cve)
- [NGINX, five vulnerabilities fixed in 1.31.7 and 1.30.6](https://pasqualepillitteri.it/en/news/23956/nginx-vulnerabilities-cve-2026-97205-1-31-7-en)
- [October 2026 Patch Tuesday, record 1,411 flaws and three zero-days](https://pasqualepillitteri.it/en/news/23803/october-2026-patch-tuesday-record-1411-flaws-three-zero-days)

## License

MIT, see [LICENSE](LICENSE).
