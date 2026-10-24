# php2shell-hardening

Unofficial edge rules that stop `multipart/form-data` requests before they reach PHP, as a
stopgap for CVE-2026-109618 and CVE-2026-109619 ("php2shell") on installations that cannot
be updated yet. Covers Nginx, Apache, ModSecurity, Caddy, lighttpd, LiteSpeed, FrankenPHP, Cloudflare and
`php.ini`, with a test suite. The `session.upload_progress` setting here is also the mitigation
PHP asks for against CVE-2026-115560, a third issue published on 23 October 2026 that has no
release yet.

If you run PHP 7.4, 8.0 or 8.1, look first for a vendor package with the fix: Ubuntu Pro for
20.04, Red Hat and AlmaLinux for 8 and 9, cPanel and CloudLinux for hosting, or a build from the
backport branches. Those packages keep the old version number, see "Getting a fixed package".

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
first. Several of them have already shipped the fix for the old branches (Ubuntu Pro for 20.04,
RHEL and AlmaLinux, cPanel, CloudLinux, see below). Packages with a backport keep the old
version number.

### 23 October 2026: CVE-2026-115560

Two days after the advisory PHP published a
[note](https://www.php.net/index.php#2026-10-23-1) on a third RCE vector, CVE-2026-115560,
again through session upload progress. There is no release for it: PHP calls the scenario
unlikely, handles it in the normal bugfix cycle and will publish the full advisory with the
next release. No affected-version list yet, and the patched versions of 21 October do not
cover it.

It needs three conditions at the same time:

- `session.serialize_handler` set to `php_binary` or `php_serialize` in the configuration,
- the application switching it to `php` with `ini_set()` before `session_start()`,
- session upload progress still enabled.

The mitigation is the one already in this repository, `session.upload_progress.enabled = 0`.
If you applied it for CVE-2026-109619 on 21 October there is nothing else to do: keep it off
until the next bugfix release. Applications that never change the serialize handler at runtime
can leave the feature on, so check the code before deciding:

```bash
grep -rn --include='*.php' -E "ini_set\s*\(\s*['\"]session\.serialize_handler" /var/www
```

## Getting a fixed package

A vendor backport is the upstream fix applied to the old code without a new PHP version. The
package keeps its number, so `php -v` says nothing about whether the fix is there, and scanners
that compare only versions report patched systems as vulnerable. Check the package changelog
for the CVE instead; the commands are in each section.

### Ubuntu 20.04

`php7.4` is fixed in `7.4.3-4ubuntu2.29+esm5`
([USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)), available only with Ubuntu
Pro. On 20.04 `php7.4` is in main, so the fix is in `esm-infra`. The same notice covers 18.04
(`php7.2 7.2.24-0ubuntu0.18.04.17+esm14`, Pro) and 16.04 and 14.04 (`php7.0 ...+esm22`,
`php5 ...+esm18`, Legacy Support add-on). Releases that are still supported get the fix without
a subscription, from [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1): 22.04
`php8.1 8.1.2-1ubuntu2.28`, 24.04 `php8.3 8.3.6-0ubuntu0.24.04.13`, 26.04
`php8.5 8.5.4-0ubuntu1.5`. To check 20.04 after `pro attach` and `apt upgrade`:

```bash
dpkg -s php7.4-cli | grep ^Version    # 7.4.3-4ubuntu2.29+esm5 or later
```

The free Ubuntu Pro subscription covers up to 5 physical machines, with unlimited VMs and
containers on them (50 for official Ubuntu community members). Canonical words the eligibility
in different ways. [ubuntu.com/pro](https://ubuntu.com/pro) says personal use, the
[2022 announcement](https://canonical.com/blog/ubuntu-pro-beta-release) and the
[FAQ](https://discourse.ubuntu.com/t/ubuntu-pro-faq/34042) say personal and small-scale
commercial use, and the [personal terms](https://canonical.com/legal/ubuntu-pro/personal) allow
one account per company or legal entity, ask you to name the company when you register on its
behalf and cap it at 5 physical systems. None of them says what happens with a machine that
belongs to a client or an employer, so ask Canonical before relying on it for those. Going over
the limit is not blocked, but Canonical counts the active machines, and `sudo pro detach` frees
a slot.

On a machine that is not attached, the table printed by `pro status` lists the services that
are available, not the ones that are active. Check `attached` in `pro status --format json`.

If PHP 7.4 came from the ondrej PPA, its packages carry epoch `1:` (`1:7.4.33-20+ubuntu20.04.1`)
and apt sees them as newer than Ubuntu's: it never moves to the ESM build on its own, so
install the ESM versions explicitly. Extensions taken from the PPA (apcu, imagick and similar)
come from other source packages with their own versions, so check each of them too. The PPA removed its focal packages in
June 2025 and the downloads now return 404, so save what is installed before switching, or
there is no way back:

```bash
apt install dpkg-repack
dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' 'php7.4*' | awk '$1 == "ii" { print $2 }' | xargs dpkg-repack
```

### ondrej/sury packages

On 21 October `php7.4 1:7.4.33-31` was published for Debian 11, 12 and 13 and Ubuntu 22.04,
24.04 and 26.04. Its changelog lists "Avoid state corruption via bailout" for CVE-2026-109618 and
CVE-2026-109619, backported from 8.2.35. There is no such build for Ubuntu 20.04 or Debian 10.

When you update from these repositories, upgrade only the packages built from the PHP source
you run. Upgrading the PECL extension packages (`php8.2-apcu`, `php8.2-imagick`,
`php8.2-memcache`) pulls in the `php-*` metapackages, which install PHP 8.5 and switch
`/usr/bin/php` to it.

```bash
apt-get install --only-upgrade $(dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package} ${source:Package}\n' | awk '$1 == "ii" && $3 == "php8.2" { print $2 }')
# if /usr/bin/php has already moved
update-alternatives --set php /usr/bin/php8.2
```

### Debian

Debian 12 has `php8.2 8.2.35-1~deb12u1` (DLA-4848-1) and Debian 13 `php8.4 8.4.27-1~deb13u1`
(DSA-6574-1), as listed by the
[Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618). The
tracker has no data for `php7.4` on Debian 11. A third-party summary reports a Freexian ELTS
(paid extended support) advisory, ELA-1853-1, with `php7.4 7.4.33-1+deb11u14`; confirm it with
Freexian before relying on it. The free alternative is the sury.org build above.

### Red Hat, AlmaLinux and derivatives

RHEL 8 has the fix in the `php:7.4` module,
[RHSA-2026:87080](https://access.redhat.com/errata/RHSA-2026:87080), `php 7.4.33-8`, published
on 21 October together with ten other CVEs. AlmaLinux announced the same day, on its
[blog](https://almalinux.org/blog/), patched packages for every PHP stream on 8, 9 and 10. For
RHEL 7 the [bulletin RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013)
lists `session.upload_progress.enabled = 0` as the only change required. Check a package with:

```bash
rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'
```

### Hosting panels

CloudLinux, according to its
[blog](https://blog.cloudlinux.com/php-cve-2026-109618-and-cve-2026-109619): `ea-php` 5.2 to
8.5 fixed on 21 October at 20:55 UTC; `alt-php` 5.2 to 5.6, 7.0 to 7.4 and 8.0 to 8.5 in the
stable repositories of CloudLinux 7, 8 and 9 by 00:07 UTC on 22 October; on CloudLinux 10 only
5.2 is in the normal repository and the others come from the ELS repository, which has to stay
enabled; CloudLinux 6 is not confirmed. Its security metadata was not published at that point,
so `yum --security` does not list these packages: use a plain `dnf upgrade 'alt-php*'` or
`'ea-php*'`, then restart PHP.

```bash
rpm -q --changelog alt-php74-common | grep -E 'CVE-2026-(109618|109619)'
rpm -q --changelog ea-php74-php-cli | grep -E 'CVE-2026-(109618|109619)'
```

cPanel EasyApache 4 is reported to carry backports for `ea-php74`, `ea-php80` and `ea-php81`
(`7.4.33-19`, `8.0.30-12`, `8.1.34-5`, EA-13613, EA-13612, EA-13611) by
[ComputingForGeeks](https://computingforgeeks.com/patch-php2shell-cpanel-whm/), not by a cPanel
note. `ea-php73` and older have no fix; TuxCare ELS is a paid option, and its CVE tracker says
whether php2shell is covered. The Plesk and DirectAdmin forum threads of 21 October gave no
date and did not name 7.4, 8.0 or 8.1, so ask the vendor or the host which package contains the
fix and for the changelog line with CVE-2026-109618.

### Building from a backport branch

Without a vendor package, build from the branch of the PHP project. The 7.4 branch differs from
the 7.4 code by one security commit dated 18 October 2026 (17 files, 240 lines added, 59
removed), and the 8.0 and 8.1 branches work the same way. Reuse the options of the PHP you run
(`php -i | grep 'Configure Command'`) and install into a separate prefix:

```bash
git clone --depth 1 --branch PHP-7.4-CVE-2026-109618-109619 https://github.com/php/php-src.git
cd php-src
git log -1 --format='%h %ad %s'
./buildconf --force
./configure --prefix=/opt/php-7.4-patched <options of the current PHP>
make -j"$(nproc)"
sudo make install
```

The branch has the two fixes and nothing else, and 7.4 has been out of support since
November 2022, so other known flaws stay open and every later update is yours. Rebuild the PECL
extensions with the `phpize` of the new prefix, point the FPM unit at the new binary, try it in
staging with `error_reporting = E_ALL`, and keep the commit hash and the build log: `php -v`
does not prove the patch.

### Docker

Images built `FROM php:8.1-fpm` or older tags will not get the fix: there is no upstream
release for those branches. Move to an 8.2.35 or later tag, or build from a backport branch.

## If you cannot update

The risks, the cases where the flaws trigger and why a login or a missing upload form does
not protect you are covered in
[PHP2Shell, what to do if you can't update PHP](https://pasqualepillitteri.it/en/news/26241/php2shell-cant-update-php-legacy-apps).
The steps below, in order, from the strongest to the weakest.

1. Use a vendor package that contains the fix (see "Getting a fixed package"), or build from
   one of the backport branches above.
2. Try the smallest jump to a supported branch in staging, with `error_reporting = E_ALL`.
3. Put authentication in front of PHP, so an unauthorized request is rejected before the
   engine reads its body. Application-level login does not help: PHP parses the request
   before your script runs.
4. Limit request size at the edge and block multipart where it is not needed (the rules in
   this repository).
5. Apply the PHP settings below, with a memory cap outside PHP.

Then check the server with `test/audit-server.sh` (see "Audit a server" below).

### Authentication before PHP

Ready-to-edit files are in `nginx/auth-before-php.conf.example` and
`apache/auth-before-php.conf.example`. In short, Nginx with basic auth or an allow-list:

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

The same lines, with comments, are in `php-fpm/pool-php2shell.conf`.

Set them where the application cannot override them (`php_admin_value` and `php_admin_flag` in
the FPM pool or in the Apache configuration), not with `ini_set()` or `.user.ini`, and reload
PHP-FPM so every worker is recreated. Set `process_control_timeout` first (next section), or
the reload drops the requests in flight.

```ini
; PHP-FPM pool
php_admin_value[memory_limit] = -1
php_admin_value[post_max_size] = 8M
php_admin_value[max_input_nesting_level] = 32
php_admin_flag[session.upload_progress.enabled] = off
; PHP 8.5 only
php_admin_flag[fatal_error_backtraces] = off
; workers are recycled after 500 requests instead of never
pm.max_requests = 500
; stronger, costs performance: the worker is recreated after every request
;pm.max_requests = 1
```

- `memory_limit = -1` removes the limit an attacker could trip on purpose, but an underlying
  allocation failure can still reach the vulnerable path. Pair it with a container or cgroup
  limit that kills only the affected worker (see "Memory cap with systemd").
- Do not use `RLIMIT_AS` or `RLIMIT_DATA` (`ulimit -v`) as a memory cap. They make `mmap()`
  fail, which is the failure that triggers the vulnerable path.
- `post_max_size = 8M` is for applications without uploads. If uploads are needed PHP suggests
  32M, with `upload_max_filesize` below it.
- `session.upload_progress.enabled = off` blocks the confirmed session paths and not other
  variants. It is also the only mitigation for CVE-2026-115560, which has no release yet, so
  keep it off after the update unless you use the feature and your code never calls
  `ini_set('session.serialize_handler', ...)`.
- `pm.max_requests` defaults to 0, so a worker and its state can live until the next reload.
  500 bounds that at almost no cost. The advisory suggests 1 if performance allows; neither
  removes the condition.
- The advisory asks for a lower `max_input_nesting_level` than the default 64.
- Remove or fix settings that emit diagnostics before initialization, and fix fatal errors
  and execution timeouts an attacker can reach. Hiding messages with `error_reporting`,
  `display_errors` or `@` does not help. See "Values passed to PHP per request" and
  "Startup warnings" below.

Verify values from the web SAPI with a temporary `phpinfo()` page, not from the CLI, then
delete it.

### Reloading PHP-FPM without dropping requests

With the default `process_control_timeout = 0` a reload sends SIGQUIT and then SIGTERM to every
worker at once: the requests in flight are cut and nginx answers 502. On a busy site that is
hundreds of failed requests for each reload. Give the workers time to finish, in the `[global]`
section of `php-fpm.conf`, above the `include=` line (`php-fpm/global-php2shell.conf`):

```ini
[global]
process_control_timeout = 10s
```

Added at the end of the file, after `include=`, the line is read as part of the last pool and
FPM refuses the configuration with `unknown entry 'process_control_timeout'`. The reload that
applies the setting still runs with the old value, because the master stops the workers before
it re-reads its configuration, so do that first reload at a quiet moment. Test before every
reload:

```bash
php-fpm7.4 -t && systemctl reload php7.4-fpm
```

### Memory cap with systemd

`memory_limit = -1` needs a cap outside PHP. With systemd, a drop-in on the FPM unit sets it
(`systemd/php-fpm-memory.conf`):

```ini
# /etc/systemd/system/php7.4-fpm.service.d/php2shell-memory.conf
[Service]
MemoryMax=2G
MemorySwapMax=0
MemoryLimit=2G
OOMPolicy=continue
Restart=on-failure
```

- Check the current usage first with `systemctl show -p MemoryCurrent php7.4-fpm` and size the
  cap above it. A cap below the usage makes the kernel reclaim and kill right away.
- Apply it without a restart with
  `systemctl set-property --runtime php7.4-fpm.service MemoryMax=2G MemorySwapMax=0`
  (`MemoryLimit=2G` on cgroup v1), then `systemctl daemon-reload` for the drop-in.
  `OOMPolicy=` cannot be set with `set-property`; `daemon-reload` applies it to the running
  service.
- `MemoryMax=` and `MemorySwapMax=` are for cgroup v2, `MemoryLimit=` for cgroup v1.
  `stat -fc %T /sys/fs/cgroup` prints `cgroup2fs` on v2. There, drop `MemoryLimit=`: systemd
  252 and later log it as deprecated.
- With the default `OOMPolicy=stop` on cgroup v2, the first time the kernel kills a worker for
  memory systemd stops the whole service, every pool with it. `continue` keeps it running and
  the master starts a new worker. On cgroup v1 systemd does not see OOM kills, and systemd
  older than 243 (Debian 10, CentOS 8) ignores the line.
- Without `MemorySwapMax=0` the pool goes to swap at the cap and a runaway worker is not
  killed until swap runs out.
- The kernel kills one process, normally the largest worker, but the advisory warns that the
  master can go too. `Restart=on-failure` brings the service back in that case.

On systemd 252 with cgroup v2, one worker killed under `OOMPolicy=stop` left the unit failed
with `oom-kill`; under `continue` only that request got a 502.

### Values passed to PHP per request

On FPM, INI values sent by the web server with each request (`PHP_VALUE` and
`PHP_ADMIN_VALUE`) are applied before the request starts; the advisory for CVE-2026-109619
names them as the FPM path when one of them produces a diagnostic. Pool values and `.user.ini`
do not behave that way. Find them and move the settings into the pool:

```bash
nginx -T 2>/dev/null | grep -E 'fastcgi_param\s+PHP_(ADMIN_)?VALUE'
grep -rnE 'PHP_(ADMIN_)?VALUE' /etc/apache2 /etc/httpd 2>/dev/null
```

With mod_php the same holds for `php_value` and `php_flag` in `.htaccess` and in the Apache
configuration. mod_php is also where the full exploit was shown, so make sure it is not loaded
even where Apache is stopped and FPM does the work: a later start of Apache brings it back.

```bash
apachectl -M 2>/dev/null | grep -i php    # reads the configuration, works with Apache stopped
a2dismod php7.4                           # Debian, Ubuntu
```

On RHEL and CentOS the module is loaded by `/etc/httpd/conf.modules.d/15-php.conf`: comment
out its `LoadModule` line.

### Startup warnings

The easiest diagnostics to find are the warnings PHP prints each time FPM starts or reloads.
A common cause is `extension=` lines added to `php.ini` for modules the distribution already
loads from `conf.d`:

```
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli' (... undefined symbol: mysqlnd_global_stats)
PHP Warning:  Module 'curl' already loaded
```

`mysqli` listed in `php.ini` loads before `mysqlnd` from `conf.d` and fails, and `curl` is
loaded twice. These come from module startup, not from a request, so they are not the path
the advisory describes. On a production server they came with short bursts of HTTP 500
(`HeadersAlreadySentException` from the framework) right after a reload, and they bury the
warnings that matter. Remove the duplicates and check that FPM starts clean:

```bash
php-fpm7.4 -m 2>&1 | grep -ciE 'warning|unable|already loaded'    # expect 0
```

### ISPConfig

ISPConfig rewrites pool files and vhosts from its templates each time a site is saved in the
panel, so lines added by hand to `pool.d/web*.conf` or to the vhost disappear. Put them where
the panel keeps them:

- PHP settings in the site's Options tab, "Custom php.ini settings". For PHP-FPM, ISPConfig
  writes them into the pool as `php_admin_value` and `php_admin_flag`.
- nginx rules in the same tab, "nginx Directives".
- Settings for every site in a copy of the template under
  `/usr/local/ispconfig/server/conf-custom/`, such as `php_fpm_pool.conf.master` or
  `nginx_vhost.conf.master`. Compare it with the new template after each ISPConfig update.

The `[global]` section of `php-fpm.conf` and the systemd drop-in are not managed by ISPConfig.

## What's here

- `nginx/php2shell-maps.conf`: `map` blocks for `http{}`, flags multipart POST, PUT and PATCH
  minus an upload-route allowlist
- `nginx/php2shell-server-snippet.conf`: the `if` that returns 403, for `server{}`
- `apache/.htaccess`: `mod_rewrite` rule that returns 403 on multipart POST, PUT and PATCH
- `apache/modsecurity-php2shell.conf`: ModSecurity rules on the `PHP_SESSION_UPLOAD_PROGRESS`
  field and on malformed bodies, plus optional body limits and a multipart block
- `apache/auth-before-php.conf.example`: IP allow-list or basic auth and request limits for Apache
- `nginx/auth-before-php.conf.example`: IP allow-list or basic auth and body limit for Nginx
- `cloudflare/custom-rule.md`: custom-rule expression, scoped, and what not to do
- `caddy/php2shell.caddyfile`: matcher that returns 403 on multipart except upload routes
- `frankenphp/Caddyfile-snippet`: disables session upload progress
- `lighttpd/php2shell.conf`: multipart block, to scope per vhost
- `litespeed/php2shell.conf`: the same rewrite rule for LiteSpeed Enterprise and
  OpenLiteSpeed, plus where the `lsphp` `php.ini` lives
- `php-fpm/99-php2shell.ini`: session hardening for `php.ini`
- `php-fpm/pool-php2shell.conf`: the advisory settings as `php_admin_*` lines for an FPM pool,
  with `pm.max_requests`
- `php-fpm/global-php2shell.conf`: `process_control_timeout`, so a reload does not drop requests
- `systemd/php-fpm-memory.conf`: drop-in with the memory cap and `OOMPolicy=continue`
- `test/audit-server.sh`: read-only audit of a PHP-FPM server
- `test/verify.sh`: checks a running site, any web server, against the multipart block
- `test/check-sync.py`: fails when the maps in the container test drift from the shipped ones
- `test/`: decision-table check and a self-contained Nginx container test
- `.github/workflows/test.yml`: runs all of the above on every push

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

## Check that it works

After applying a rule, run the checker against staging. It sends empty POST and PUT
requests and expects multipart (including the comma and upper-case variants) to be blocked,
while GET, urlencoded and JSON requests pass.

```bash
bash test/verify.sh https://staging.example.test /upload
```

The second argument is an upload route that must keep working; leave it out if there is none.
A blocked request answers 403, 400 or drops the connection (nginx `return 444`).

## Audit a server

`test/audit-server.sh` runs on the server, as root, and changes nothing. It reads the effective
configuration with `php-fpm -tt`, `nginx -T`, `apachectl -M` and `systemctl show`, for every
PHP-FPM it finds (distribution packages, ISPConfig builds in `/opt/php-*`, Remi), and checks:

- `memory_limit = -1`, `session.upload_progress.enabled` off and `pm.max_requests` above 0 as
  `php_admin_*` in every pool
- `process_control_timeout` above 0
- no startup warnings from `php-fpm -m`
- no `RLIMIT_AS` or `RLIMIT_DATA` on the running master and workers, and no `LimitAS=` or
  `LimitDATA=` on the unit
- `MemoryMax=` (`MemoryLimit=` on cgroup v1) and `OOMPolicy=continue` on the unit
- no `PHP_VALUE` or `PHP_ADMIN_VALUE` passed by nginx or Apache
- mod_php not loaded or enabled, and `php_value` in `.htaccess` when it is
- no `client_max_body_size 0` in the nginx configuration

```bash
sudo bash test/audit-server.sh
```

Each line is PASS, WARN or SKIP, and the exit code is 1 if there is a WARN. The output names
files, pools and settings of the server, so read it before you share it.

## Test

```bash
# decision table, no server needed
python3 test/test_logic.py

# the container test and the shipped maps still agree
python3 test/check-sync.py

# full Nginx container test (needs Docker)
bash test/run-docker-test.sh
```

The Apache, Caddy, lighttpd and LiteSpeed rules have no container test yet: check them with
`test/verify.sh`.

Every push runs the decision table, the shell syntax check, the drift check and the Nginx
container test through `.github/workflows/test.yml`.

## After the update

Update PHP to a patched release and remove these rules where you can. Keep them only for
branches that will not be patched, and re-check against the advisory.

Keep `session.upload_progress.enabled = off` even on a patched release until the bugfix
release that fixes CVE-2026-115560 is out: the versions of 21 October do not contain that fix.

## Detection

Scanning is worth assuming. As of 23 October 2026 watchTowr reports exploitation attempts
against its honeypots since 21 October, Amazon describes the flaws as broadly exploited and
traced an attempt back to 17 October, before disclosure, and Cloudflare reports attack traffic
against its customers. Huntress and CISA saw none on 21 October, no compromise has been
confirmed publicly, and neither CVE is in the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) yet. Check
the live catalog rather than this line.

- PHP worker crashes (PHP-FPM or LiteSpeed's `lsphp`) with SIGSEGV or SIGABRT in the logs,
  especially close to multipart POSTs.
- Access-log multipart POSTs carrying a `PHP_SESSION_UPLOAD_PROGRESS` field on routes that
  never accept uploads.
- Session files in `session.save_path` with upload-progress entries for sessions that never
  uploaded, or rewritten unusually often.
- Enable `log_errors`, a working `error_log` and `error_reporting = E_ALL` in an isolated
  environment to find fatal errors and timeouts reachable from outside.

## Read more on pasqualepillitteri.it

- [php2shell on PHP 7.4, the patch is in Ubuntu 20.04 Pro and web hosting](https://pasqualepillitteri.it/en/news/26862/php2shell-php-74-patch-ubuntu-20-04-pro-hosting)
- [PHP2Shell, what to do if you can't update PHP (legacy apps)](https://pasqualepillitteri.it/en/news/26241/php2shell-cant-update-php-legacy-apps)
- [php2shell, block PHP attacks with Nginx and Apache before the patch](https://pasqualepillitteri.it/en/news/26086/php2shell-nginx-apache-rules-block-php-before-patch)
- [PHP RCE flaws leak, patch arrives October 21](https://pasqualepillitteri.it/en/news/26058/php-rce-flaws-leak-patch-october-21)
- [Drupal patches two critical RCE flaws, update before the exploits](https://pasqualepillitteri.it/en/news/25257/drupal-critical-rce-flaws-field-ui-entity-list)
- [Nextcloud, PHP web shell via Collabora CODE](https://pasqualepillitteri.it/en/news/24056/nextcloud-collabora-code-web-shells-cve)
- [NGINX, five vulnerabilities fixed in 1.31.7 and 1.30.6](https://pasqualepillitteri.it/en/news/23956/nginx-vulnerabilities-cve-2026-97205-1-31-7-en)
- [October 2026 Patch Tuesday, record 1,411 flaws and three zero-days](https://pasqualepillitteri.it/en/news/23803/october-2026-patch-tuesday-record-1411-flaws-three-zero-days)

## License

MIT, see [LICENSE](LICENSE).
