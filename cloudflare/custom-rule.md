# Cloudflare custom rule (php2shell) - UNOFFICIAL, PROVISIONAL

Dashboard: **Security -> WAF -> Custom rules**. Action: **Block**.

> Cloudflare has deployed **managed WAF rules** for php2shell on all plans, including Free. That protection may already be active on your zone. The rules below are for extra, explicit control.

## Recommended: block multipart, scoped, except upload routes

```
(any(lower(http.request.headers["content-type"][*]) contains "multipart/form-data"))
and (http.request.method in {"POST" "PUT" "PATCH"})
and not (
  http.request.uri.path eq "/upload" or starts_with(http.request.uri.path, "/upload/")
  or http.request.uri.path eq "/api/upload" or starts_with(http.request.uri.path, "/api/upload/")
  or http.request.uri.path eq "/wp-admin/async-upload.php"
)
```

`contains "multipart/form-data"` also catches the comma variant
(`multipart/form-data,boundary=x`), which PHP still treats as multipart. PUT/PATCH are
included because PHP 8.4's `request_parse_body()` parses multipart on those methods too.
Adapt the upload-route allowlist to your app. This still blocks legitimate uploads on every
other route.

Use `eq` plus `starts_with()`, not `http.request.uri.path in {...}`: `in` matches the exact
path only, so `/upload/image` would be blocked while the Nginx and Caddy rules let it through.
`starts_with()` is anchored at the beginning of the path, so `/uploads-report` does not match
`/upload/`, the same segment boundary the other rules use.

## Surgical (Enterprise, request-body inspection): block only the PoC field

```
any(http.request.body.form.names[*] == "PHP_SESSION_UPLOAD_PROGRESS")
```

Blocks only requests carrying the `PHP_SESSION_UPLOAD_PROGRESS` form field, so normal uploads
keep working. Needs a plan where the request body is available to custom rules. If you changed
`session.upload_progress.name` in php.ini, use that name instead.

## Do NOT block on PHPSESSID

A widely shared snippet also blocks any request whose cookie or query string contains
`phpsessid`. Do not use that:

- **It breaks normal visitors.** `PHPSESSID` is PHP's default session cookie, sent on most
  requests by anyone with a session (login, cart, dashboard). Blocking it takes the site down
  for them.
- **It does not match the exploit.** The PoC uses the `PHP_SESSION_UPLOAD_PROGRESS` form field,
  not the `PHPSESSID` cookie; upload-progress can start a session from the multipart field with
  no cookie at all.
- **It is bypassable.** Apps that set a custom session name via `session_name()` never match
  the literal `PHPSESSID`.

As always: a WAF parses multipart differently from PHP, these are stopgaps, and the real fix is
to update PHP.
