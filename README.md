# htaccesslint

Lint Apache `.htaccess` files offline. Standard library only, Python 3.9+. It reads text; it never contacts a server, so it cannot tell you whether Apache will accept a file, only that something looks wrong or risky. Run it on a copy before you upload a change.

```
$ python -m htaccesslint tests/data/messy.htaccess
tests/data/messy.htaccess: 15 findings
  warn  line 1 [typo] unknown directive 'RewriteEngin'; did you mean 'rewriteengine'?
  error line 3 [rewritecond] RewriteCond is not followed by a RewriteRule
  warn  line 4 [header-always] X-Frame-Options is set without 'always', so it is missing from error responses (4xx/5xx)
  warn  line 5 [hsts] 'preload' needs max-age of at least 31536000 (one year); this is 300
  warn  line 7 [access-2.2] Order is Apache 2.2 access control (needs mod_access_compat in 2.4); use 'Require' instead
  error line 12 [context] AllowOverride is not allowed in .htaccess (only in the server or virtual-host configuration)
  error line 15 [container] </FilesMatch> closes <IfModule> from line 13
  ...
4 errors, 9 warnings
```

## Usage

```
python -m htaccesslint FILE [FILE ...] [--json] [--strict] [--quiet]
```

`-` reads standard input. `--quiet` hides info-level findings. Exit code `0` if there are no errors, `1` for errors (or warnings with `--strict`), `2` if a file can't be read.

## Rules

| Rule | Level | What it flags |
| --- | --- | --- |
| `container` | error | `<IfModule>`, `<Files>`, `<FilesMatch>` and other containers that are never closed, closed by the wrong tag, or closed with nothing open |
| `rewritecond` | error | a `RewriteCond` not followed by a `RewriteRule` |
| `rewriteengine` | warn | `RewriteRule` before any `RewriteEngine On` in the file |
| `context` | error / info | `AllowOverride` (not allowed in `.htaccess`); `ServerTokens` (server config only) |
| `header-always` | warn | a security header (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy, Cross-Origin-*) set without `always`, so it is missing from error responses |
| `hsts` | error / warn / info | no `max-age`; `preload` with under a year or without `includeSubDomains`; `max-age` under 180 days (info: fine while testing) |
| `csp` | warn / info | `default-src *`; `'unsafe-inline'` or `'unsafe-eval'` (info) |
| `header-twice` | warn | the same header set twice with different values |
| `access-2.2` | warn | `Order`, `Allow`, `Deny`, which need `mod_access_compat` in Apache 2.4 |
| `php-directive` | warn | `php_value`/`php_flag` outside `<IfModule mod_php*.c>`, which gives a 500 error under PHP-FPM or CGI |
| `ifmodule` | info | `ExpiresActive` outside `<IfModule mod_expires.c>` |
| `indexes` | warn | `Options +Indexes` or `Indexes` (directory listings) |
| `duplicate` | warn | the same line twice in the same container |
| `typo` | warn | a directive one or two characters away from a well-known one (`RewriteEngin`) |
| `crlf` | warn | Windows line endings |

Lines ending in `\` are joined, comments are skipped, and a line repeated in *different* containers is not a duplicate.

## What it does not do

- It does not parse every Apache directive. The typo check knows about 100 common ones and stays silent about anything else, so a custom module's directive is not flagged.
- It cannot know which modules your server has, which Apache version runs, or what the main configuration already sets, so `access-2.2`, `php-directive` and `rewriteengine` are prompts to check, not proof of a fault.
- It does not evaluate `RewriteCond`/`RewriteRule` patterns, so it does not find redirect loops.

## Tests

```
python -m unittest discover -s tests -v
```

MIT licence.
