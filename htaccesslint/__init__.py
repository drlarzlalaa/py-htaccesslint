"""Lint Apache .htaccess files offline. It reads text; it never talks to a server, so it cannot say whether Apache will accept a file."""
import difflib
import re

SECURITY_HEADERS = ("strict-transport-security", "x-frame-options", "x-content-type-options", "content-security-policy",
                    "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy")
CONTAINERS = {"ifmodule", "ifdefine", "ifversion", "files", "filesmatch", "directory", "directorymatch", "location", "locationmatch",
              "limit", "limitexcept", "if", "elseif", "else", "requireall", "requireany", "requirenone", "virtualhost"}
# Directives this linter recognises as real; anything one edit away from one of these is reported as a probable typo.
KNOWN = """
addcharset adddefaultcharset addencoding addhandler addicon addlanguage addoutputfilter addtype allow allowoverride authtype authname
authuserfile authgroupfile browsermatch cachedefaultexpire cacheenable cachedisable customlog defaultlanguage defaulttype deflatecompressionlevel
deny directoryindex directoryslash documentroot errordocument errorlog expiresactive expiresbytype expiresdefault extendedstatus fileetag forcetype
header headername indexoptions indexignore keepalive keepalivetimeout limitrequestbody loglevel options order php_flag php_value php_admin_flag
php_admin_value readmename redirect redirectmatch redirectpermanent redirecttemp removecharset removehandler removetype requestheader require
rewritebase rewritecond rewriteengine rewritemap rewriteoptions rewriterule satisfy sethandler setenv setenvif setenvifnocase setoutputfilter
serveralias servername serversignature servertokens timeout unsetenv xbithack browsermatchnocase alias aliasmatch scriptalias
""".split()
NEAR = difflib.SequenceMatcher


class Finding:
    def __init__(self, level, line, rule, message):
        self.level, self.line, self.rule, self.message = level, line, rule, message

    def __repr__(self):
        return "%s line %d [%s]: %s" % (self.level, self.line, self.rule, self.message)


def logical_lines(text):
    """(line number of the first physical line, joined text) with trailing-backslash continuations folded in."""
    out, buf, start = [], "", 0
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if not buf:
            start = n
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        out.append((start, buf + line))
        buf = ""
    if buf:
        out.append((start, buf))
    return out


def lint(text):
    f = []
    if "\r\n" in text:
        f.append(Finding("warn", 1, "crlf", "Windows (CRLF) line endings; a stray carriage return can end up inside a directive's last argument"))
    stack = []                                   # (container name lower-cased, argument, line)
    conds_pending = []                           # lines of RewriteCond not yet followed by a RewriteRule
    rewrite_engine_seen = False
    seen_lines, header_values = {}, {}
    for n, raw in logical_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^<(/?)(\w+)\s*(.*?)>$", line)
        if m:
            closing, name, arg = m.group(1), m.group(2).lower(), m.group(3)
            if closing:
                if not stack:
                    f.append(Finding("error", n, "container", "</%s> closes nothing" % m.group(2)))
                elif stack[-1][0] != name:
                    f.append(Finding("error", n, "container", "</%s> closes <%s> from line %d" % (m.group(2), stack[-1][3], stack[-1][2])))
                    stack.pop()
                else:
                    stack.pop()
            elif name in CONTAINERS:
                stack.append((name, arg, n, m.group(2)))
            continue
        parts = line.split(None, 1)
        d, args = parts[0].lower(), parts[1] if len(parts) > 1 else ""
        in_mod = lambda pat: any(s[0] == "ifmodule" and re.search(pat, s[1]) for s in stack)
        where = (tuple((c[0], c[1]) for c in stack), line)          # the same line in another container is not a duplicate
        if where in seen_lines and d not in ("rewritecond", "else", "require"):
            f.append(Finding("warn", n, "duplicate", "the same directive already appears on line %d" % seen_lines[where]))
        seen_lines.setdefault(where, n)
        if d not in ("rewritecond", "rewriterule") and conds_pending:
            f.append(Finding("error", conds_pending[0], "rewritecond", "RewriteCond is not followed by a RewriteRule"))
            conds_pending = []
        if d == "rewriteengine":
            rewrite_engine_seen = args.strip().lower() == "on" or rewrite_engine_seen
        elif d == "rewritecond":
            conds_pending.append(n)
        elif d == "rewriterule":
            conds_pending = []
            if not rewrite_engine_seen:
                f.append(Finding("warn", n, "rewriteengine", "RewriteRule with no earlier 'RewriteEngine On' in this file (fine only if inherited)"))
        elif d in ("order", "allow", "deny"):
            f.append(Finding("warn", n, "access-2.2", "%s is Apache 2.2 access control (needs mod_access_compat in 2.4); use 'Require' instead" % parts[0]))
        elif d == "header":
            hm = re.match(r"^(always\s+)?(set|append|merge|add|unset|edit\*?|echo)\s+(\S+)\s*(.*)$", args, re.I)
            if hm:
                always, action, name, value = bool(hm.group(1)), hm.group(2).lower(), hm.group(3).strip('"'), hm.group(4)
                lname = name.lower()
                if lname in SECURITY_HEADERS and action in ("set", "append", "merge", "add") and not always:
                    f.append(Finding("warn", n, "header-always", "%s is set without 'always', so it is missing from error responses (4xx/5xx)" % name))
                if action == "set":
                    if lname in header_values and header_values[lname][1] != value:
                        f.append(Finding("warn", n, "header-twice", "%s is set again with a different value (first on line %d); the later one wins" % (name, header_values[lname][0])))
                    header_values[lname] = (n, value)
                if lname == "strict-transport-security" and action != "unset":
                    ma = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
                    if not ma:
                        f.append(Finding("error", n, "hsts", "Strict-Transport-Security needs max-age=<seconds>"))
                    else:
                        age = int(ma.group(1))
                        if "preload" in value.lower() and age < 31536000:
                            f.append(Finding("warn", n, "hsts", "'preload' needs max-age of at least 31536000 (one year); this is %d" % age))
                        elif age < 15552000 and "preload" not in value.lower():
                            f.append(Finding("info", n, "hsts", "max-age=%d is under 180 days; fine while testing, but browsers forget the policy quickly" % age))
                        if "preload" in value.lower() and "includesubdomains" not in value.lower():
                            f.append(Finding("warn", n, "hsts", "'preload' also needs 'includeSubDomains'"))
                if lname == "content-security-policy" and action != "unset":
                    if re.search(r"default-src\s+[^;]*\*(?!\.)", value) and "'self'" not in value:
                        f.append(Finding("warn", n, "csp", "default-src allows any origin ('*')"))
                    if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                        f.append(Finding("info", n, "csp", "the policy allows 'unsafe-inline' or 'unsafe-eval', which weakens its protection against script injection"))
        elif d in ("php_value", "php_flag", "php_admin_value", "php_admin_flag"):
            if not in_mod(r"php"):
                f.append(Finding("warn", n, "php-directive", "%s outside <IfModule mod_php*.c>: Apache returns a 500 error when PHP runs as CGI or FPM" % parts[0]))
        elif d == "expiresactive" and not in_mod(r"mod_expires"):
            f.append(Finding("info", n, "ifmodule", "ExpiresActive is not inside <IfModule mod_expires.c>; a server without the module returns a 500 error"))
        elif d == "options":
            for tok in args.split():
                if tok.lower() in ("indexes", "+indexes"):
                    f.append(Finding("warn", n, "indexes", "Options %s turns on directory listings" % tok))
        elif d == "allowoverride":
            f.append(Finding("error", n, "context", "AllowOverride is not allowed in .htaccess (only in the server or virtual-host configuration)"))
        elif d == "servertokens":
            f.append(Finding("info", n, "context", "ServerTokens cannot be set in .htaccess (server configuration only)"))
        elif d not in KNOWN and not d.startswith("<"):
            close = difflib.get_close_matches(d, KNOWN, n=1, cutoff=0.85)
            if close:
                f.append(Finding("warn", n, "typo", "unknown directive %r; did you mean %r?" % (parts[0], close[0])))
    for name, arg, line, orig in stack:
        f.append(Finding("error", line, "container", "<%s> is never closed" % orig))
    if conds_pending:
        f.append(Finding("error", conds_pending[0], "rewritecond", "RewriteCond is not followed by a RewriteRule"))
    return sorted(f, key=lambda x: (x.line, x.rule))
