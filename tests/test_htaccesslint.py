import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

import htaccesslint as hl
from htaccesslint.__main__ import main

MESSY = os.path.join(HERE, "data", "messy.htaccess")


def found(text):
    return [(x.level, x.line, x.rule) for x in hl.lint(text)]


def rules(text):
    return [x.rule for x in hl.lint(text)]


class Containers(unittest.TestCase):
    def test_balanced(self):
        self.assertEqual(found("<IfModule mod_headers.c>\nHeader always set X-A b\n</IfModule>\n"), [])

    def test_unclosed_and_stray(self):
        self.assertEqual(found("<Files x>\nRequire all denied\n"), [("error", 1, "container")])
        self.assertEqual(found("</IfModule>\n"), [("error", 1, "container")])

    def test_mismatch_names_the_opener(self):
        out = hl.lint("<IfModule a.c>\n</FilesMatch>\n")
        self.assertEqual((out[0].line, out[0].message), (2, "</FilesMatch> closes <IfModule> from line 1"))

    def test_nesting(self):
        self.assertEqual(found("<IfModule a.c>\n<Files x>\nRequire all denied\n</Files>\n</IfModule>\n"), [])


class Rewrite(unittest.TestCase):
    def test_dangling_condition(self):
        self.assertEqual(found("RewriteEngine On\nRewriteCond %{HTTPS} off\nHeader always set X-A b\n"), [("error", 2, "rewritecond")])
        self.assertEqual(found("RewriteEngine On\nRewriteCond %{HTTPS} off\n"), [("error", 2, "rewritecond")])

    def test_conditions_before_a_rule_are_fine(self):
        self.assertEqual(found("RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteCond %{HTTP_HOST} x\nRewriteRule ^ https://x/ [R=301,L]\n"), [])

    def test_engine_missing(self):
        self.assertEqual(found("RewriteRule ^a$ /b [L]\n"), [("warn", 1, "rewriteengine")])
        self.assertEqual(found("RewriteEngine on\nRewriteRule ^a$ /b [L]\n"), [])


class Headers(unittest.TestCase):
    def test_missing_always(self):
        self.assertEqual(found('Header set X-Frame-Options "DENY"\n'), [("warn", 1, "header-always")])
        self.assertEqual(found('Header always set X-Frame-Options "DENY"\n'), [])
        self.assertEqual(found('Header set X-Custom "1"\n'), [])
        self.assertEqual(found("Header unset Server\n"), [])

    def test_hsts(self):
        self.assertIn("hsts", rules('Header always set Strict-Transport-Security "includeSubDomains"\n'))
        self.assertEqual(found('Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"\n'), [])
        self.assertEqual(found('Header always set Strict-Transport-Security "max-age=86400"\n'), [("info", 1, "hsts")])
        self.assertEqual(found('Header always set Strict-Transport-Security "max-age=300; includeSubDomains; preload"\n'), [("warn", 1, "hsts")])
        self.assertEqual(found('Header always set Strict-Transport-Security "max-age=63072000; preload"\n'), [("warn", 1, "hsts")])

    def test_csp(self):
        self.assertIn("csp", rules("Header always set Content-Security-Policy \"default-src * 'unsafe-inline'\"\n"))
        self.assertEqual(found("Header always set Content-Security-Policy \"default-src 'self'\"\n"), [])
        self.assertEqual(found("Header always set Content-Security-Policy \"default-src 'self'; script-src 'unsafe-inline'\"\n"), [("info", 1, "csp")])

    def test_same_header_set_twice(self):
        out = hl.lint('Header always set X-Frame-Options "DENY"\nHeader always set X-Frame-Options "SAMEORIGIN"\n')
        self.assertEqual([(x.line, x.rule) for x in out], [(2, "header-twice")])
        self.assertEqual(found('Header always set X-Frame-Options "DENY"\nHeader always set X-Frame-Options "DENY"\n'), [("warn", 2, "duplicate")])


class Other(unittest.TestCase):
    def test_access_control_2_2(self):
        self.assertEqual(rules("Order allow,deny\nAllow from all\nDeny from 1.2.3.4\n"), ["access-2.2"] * 3)
        self.assertEqual(found("Require all granted\n"), [])

    def test_php_directives(self):
        self.assertEqual(found("php_value memory_limit 256M\n"), [("warn", 1, "php-directive")])
        self.assertEqual(found("<IfModule mod_php.c>\nphp_value memory_limit 256M\n</IfModule>\n"), [])
        self.assertEqual(found("<IfModule mod_php8.c>\nphp_flag display_errors off\n</IfModule>\n"), [])

    def test_expires_guard(self):
        self.assertEqual(found("ExpiresActive On\n"), [("info", 1, "ifmodule")])
        self.assertEqual(found("<IfModule mod_expires.c>\nExpiresActive On\n</IfModule>\n"), [])

    def test_indexes_and_allowoverride(self):
        self.assertEqual(found("Options +Indexes\n"), [("warn", 1, "indexes")])
        self.assertEqual(found("Options -Indexes +FollowSymLinks\n"), [])
        self.assertEqual(found("AllowOverride All\n"), [("error", 1, "context")])

    def test_typos_only_when_close(self):
        self.assertEqual(found("RewriteEngin On\n"), [("warn", 1, "typo")])
        self.assertEqual(found("SomeModuleDirective on\n"), [])

    def test_duplicate_line_only_in_the_same_container(self):
        two = "<Files a>\nRequire all denied\n</Files>\n<Files b>\nRequire all denied\n</Files>\n"
        self.assertEqual(found(two), [])
        self.assertEqual(found("Options -Indexes\nOptions -Indexes\n"), [("warn", 2, "duplicate")])

    def test_continuation_lines(self):
        text = 'Header always set Content-Security-Policy "default-src \'self\'; \\\n   img-src *"\nOptions +Indexes\n'
        self.assertEqual(found(text), [("warn", 3, "indexes")])

    def test_crlf_and_comments(self):
        self.assertEqual(found("# note\r\nOptions -Indexes\r\n"), [("warn", 1, "crlf")])
        self.assertEqual(found("# Order allow,deny\n\n"), [])


class Cli(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_messy_file(self):
        code, out, _ = self.run_cli(MESSY)
        self.assertEqual(code, 1)
        self.assertIn("15 findings", out)
        self.assertIn("error line 3 [rewritecond] RewriteCond is not followed by a RewriteRule", out)
        self.assertIn("4 errors, 9 warnings", out)

    def test_quiet_json_strict(self):
        code, out, _ = self.run_cli(MESSY, "--quiet")
        self.assertIn("13 findings", out)
        data = json.loads(self.run_cli(MESSY, "--json")[1])
        self.assertEqual(data[0]["findings"][0], {"level": "warn", "line": 1, "rule": "typo", "message": "unknown directive 'RewriteEngin'; did you mean 'rewriteengine'?"})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".htaccess")
            with open(p, "w") as fh:
                fh.write("Options +Indexes\n")
            self.assertEqual(self.run_cli(p)[0], 0)
            self.assertEqual(self.run_cli(p, "--strict")[0], 1)

    def test_missing_file(self):
        code, _, err = self.run_cli("/no/such/.htaccess")
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)


if __name__ == "__main__":
    unittest.main()
