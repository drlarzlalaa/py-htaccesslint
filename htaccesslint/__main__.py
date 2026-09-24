import argparse
import json
import sys

from . import lint


def main(argv=None):
    ap = argparse.ArgumentParser(prog="htaccesslint", description="Lint Apache .htaccess files, offline.")
    ap.add_argument("files", nargs="+", help=".htaccess files (- for standard input)")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--strict", action="store_true", help="exit 1 on warnings too")
    ap.add_argument("--quiet", action="store_true", help="hide info-level findings")
    args = ap.parse_args(argv)
    errors = warnings = 0
    result = []
    for path in args.files:
        try:
            if path == "-":
                text = sys.stdin.read()
            else:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
        except OSError as exc:
            print("htaccesslint: cannot read %s: %s" % (path, exc.strerror), file=sys.stderr)
            return 2
        found = [x for x in lint(text) if not (args.quiet and x.level == "info")]
        errors += sum(x.level == "error" for x in found)
        warnings += sum(x.level == "warn" for x in found)
        if args.json:
            result.append({"file": path, "findings": [{"level": x.level, "line": x.line, "rule": x.rule, "message": x.message} for x in found]})
        else:
            print("%s: %s" % (path, "no findings" if not found else "%d findings" % len(found)))
            for x in found:
                print("  %-5s line %d [%s] %s" % (x.level, x.line, x.rule, x.message))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("%d errors, %d warnings" % (errors, warnings))
    return 1 if errors or (args.strict and warnings) else 0


if __name__ == "__main__":
    sys.exit(main())
