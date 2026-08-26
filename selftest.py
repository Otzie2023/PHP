#!/usr/bin/env python3
"""selftest.py -- regression test for the Stage 0 pipeline.

Builds a small PHP file containing one instance of every hazard class the
scanner is supposed to find, runs scan-identifiers.php and
classify-identifiers.py over it, and asserts the expected classification.

This exists because a near-zero result on a real corpus is indistinguishable
from a broken scanner. Run it before trusting any corpus figure.

    python3 selftest.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def check_environment() -> tuple[str, int] | tuple[None, int]:
    """Verify the pieces the pipeline needs are present, with actionable
    messages. Returns (php binary, 0) or (None, exit code)."""
    scanner = os.path.join(HERE, "scan-identifiers.php")
    if not os.path.isfile(scanner):
        print(f"scan-identifiers.php is missing from {HERE}", file=sys.stderr)
        print("It is the scanner; the pipeline cannot run without it.",
              file=sys.stderr)
        return None, 1

    php = shutil.which(os.environ.get("PHP", "php"))
    if php is None:
        print("no 'php' binary on PATH.", file=sys.stderr)
        print("  Debian/Ubuntu:  sudo apt install php-cli", file=sys.stderr)
        print("  Fedora:         sudo dnf install php-cli", file=sys.stderr)
        print("  Arch:           sudo pacman -S php", file=sys.stderr)
        print("Set PHP=/path/to/php to use a specific build.", file=sys.stderr)
        return None, 1

    r = subprocess.run([php, "-r", "echo (int) function_exists('token_get_all');"],
                       capture_output=True, text=True)
    if r.stdout.strip() != "1":
        print(f"{php} has no ext/tokenizer, which the scanner requires.",
              file=sys.stderr)
        print("  Debian/Ubuntu:  it is built into php-cli; check your php.ini",
              file=sys.stderr)
        return None, 1

    ver = subprocess.run([php, "-r", "echo PHP_VERSION;"],
                         capture_output=True, text=True).stdout.strip()
    mb = subprocess.run([php, "-r", "echo function_exists('mb_check_encoding') ? 'yes' : 'no';"],
                        capture_output=True, text=True).stdout.strip()
    print(f"php {ver} at {php} (ext/mbstring: {mb})")
    return php, 0

SOURCE = (
    b"<?php\n"
    b"class Stra\xc3\x9fe {}\n"                       # NFC German, conformant
    b"function gr\xc3\xbc\xc3\x9fen() {}\n"           # conformant
    b"const ZAHLUNGSGR\xc3\x96\xe1\xba\x9eE = 2;\n"   # capital sharp s U+1E9E
    b"$chrtext\xc2\xa0 = 1;\n"                        # U+00A0 glued on
    b"$zwj\xe2\x80\x8dtest = 2;\n"                    # U+200D ZWJ
    b"$mixed\xd0\xb0dmin = 3;\n"                      # Cyrillic a among Latin
    b"class \xa9Latin1 {}\n"                          # raw Latin-1 byte
    b"$nfd_a\xcc\x88 = 4;\n"                          # a + U+0308, not NFC
)

# name_hex -> (valid_utf8, uax31_profile, nfc, confusable_ascii, mixed_script)
#
# The assertion is on uax31_profile, not on raw XID. Raw XID_Continue answers
# differently depending on the Unicode version the running Python was built
# against: UAX #31 moved the joining controls into XID_Continue, so CPython
# 3.12 (Unicode 15.0) rejects U+200D while CPython 3.14 (Unicode 16.0) accepts
# it. The profile -- UAX #31 minus Default_Ignorable_Code_Points, which UAX #31
# itself recommends for general-purpose identifiers -- is stable across
# versions, and is the rule an RFC should actually specify.
EXPECT = {
    "53747261c39f65":                 (True,  True,  True,  "", False),   # Straße
    "6772c3bcc39f656e":               (True,  True,  True,  "", False),   # grüßen
    "5a41484c554e47534752c396e1ba9e45": (True, True, True,  "", False),   # ZAHLUNGSGRÖẞE
    "63687274657874c2a0":             (True,  False, True,  "", False),   # chrtext + NBSP
    "7a776ae2808d74657374":           (True,  False, True,  "", False),   # zwj + ZWJ
    "6d69786564d0b0646d696e":         (True,  True,  True,  "mixedadmin", True),
    "a94c6174696e31":                 (False, False, False, "", False),   # \xA9Latin1
    "6e66645f61cc88":                 (True,  True,  False, "", False),   # a + combining diaeresis
}


def main() -> int:
    php, rc = check_environment()
    if php is None:
        return rc

    tmp = tempfile.mkdtemp(prefix="php-ident-selftest-")
    try:
        pkg = os.path.join(tmp, "corpus", "testpkg")
        os.makedirs(pkg)
        with open(os.path.join(pkg, "probe.php"), "wb") as fh:
            fh.write(SOURCE)

        jsonl = os.path.join(tmp, "scan.jsonl")
        out = os.path.join(tmp, "findings.json")

        r = subprocess.run(
            [php, os.path.join(HERE, "scan-identifiers.php"),
             "--depth=1", f"--out={jsonl}", os.path.join(tmp, "corpus")],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("scan-identifiers.php failed:", r.stderr, file=sys.stderr)
            return 1

        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "classify-identifiers.py"),
             jsonl, "--json", out],
            capture_output=True, text=True)
        if r.returncode != 0:
            print("classify-identifiers.py failed:", r.stderr, file=sys.stderr)
            return 1

        data = json.load(open(out))
        env = data["summary"]["environment"]
        print(f"unicode {env['unicode']} via python {env['python']}")
        rows = {r["name_hex"]: r for r in data["rows"]}

        failures = 0
        for hexname, (utf8, uax31, nfc, conf, mixed) in EXPECT.items():
            row = rows.get(hexname)
            if row is None:
                print(f"  MISSING  {hexname} was not detected at all")
                failures += 1
                continue
            got = (row["valid_utf8"], row["uax31_profile"], row["nfc"],
                   row["confusable_ascii"], row["mixed_script"])
            want = (utf8, uax31, nfc, conf, mixed)
            label = row["name"] if row["valid_utf8"] else f"<{hexname}>"
            if got == want:
                extra = ""
                if row["invisible"]:
                    extra = (f"   [invisible: {row['invisible']};"
                             f" raw XID accepts it: {row['uax31']}]")
                print(f"  PASS     {label}{extra}")
            else:
                print(f"  FAIL     {label}\n"
                      f"             want utf8/profile/nfc/conf/mixed = {want}\n"
                      f"             got                            = {got}")
                failures += 1

        extra = set(rows) - set(EXPECT)
        for hexname in extra:
            print(f"  EXTRA    unexpected detection: {hexname}")
            failures += 1

        print()
        if failures:
            print(f"{failures} failure(s)")
            return 1
        print(f"all {len(EXPECT)} checks passed")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
