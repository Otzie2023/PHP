#!/usr/bin/env python3
"""classify-identifiers.py -- Stage 0 analysis for the
"Unicode-aware identifiers in PHP" RFC.

Reads the JSON Lines produced by scan-identifiers.php and classifies every
non-ASCII identifier against the criteria a strict mode would enforce:

  * valid UTF-8
  * UAX #31 conformance (XID_Start / XID_Continue)
  * Normalization Form C
  * single script (UTS #39 mixed-script signal)
  * confusability with a pure ASCII identifier (UTS #39 signal)
  * divergence between PHP's ASCII-only case folding and Unicode case folding,
    which only matters for the case-insensitive symbol kinds

Notes on data sources: CPython's str.isidentifier() is implemented on top of
the XID_Start / XID_Continue properties, so it is used as the UAX #31 oracle.
Script detection is approximated from the Unicode character name prefix,
because the Script property is not exposed by the standard library; this is
adequate for the Latin / Greek / Cyrillic confusion cases that matter here and
is reported as an approximation. The confusable set is a hand-picked subset of
UTS #39 confusables.txt restricted to Cyrillic and Greek homoglyphs of ASCII
letters, which covers the realistic supply-chain attack.

Usage:
    python3 classify-identifiers.py scan.jsonl [--csv out.csv] [--json out.json]
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
import unicodedata

# Symbol kinds that PHP looks up case-insensitively.
CASE_INSENSITIVE_ROLES = {
    "class_decl",
    "interface_decl",
    "trait_decl",
    "enum_decl",
    "function_decl",
    "namespace_decl",
    "class_use",
    "attribute",
}

# Cyrillic and Greek homoglyphs of ASCII letters (subset of UTS #39).
CONFUSABLE_TO_ASCII = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u04bb": "h",
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041d": "H",
    "\u041a": "K", "\u041c": "M", "\u041e": "O", "\u0420": "P", "\u0422": "T",
    "\u0425": "X", "\u0406": "I", "\u0408": "J", "\u0405": "S",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03bd": "v", "\u03c5": "u",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
}

SCRIPT_PREFIXES = (
    "LATIN", "GREEK", "COPTIC", "CYRILLIC", "ARMENIAN", "HEBREW", "ARABIC",
    "SYRIAC", "THAANA", "DEVANAGARI", "BENGALI", "GURMUKHI", "GUJARATI",
    "ORIYA", "TAMIL", "TELUGU", "KANNADA", "MALAYALAM", "SINHALA", "THAI",
    "LAO", "TIBETAN", "MYANMAR", "GEORGIAN", "HANGUL", "ETHIOPIC", "CHEROKEE",
    "KHMER", "MONGOLIAN", "HIRAGANA", "KATAKANA", "BOPOMOFO", "CJK", "YI",
    "VAI", "BAMUM", "JAVANESE", "BALINESE", "SUNDANESE", "TIFINAGH", "NKO",
)

# Default_Ignorable_Code_Point, as ranges. unicodedata does not expose the
# property, and it is stable enough to carry inline.
#
# This matters more than it looks. UAX #31 moved the joining controls U+200C
# and U+200D, and the variation selectors, INTO XID_Continue; older revisions
# excluded them. So `str.isidentifier()` answers differently depending on which
# Unicode version the running Python was built against -- CPython 3.12 says
# ZWJ is not a continue character, CPython 3.14 says it is. A survey whose
# result flips with the interpreter version is worthless, so the profile check
# below does not depend on it.
#
# UAX #31 recommends exactly this profile: remove the Default_Ignorable_Code_
# Points from general-purpose identifiers, because they request a rendering
# difference without guaranteeing one. That is the rule a language RFC should
# specify, and it is version-independent.
DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C),
    (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F),
    (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

INVISIBLE_CATEGORIES = {"Cf", "Cc", "Cs", "Co", "Cn", "Zs", "Zl", "Zp"}


def is_default_ignorable(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in DEFAULT_IGNORABLE_RANGES)


def is_invisible(ch: str) -> bool:
    """Default_Ignorable, or a format/control/separator character.

    Everything here is either literally invisible or renders as whitespace,
    which is the property that makes it dangerous inside an identifier.
    """
    return is_default_ignorable(ch) or unicodedata.category(ch) in INVISIBLE_CATEGORIES


def invisible_offenders(s: str) -> list[str]:
    out = []
    for ch in s:
        if ch.isascii():
            continue
        if is_invisible(ch):
            try:
                out.append(f"U+{ord(ch):04X} {unicodedata.name(ch)}")
            except ValueError:
                out.append(f"U+{ord(ch):04X} <unnamed, {unicodedata.category(ch)}>")
    return out


def script_of(ch: str) -> str:
    """Approximate the Script property from the character name.

    ASCII letters are Script=Latin, not Common. Treating them as Common makes
    the Latin/Cyrillic and Latin/Greek pairs -- the whole point of the check --
    unreachable whenever the Latin half is plain ASCII, which is the normal
    case for a homoglyph attack on an existing identifier.
    """
    if ch.isascii():
        if ch.isalpha():
            return "Latin"
        return "Common"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "Unknown"
    for prefix in SCRIPT_PREFIXES:
        if name.startswith(prefix + " ") or name == prefix:
            return prefix.title()
    cat = unicodedata.category(ch)
    if cat in ("Mn", "Mc", "Me", "Nd", "Pc", "Cf", "Zs"):
        return "Common"
    return "Other"


VENDOR_MARKERS = ("/vendor/", "/node_modules/", "/third_party/", "/thirdparty/",
                  "/Vendor/", "/extend/", "/lib/alipay/", "/vendors/")


def is_vendored(path: str) -> bool:
    p = "/" + path
    return any(m in p for m in VENDOR_MARKERS)


def ascii_lower(s: str) -> str:
    """Reproduce zend_str_tolower(): only U+0041..U+005A are mapped."""
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def is_uax31(s: str) -> bool:
    if not s:
        return False
    first, rest = s[0], s[1:]
    if not (first == "_" or first.isidentifier()):
        return False
    return all(("a" + c).isidentifier() for c in rest)


def uax31_offenders(s: str) -> list[str]:
    bad = []
    for i, c in enumerate(s):
        ok = (c == "_" or c.isidentifier()) if i == 0 else ("a" + c).isidentifier()
        if not ok and not c.isascii():
            try:
                bad.append(f"U+{ord(c):04X} {unicodedata.name(c)}")
            except ValueError:
                bad.append(f"U+{ord(c):04X} <unnamed>")
    return bad


def classify(name_hex: str) -> dict:
    raw = bytes.fromhex(name_hex)
    result = {
        "name": None,
        "valid_utf8": False,
        "uax31": False,
        "uax31_profile": False,
        "invisible": "",
        "nfc": False,
        "scripts": "",
        "mixed_script": False,
        "confusable_ascii": None,
        "multi_script": False,
        "casefold_divergence": False,
        "offenders": "",
        "codepoints": 0,
    }

    try:
        name = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return result

    result["name"] = name
    result["valid_utf8"] = True
    result["codepoints"] = len(name)
    result["nfc"] = unicodedata.normalize("NFC", name) == name
    result["uax31"] = is_uax31(name)
    result["offenders"] = "; ".join(uax31_offenders(name))
    invis = invisible_offenders(name)
    result["invisible"] = "; ".join(invis)
    # The rule an RFC should specify: UAX #31 plus the recommended profile that
    # removes Default_Ignorable_Code_Points. Version-independent.
    result["uax31_profile"] = result["uax31"] and not invis

    scripts = {script_of(c) for c in name}
    real = {s for s in scripts if not s.startswith("Common")}
    result["scripts"] = ",".join(sorted(scripts))
    # UTS #39 treats any multi-script identifier as suspicious, but Han +
    # Hiragana + Katakana is normal Japanese and Han + Latin is normal in
    # Chinese code. The security-relevant case is confusable script pairs.
    confusable_pairs = ({"Latin", "Cyrillic"}, {"Latin", "Greek"}, {"Cyrillic", "Greek"})
    result["mixed_script"] = any(pair <= real for pair in confusable_pairs)
    result["multi_script"] = len(real) > 1

    if any(c in CONFUSABLE_TO_ASCII for c in name):
        skeleton = "".join(CONFUSABLE_TO_ASCII.get(c, c) for c in name)
        if skeleton.isascii() and skeleton != name:
            result["confusable_ascii"] = skeleton

    # PHP folds ASCII only; Unicode casefold() is what a consistent language
    # would use. Divergence means the identifier's case-insensitivity today
    # differs from what users expect.
    result["casefold_divergence"] = ascii_lower(name) != name.casefold()

    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl")
    ap.add_argument("--csv", dest="csv_path")
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()

    files = 0
    file_bytes = 0
    bad_utf8_files = 0
    bom_files = 0
    bidi_files = 0
    declare_encoding_files = 0
    lex_errors = 0
    skipped_binary = 0
    skipped_no_tag = 0
    packages = set()
    pkg_with_ident = set()
    file_with_ident = set()

    rows = []
    occurrences = 0

    with open(args.jsonl, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec["type"] == "skip":
                packages.add(rec["pkg"])
                if rec["reason"] == "binary":
                    skipped_binary += 1
                else:
                    skipped_no_tag += 1
                continue
            if rec["type"] == "file":
                files += 1
                file_bytes += rec["bytes"]
                packages.add(rec["pkg"])
                bad_utf8_files += not rec["valid_utf8"]
                bom_files += rec["bom"]
                bidi_files += rec["bidi"]
                declare_encoding_files += rec["declare_encoding"]
                lex_errors += rec["lex_error"]
                continue

            occurrences += rec["n"]
            pkg_with_ident.add(rec["pkg"])
            file_with_ident.add((rec["pkg"], rec["file"]))
            info = classify(rec["name_hex"])
            rows.append({
                "pkg": rec["pkg"],
                "file": rec["file"],
                "line": rec["line"],
                "role": rec["role"],
                "vendored": is_vendored(rec["file"]),
                "kind": rec["kind"],
                "occurrences": rec["n"],
                "name": info["name"] if info["name"] is not None else "<invalid utf-8>",
                "name_hex": rec["name_hex"],
                "codepoints": info["codepoints"],
                "valid_utf8": info["valid_utf8"],
                "uax31": info["uax31"],
                "uax31_profile": info["uax31_profile"],
                "invisible": info["invisible"],
                "nfc": info["nfc"],
                "scripts": info["scripts"],
                "mixed_script": info["mixed_script"],
                "multi_script": info["multi_script"],
                "confusable_ascii": info["confusable_ascii"] or "",
                "casefold_divergence": info["casefold_divergence"],
                "case_insensitive_role": rec["role"] in CASE_INSENSITIVE_ROLES,
                "uax31_offenders": info["offenders"],
            })

    distinct = {r["name_hex"] for r in rows}

    def count(pred) -> int:
        return sum(1 for r in rows if pred(r))

    summary = {
        "environment": {
            "python": ".".join(str(x) for x in sys.version_info[:3]),
            "unicode": unicodedata.unidata_version,
            "note": ("XID_Start/XID_Continue come from this Unicode version; "
                     "the uax31_profile column does not depend on it"),
        },
        "corpus": {
            "packages": len(packages),
            "php_files": files,
            "megabytes": round(file_bytes / 1048576, 1),
            "lex_errors": lex_errors,
            "skipped_binary": skipped_binary,
            "skipped_no_open_tag": skipped_no_tag,
        },
        "file_hazards": {
            "invalid_utf8_files": bad_utf8_files,
            "utf8_bom_files": bom_files,
            "bidi_control_files": bidi_files,
            "declare_encoding_files": declare_encoding_files,
        },
        "identifiers": {
            "records": len(rows),
            "occurrences": occurrences,
            "distinct_names": len(distinct),
            "packages_affected": len(pkg_with_ident),
            "files_affected": len(file_with_ident),
        },
        "would_be_rejected_by_strict_mode": {
            "invalid_utf8": count(lambda r: not r["valid_utf8"]),
            "not_uax31": count(lambda r: r["valid_utf8"] and not r["uax31"]),
            "not_uax31_profile": count(lambda r: r["valid_utf8"] and not r["uax31_profile"]),
            "not_nfc": count(lambda r: r["valid_utf8"] and not r["nfc"]),
            "any": count(lambda r: not r["valid_utf8"] or not r["uax31_profile"] or not r["nfc"]),
        },
        "invisible_characters": {
            "identifiers_containing_one": count(lambda r: r["invisible"]),
            "accepted_by_raw_xid_this_unicode_version": count(
                lambda r: r["invisible"] and r["uax31"]
            ),
        },
        "security_signals": {
            "confusable_script_mix": count(lambda r: r["mixed_script"]),
            "multi_script": count(lambda r: r["multi_script"]),
            "confusable_with_ascii": count(lambda r: r["confusable_ascii"]),
        },
        "case_folding": {
            "casefold_divergence": count(lambda r: r["casefold_divergence"]),
            "divergence_in_case_insensitive_role": count(
                lambda r: r["casefold_divergence"] and r["case_insensitive_role"]
            ),
        },
        "first_party_vs_vendored": {
            "first_party_records": count(lambda r: not r["vendored"]),
            "vendored_records": count(lambda r: r["vendored"]),
        },
        "by_role": dict(collections.Counter(r["role"] for r in rows).most_common()),
        "top_scripts": dict(collections.Counter(r["scripts"] for r in rows).most_common(10)),
    }

    if args.csv_path and rows:
        with open(args.csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump({"summary": summary, "rows": rows}, fh,
                      ensure_ascii=False, indent=2)

    json.dump(summary, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
