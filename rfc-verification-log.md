# Verification log for the Strict Identifiers RFC

Every factual claim in `rfc-strict-identifiers.txt`, with how it was checked.
Checked 2026-08-25. Anything marked *not verified* is not in the RFC.

## php-src, fetched from `master` at check time

| Claim | Source | Result |
| --- | --- | --- |
| `LABEL [a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*` | `Zend/zend_language_scanner.l:1409` | exact match |
| `IS_LABEL_START` / `IS_LABEL_SUCCESSOR` also use `>= 0x80` | same file, lines 119-120 | confirmed |
| Seven rules produce identifier tokens via `RETURN_TOKEN_WITH_STR` | lines 1639, 2447, 2469, 2473, 2477, 2485, 2708 | confirmed |
| They funnel into `emit_token_with_str` -> `zend_copy_value()` | line 3220 | confirmed |
| `zend_lex_tstring()` is **not** that path; it scans ASCII only | line 304-306 | confirmed — this corrected an earlier draft that named it as the choke point |
| `zend_declarables` has exactly one member, `ticks` | `Zend/zend_compile.h:105-107` | confirmed |
| `FC(member)` is `CG(file_context).member` | `Zend/zend_compile.c:63` | confirmed |
| `strict_types` uses `zend_is_first_statement()` and rejects block mode | `Zend/zend_compile.c` ~7548-7560 | confirmed |
| Case-insensitive comparison uses an ASCII-only map | `Zend/zend_operators.h:468, 1008` (`zend_tolower_ascii`) | confirmed |
| php-src master version | `main/php_version.h` | 8.6.0-dev |

## PHP manual

The quoted note ("PHP doesn't support Unicode variable names, however, some
character encodings ...") is from `language/variables.xml` in `php/doc-en`,
immediately after the `^[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*$` regex.
Quoted verbatim.

## Empirical, PHP 8.3.6

```
[1] class Straße {}
    straße   -> resolves        STRAßE   -> resolves
    Straẞe   -> class not found STRASSE  -> class not found
[2] $<U+1F642>, $x<U+00A0>, ${"\xFF\xFE"}  -> all accepted as identifiers
[3] $a<U+0308> and $<U+00E4>               -> distinct variables
[4] define("<U+00C4>", 1)                  -> constant() returns 1
    json_decode('{"<U+1F4A9>":42}')        -> property accessible
```

## Unicode standards, fetched from unicode.org

| Claim | Source |
| --- | --- |
| UAX #31 is at revision 43, Unicode 17.0.0, dated 2025-08-20 | tr31 header |
| UAX31-R1-2 permits declaring a profile with a precise added/removed specification | tr31 §2 |
| §7.3 Default-Ignorable Exclusion Profile exists as a **standard** profile | tr31 §7.3 |
| The "request a difference in display but do not guarantee it" passage | tr31 §2.3, quoted verbatim |
| UAX31-C1 note: implementations using an unversioned UCD reference "should specify a minimum version" | tr31 §1.4 |
| UAX31-C2 requires stating which requirements are observed | tr31 §1.4 |
| UAX31-R6 = require the normalization form (rather than apply it) | tr31 §5 |
| R1b is automatic only *without* a profile | tr31 §2, note to R1b |
| "the Default_Ignorable_Code_Point property values are not guaranteed to be stable" | tr31 §2.3 |
| R1a withdrawn in Unicode 15.1; its characters became part of the default | tr31 Migration, "Version 15.1" |
| §5.2.1: never use General_Category / toLowercase to test identifier casing | tr31 §5.2.1 |
| §4.1.1 bidi example `x + <Hebrew> == 1` | tr31 §4.1.1 |
| §5: NFC for case-sensitive languages, NFKC for case-insensitive | tr31 §5 |
| XID_Start / XID_Continue once-in-always-in | stability_policy.html, Property Value Stability table, Identifiers group |
| "All strings that are valid default Unicode identifiers will continue to be valid ..." | stability_policy.html, Identifier Stability |
| Strong Normalization Stability | stability_policy.html |
| Unicode 17.0 released 2025-09-09 | Unicode release announcement |

## Empirical Unicode checks

Cross-checked two independent implementations — CPython 3.12 (`unicodedata`
15.0.0, `str.isidentifier()`) and the `regex` module (current UCD):

```
U+200C  regex XID_Continue=True  DI=True  Other_ID_Continue=True  | Unicode 15.0: XID_Continue=False
U+200D  regex XID_Continue=True  DI=True  Other_ID_Continue=True  | Unicode 15.0: XID_Continue=False
U+FE0F  regex XID_Continue=True  DI=True                          | Unicode 15.0: XID_Continue=True
U+00A0  regex XID_Continue=False DI=False                         | Unicode 15.0: XID_Continue=False
U+005F  XID_Start=False  XID_Continue=True
U+0024  XID_Start=False  XID_Continue=False
```

This confirms four RFC claims: the joining controls entered via
`Other_ID_Continue`; the version-dependence is real; U+00A0 is caught by plain
XID and not by the profile; `_` must be added to Start while `$` must not.

Python NFKC folding, CPython 3.12: `exec("\u00AA = 1", ns)` binds the name
`a` in `ns`. Confirmed.

Table sizes, computed over all 0x110000 code points with the profile
subtraction applied: Start 693 ranges, Continue 807 ranges, NFC quick-check
251 ranges, total 13.7 KiB as `uint32` pairs; 269 code points removed from
`XID_Continue` by the subtraction.

## Corpus figures

From the Stage 0 survey in this repository. Packagist corpus downloaded
independently on the author's machine and re-scanned here; both runs produced
one identifier record. `selftest.py` passes 8/8, which is what distinguishes
"no findings" from "broken scanner".

- Packagist: 250 packages, 61,891 PHP files, 1 identifier record.
- GitHub: 250 repositories, 106,713 PHP files, 136 records, 33 non-conformant.
- 168,604 files total, **0** non-NFC identifiers.
- Symfony `\xA9` class name verified against upstream `symfony/cache` branch 7.3.
- Alipay U+00A0 identifier: 5 vendored copies across 4 unrelated projects.
- Japanese PHPUnit method declarations: 52 records. CommerceML Russian
  property accesses: 32 records.

## PHP release timeline

PHP 8.5 released 2025-11-20; latest stable 8.5.9 (2026-07-30). PHP 8.6 Beta 1
and soft feature freeze 2026-08-13, GA scheduled 2026-11-19. A new RFC
therefore targets PHP 8.7. RFCs require a 2/3 majority.

## Deliberately excluded

- **CVE-2021-42574 / "Trojan Source".** Widely reported, but not verified
  against a primary source in this pass. The RFC cites UAX #31 §4.1.1's own
  worked example instead, which is both verified and more precise.
- **Rust RFC 2457 and PEP 3131 details** beyond the NFKC behaviour actually
  executed above.
- **`PHP_UNICODE_VERSION` value `"16.0.0"`** is written as an example only;
  the real value depends on which UCD php-src bundles.
- **The claim that a two-stage table would be smaller** is stated as an
  expectation, not a measurement.
