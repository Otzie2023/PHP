# Stage 0: measuring non-ASCII identifiers in real PHP code

Data collection tooling for a prospective RFC on Unicode-aware identifiers in
PHP. It answers the question the internals list will ask first: **how much
real code would a strict identifier mode break, and what would it catch?**

## Background

PHP's scanner has always defined identifiers on bytes, not code points:

    LABEL  [a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*

Every byte from 0x80 to 0xFF is accepted. Because UTF-8 continuation bytes are
all >= 0x80, UTF-8 identifiers work by accident. There is no encoding
validation, no normalisation, and no UAX #31 profile. Case-insensitive symbol
lookup uses `zend_str_tolower()`, which since PHP 8.2 is guaranteed to map only
`A`-`Z`. The observable consequences:

```php
class Straße {}
new straße();   // resolves   (S -> s; the U+00DF bytes are untouched)
new STRAßE();   // resolves
new Straẞe();   // Error      -- U+1E9E is a different byte sequence
new STRASSE();  // Error

$🙂 = 1;                     // accepted: U+1F600 is not excluded
${"a\xCC\x88"} !== $ä;       // NFD and NFC are distinct variables
${"\xFF\xFE"} = 1;           // invalid UTF-8 is a valid variable name
```

The goal of a strict mode is therefore not to permit more, but to **specify
what is permitted**: valid UTF-8, UAX #31 `XID_Start`/`XID_Continue`, and
Normalization Form C.

## Repository layout

    scan-identifiers.php        scanner: tokenizes PHP, emits JSON Lines
    classify-identifiers.py     Unicode classification and aggregation
    selftest.py                 regression test -- run this first
    fetch-corpus.py             corpus builder, GitHub repository lists
    fetch-packagist.py          corpus builder, Packagist popularity ranked
    findings-packagist.csv      per-identifier results, Packagist corpus
    findings.csv                per-identifier results, GitHub corpus
    summary-packagist.json      aggregate figures, Packagist corpus
    summary.json                aggregate figures, GitHub corpus
    scan-packagist.jsonl.gz     raw scanner output, Packagist corpus
    scan-all.jsonl.gz           raw scanner output, GitHub corpus
    meta/repos.json             GitHub corpus stratum A, as resolved
    meta/repos_regional.json    GitHub corpus stratum B, as resolved
    rfc-strict-identifiers.txt  draft RFC, in DokuWiki markup -- NOT submitted
    rfc-verification-log.md     how every claim in the RFC was checked
    LICENSE                     BSD-3-Clause

All five executable files must sit in the same directory.

## Status

The survey is complete and its results stand on their own. The draft RFC in
this repository has **not** been submitted, and is now **superseded**: the
concept discussion on `internals@lists.php.net` established that it bundled
four rules with four different cost profiles behind a single mechanism, and
that the mechanism was chosen before the problem was stated. Read
`rfc-strict-identifiers.txt` as a historical artefact.

What the discussion produced instead is a decomposition along an axis
suggested on the list -- rejecting versus normalising:

| | Nature | Measured cost |
| --- | --- | ---: |
| Not well-formed UTF-8 | only rejectable | 2 identifiers in 520,802 files |
| Invisible characters | only rejectable, but not all accidental | 68 |
| Not NFC | either; a rejection can print the composed spelling | **0** |
| ASCII-only case folding | already normalisation, and incomplete | 19 |

Only the third of these is free. The others each have a different audience and
a different price, and they do not obviously belong in one feature.

## Requirements

* PHP with ext/tokenizer (`sudo apt install php-cli` on Debian/Ubuntu).
  ext/mbstring is used when present but is not required; UTF-8 validation falls
  back to PCRE. ext/intl is not used at all.
* Python 3.9 or newer. No third-party packages.

`python3 selftest.py` checks both and names what is missing.

## The tools

| File | Role |
| --- | --- |
| `fetch-corpus.py` | downloads GitHub tarballs, extracting only PHP sources |
| `fetch-packagist.py` | same, from a Packagist package list (see caveat below) |
| `scan-identifiers.php` | tokenizes with ext/tokenizer, emits JSON Lines |
| `classify-identifiers.py` | Unicode classification and aggregation |
| `selftest.py` | regression test: injects one of every hazard class |

The split is deliberate. Extraction must use PHP's own lexer, because a regex
over the raw file cannot tell an identifier from a word inside a comment or a
string literal, and in non-English code those vastly outnumber identifiers.
Classification must happen outside PHP, because PHP core has no NFC and no
UAX #31 tables -- which is exactly the gap the RFC addresses.

```sh
php scan-identifiers.php --progress --out=scan.jsonl corpus/
python3 classify-identifiers.py scan.jsonl --csv findings.csv --json findings.json
```

All five files must sit in the same directory; `selftest.py` shells out to
`scan-identifiers.php` beside it. Set `PHP=/path/to/php` to pick a specific
build.

Run `python3 selftest.py` before trusting any corpus figure. A near-zero
result on real code is indistinguishable from a broken scanner, and the
Packagist corpus produces exactly one finding; the self-test injects a
conformant German identifier, a capital sharp s, a glued-on U+00A0, a
zero-width joiner, a Cyrillic homoglyph, a raw Latin-1 byte and a decomposed
umlaut, and asserts the classification of each.

### Method notes

* `scan-identifiers.php` skips files containing a NUL byte and files with no
  PHP open tag. Both are necessary: `.php` is routinely used as an extension
  for SQLite databases and caches to keep the web server from serving them,
  and feeding those to `token_get_all()` manufactures hundreds of phantom
  identifiers out of binary noise.
* `classify-identifiers.py` uses CPython's `str.isidentifier()` as the raw
  UAX #31 oracle, since it is implemented on the `XID_Start`/`XID_Continue`
  properties. NFC comes from `unicodedata`. Both therefore reflect the Unicode
  version the running Python was built against, which the summary records under
  `environment`.
* **Raw XID is not version-stable, so it is not what the tool asserts on.**
  UAX #31 moved the joining controls U+200C and U+200D into `XID_Continue`;
  older revisions excluded them explicitly. CPython 3.12 (Unicode 15.0)
  therefore rejects `$zwj<ZWJ>test` and CPython 3.14 (Unicode 16.0) accepts it.
  The `uax31_profile` column applies the profile UAX #31 itself recommends for
  general-purpose identifiers -- XID minus the Default_Ignorable_Code_Points --
  which is stable across versions and is the rule an RFC should specify. The
  `Default_Ignorable_Code_Point` ranges are carried inline because
  `unicodedata` does not expose the property.
* The Script property is approximated from Unicode character names, because
  the standard library does not expose it. This is adequate for the
  Latin/Greek/Cyrillic confusion cases that matter and is reported as an
  approximation.
* The role heuristic looks at the nearest preceding significant token. It
  cannot distinguish a method call from a property access after `->`, so the
  case-folding figures for `property_or_method` and `static_member` are
  reported separately from the unambiguous declaration roles.

## Corpora and results

Three corpora were scanned. The largest is the one that matters.

**Corpus 0 -- Packagist, top 5,000 by downloads.** 4,863 packages resolvable
and non-empty, 520,802 PHP files, 2.4 GB. Run after the list asked for more
than the original 250.

| Measure | Value |
| --- | ---: |
| Non-ASCII identifier records | 1,447 |
| Distinct names | 898 |
| Packages affected | 25 of 4,863 |
| Files affected | 237 of 520,802 |
| Not well-formed UTF-8 | 2 |
| Not conformant to the profile | 913 |
| **Not NFC** | **0** |
| Containing an invisible character | 68 |

**One package is 91 % of that result.** `markrogoyski/math-php` accounts for
1,312 of the 1,447 records, 888 of the 913 non-conformances, and they are
neither fixtures nor accidents -- they are variable names in `src/` that spell
the formula:

```php
$n！ = self::factorial($n);
$∑  = 0;
protected $d₁;
$π  = \M_PI;
$│∑│      = $∑->det();
$√⟮2π⟯ᵏ│∑│ = \sqrt((2 * $π) ** $k * $│∑│);
```

1,247 of the 1,312 are `T_VARIABLE`. The characters that fail are mathematical
notation: U+27EE/U+27EF flattened parentheses, sub- and superscript digits,
U+2211 summation, U+2212 minus. None is in `XID_Continue`.

Excluding that one package, the picture is different in kind:

| Measure | Excluding math-php |
| --- | ---: |
| Records | 135 across 24 packages, 41 files |
| Not conformant | 25 -- of which 15 are one test file in `hoa/console` |
| Production tier only | 65 records, 18 packages, 6 non-conformant |

Everything else already conforms: `mjaschen/phpgeo` (22, Vincenty geodesy with
`$φ`, `$λ`, `$sinλ`, `$cos2σM`), `tracy/tracy` (14, U+029F as a Latte namespace
prefix), `wsdltophp/packagegenerator` (44, generated accessors over a Russian
WSDL schema).

**Names, as distinct from identifiers.** PHP allows any string as a *name*;
only *identifiers* are constrained by the lexer. Scanning literals in
name-creating positions (`${'...'}`, `->{'...'}`, `define()`, `class_alias()`
and friends) over the same corpus yields **5** non-ASCII names in 2 packages:
three in `halaxa/json-machine` naming variables after the individual bytes of
the UTF-8 BOM, and two in vendored `rowbot/url` WHATWG conformance tests. All
five are deliberate uses of the name syntax precisely because they are not
expressible as identifiers.

Two further corpora were scanned earlier and are retained for comparison.

**Corpus 1 -- Packagist, popularity weighted.** The 250 most-downloaded
packages on Packagist (all above 10,000 downloads), resolved to their GitHub
source repositories: 61,891 PHP files, 266 MB. This is the corpus that answers
"what would a strict mode break in code people actually install".

**Corpus 2 -- GitHub, two strata.** 250 repositories in two strata: 129
top-starred PHP projects, and 122 projects found through Chinese, Japanese,
Russian, German, Korean, Persian and Greek search terms, where non-ASCII
identifiers are a priori more likely. 106,713 PHP files, 540 MB. This corpus
answers "who actually uses non-ASCII identifiers, and how".

| | Packagist (250 pkgs) | GitHub (250 repos) |
| --- | ---: | ---: |
| PHP files | 61,891 | 106,713 |
| Non-ASCII identifier records | **1** | 136 |
| Distinct names | 1 | 107 |
| Packages affected | 1 | 14 |
| Files affected | 1 | 41 |

These two numbers answer two different questions and must not be added
together.

**Cost -- what would stop compiling.** On the Packagist corpus, one
identifier. That is the adoption cost of a strict mode across the code most
people actually install.

**Catch rate -- what the rule would find.** Only measurable where non-ASCII
identifiers occur at all, which is not the top Packagist packages. On the
GitHub corpus, 33 of 136.

| Check | Packagist | GitHub |
| --- | ---: | ---: |
| Invalid UTF-8 | 1 | 17 |
| Not UAX #31 conformant (raw) | 0 | 16 |
| Not UAX #31 conformant (recommended profile) | 0 | 16 |
| Contains an invisible character | 0 | 11 |
| Not NFC | **0** | **0** |
| Any of the above | 1 | 33 |

Both numbers are small, and this survey does not argue otherwise. It measures;
it does not make the case.

File-level hazards, independent of identifiers:

| Hazard | Packagist | GitHub |
| --- | ---: | ---: |
| Invalid UTF-8 anywhere in the file | 1 | 125 |
| UTF-8 BOM | 0 | 20 |
| Bidi control characters | 1 | 6 |
| `declare(encoding=...)` | 0 | 4 |

The headline number is the first one: **across the 250 most-installed packages
on Packagist, exactly one non-ASCII identifier exists**, and it is the Symfony
case below. The BC cost of an opt-in strict mode on mainstream dependency
graphs is, to a first approximation, zero.

### What this survey is not evidence of

**It found no homoglyph or spoofing attacks, and it is not evidence that any
exist in PHP.** Across both corpora there is not one identifier mixing Latin
with Cyrillic or Greek, and not one that maps to a plausible ASCII identifier
under homoglyph substitution. Anyone citing these numbers as support for a
supply-chain attack surface would be misusing them.

What the data does show is invisible characters inside identifiers -- 11
instances, all of them typos rather than attacks -- and identifiers that are
not well-formed UTF-8. Those are correctness hazards, not security findings,
and UAX #31 section 2.3 takes the same view: for programming languages,
spoofing is better addressed by higher-level diagnostics than in the lexer.

The single bidi hit in Packagist is a false positive for attack purposes:
`nesbot/carbon`, `src/Carbon/List/languages.php` uses U+202B RIGHT-TO-LEFT
EMBEDDING inside a *string literal* holding the Uyghur endonym. Real code
contains legitimate bidi controls in data, so a bidi lint has to be scoped to
comments and identifiers, not to the whole file. This is worth stating in the
RFC before someone raises it as an objection.

### Findings

**1. Symfony ships a class name that is not valid UTF-8.**
`symfony/cache`, `Traits/ValueWrapper.php:19` declares `class \xA9` -- a class
whose entire name is one 0xA9 byte, in a file that consequently does not decode
as UTF-8. Verified against upstream branch 7.3, and found independently in both
corpora. It is the *only* non-ASCII identifier in the Packagist corpus, which
makes it simultaneously the entire measured BC cost of a strict mode and the
reason that mode must be opt-in. This single data point is the argument for
`declare()` over an INI setting or a default change.

**2. A no-break space is glued onto an identifier in the Alipay SDK.**
`AopClient.php` contains `$chrtext\u{00A0} = null;` and later passes
`$chrtext\u{00A0}` by reference to `openssl_public_encrypt()`. It works only
because the typo is consistent; anyone typing `$chrtext` creates a silently
different variable. Five vendored copies appear across four unrelated projects
in the corpus. U+00A0 is not in `XID_Continue`, so a UAX #31 check catches it at
compile time. This is the clearest example of the diagnostic value of the
proposal, as distinct from its expressive value.

**3. Japanese test method names are established practice, not a curiosity.**
52 of the 136 records are PHPUnit method declarations such as
`test_認証済みユーザーは取引先一覧を閲覧できる`. These are well-formed, NFC, and UAX #31
conformant. They are the constituency that benefits from the guarantees.

**4. Russian property names come from an external data format.**
`icms2_showcase` accesses SimpleXML nodes from CommerceML (1C) exports:
`$xml->Свойства`, `$xml->ЦенаЗаЕдиницу`. The identifiers are dictated by the
interchange format, not chosen for style.

**5. Legacy encodings still exist in shipped source.**
`FeMiner/wms` contains GBK-encoded PHP files whose identifiers are non-UTF-8
byte sequences, e.g. `warehouse\xB2\xBB\xB4\xE6\xD4\xDA`.

**6. A Unicode version floor and a profile are both mandatory, and the survey
proved it the hard way.** The regression test failed when run on CPython 3.14
and passed on 3.12, for one identifier containing a zero-width joiner, because
`XID_Continue` changed underneath it. A PHP RFC that says only "UAX #31
conformant" inherits that instability: the same source file would compile or
not depending on which ICU or Unicode table the build was linked against. The
RFC must (a) name a minimum Unicode version, as
`draft-rodenhaeuser-idna-transparent-resolution` does, and (b) declare a
profile excluding Default_Ignorable_Code_Points -- which UAX #31 recommends
anyway, on the grounds that variation selectors and joining controls request a
rendering difference without guaranteeing one.

11 identifiers in the GitHub corpus contain an invisible character: nine are
the U+00A0 case below, and one is an identifier made of two U+3000 IDEOGRAPHIC
SPACE characters followed by a digit. None appears in the Packagist corpus.

**7. Zero NFC violations.** Not one identifier in the corpus was non-NFC.
This strongly suggests the cheap design is the right one: require NFC and
reject otherwise, rather than bundling full normalisation tables in core to
silently rewrite identifiers. An NFC quick-check table restricted to the XID
subset is a few KiB.

**8. Zero confusable-script mixtures.** No Latin/Cyrillic or Latin/Greek mixed
identifiers were found in either corpus. 54 identifiers are multi-script, but
all of them are benign: an ASCII prefix such as `test_` in front of Han,
Hiragana or Katakana. The UTS #39 argument for the proposal is preventive, and
should be presented as such rather than as a response to observed attacks.

Note that this figure is only meaningful because ASCII letters are classified
as Script=Latin. An earlier revision of `classify-identifiers.py` classified
them as Common, which made the Latin/Cyrillic pair unreachable whenever the
Latin half was plain ASCII -- that is, in exactly the homoglyph attack the
check exists to find. The regression test in the repository injects
`$mixed\u{0430}dmin` for this reason.

**9. Case folding divergence exists but not where it breaks anything.**
34 records diverge between PHP's ASCII fold and Unicode case folding; none of
them is in an unambiguously case-insensitive declaration role. PHP_CodeSniffer
carries a test fixture built exactly on this behaviour:

```php
$t->DIFFERENTcaseSameNonAnsiiCharáctêrs();      // resolves
$t->DIFFERENTcaseDifferentNonAnsiiCharÁctÊrs(); // Error: Á is not folded
```

This supports keeping case-folding changes out of the first RFC entirely.

## Caveats

* 250 repositories is a pilot, not Packagist. GitHub star count is a poor proxy
  for Packagist install count, and stratum B is a convenience sample built from
  search terms, so the two strata must not be pooled into a single rate.
* `.php` files inside `vendor/` are counted but flagged, since vendored copies
  duplicate upstream findings (17 of 136 records are vendored).
* Scanning used PHP 8.3's tokenizer. Syntax introduced later still lexes, but
  re-running on the newest release before publication is advisable.

## Running against Packagist

    python3 fetch-packagist.py --probe          # connectivity check first
    python3 fetch-packagist.py --out corpus/packagist --limit 2000 \
        --min-downloads 10000 --manifest manifest.json
    php scan-identifiers.php --progress --out=scan.jsonl corpus/packagist
    python3 classify-identifiers.py scan.jsonl --csv findings.csv --json findings.json

`--out` is a directory, one subdirectory per package. The run resumes: packages
whose directory already exists are skipped, so an interrupted download can be
restarted with identical arguments. `--manifest` records the resolved package
list so a later run can be compared against the same corpus.

Downloading and extraction use `urllib` and `tarfile`, not a `curl | tar` shell
pipeline. A pipeline cannot report which half failed, and capturing subprocess
output while also redirecting tar's stderr discards the diagnosis completely --
an earlier version of this script did exactly that and reported 250 consecutive
silent failures. Every failure status now names a cause: `http_404`,
`network:*`, `timeout`, `not_gzip:*`, `tar:*`, `no_php_files`. The first ten are
printed at the end of a run.

codeload serves the default branch under the ref `HEAD`. Guessing
`refs/heads/main` or `refs/heads/master` is both unnecessary and wrong for any
repository whose default branch is neither.

Packagist metadata is irregular. `source` and `dist` frequently exist with a
`null` value rather than being absent, some packages are hosted outside GitHub,
and some have no versions at all. Resolution is fully defensive and never
raises, because one malformed package aborting a thread pool would discard the
entire run.

`--probe` downloads and extracts one known repository verbosely and exits. Use
it before a long run, and whenever a run yields nothing.

A complete pass over the roughly 400,000 published packages needs on the order
of a terabyte of transfer if done naively; restricting to packages above a
download threshold, and extracting only PHP files from the default-branch
tarball, keeps it tractable.

## Licence

BSD-3-Clause (SPDX: `BSD-3-Clause`), matching php-src. The PHP License v3.01
and the Zend Engine License were formally retired on 2026-05-07; PHP License
v4.0 is textually identical to the Modified BSD License. Using the same terms
means the tooling and its output can be attached to an RFC without licence
friction.
