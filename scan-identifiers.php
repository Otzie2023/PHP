<?php
/**
 * scan-identifiers.php -- Stage 0 data collection for the
 * "Unicode-aware identifiers in PHP" RFC.
 *
 * Walks a directory tree, tokenizes every PHP source file with ext/tokenizer
 * and reports:
 *   - every identifier token containing at least one byte >= 0x80
 *   - file level hazards: invalid UTF-8, BOM, bidirectional control
 *     characters (CVE-2021-42574 "Trojan Source"), declare(encoding=...)
 *
 * Output is JSON Lines on stdout (or --out=FILE). Unicode classification is
 * deliberately NOT done here: PHP core has no NFC and no UAX #31 tables,
 * which is precisely the gap this RFC is about. Classification happens in
 * classify-identifiers.py.
 *
 * Usage:
 *   php scan-identifiers.php [options] <root> [<root> ...]
 *
 * Options:
 *   --out=FILE       write JSONL to FILE instead of stdout
 *   --ext=LIST       comma separated extensions (default: php,inc,phtml,phpt)
 *   --depth=N        treat the first N path segments below <root> as the
 *                    package name (default: 1)
 *   --max-bytes=N    skip files larger than N bytes (default: 4194304)
 *   --progress       write progress to stderr
 *
 * License: BSD-3-Clause, the same terms as php-src since the PHP License v3.01
 * was retired in May 2026, so this tooling and its output can be attached to
 * an RFC without licence friction.
 */

declare(strict_types=1);

/**
 * Bumped whenever the scanner's output semantics change. It is written into
 * the first line of the JSONL so that a result set always records which tool
 * and which PHP produced it, and so that a stale copy of one tool paired with
 * a current copy of another is detected rather than silently tolerated.
 */
const TOOL_VERSION = '1.2.0';

const IDENTIFIER_TOKENS = [
    T_STRING,
    T_VARIABLE,
    T_NAME_QUALIFIED,
    T_NAME_FULLY_QUALIFIED,
    T_NAME_RELATIVE,
    T_START_HEREDOC,
];

/**
 * Functions whose string argument creates or looks up a name rather than
 * being ordinary data. PHP distinguishes names from identifiers: an identifier
 * is a lexical token, a name is any string that reaches a symbol table, and
 * the second set is much larger. Identifiers are what a compile-time rule can
 * govern; names are not. Only the statically visible part of the name space is
 * measurable at all -- a literal in source -- and that is what this collects.
 */
const NAME_FUNCTIONS = [
    'define' => 0,
    'constant' => 0,
    'defined' => 0,
    'class_alias' => 1,
    'class_exists' => 0,
    'interface_exists' => 0,
    'enum_exists' => 0,
    'function_exists' => 0,
    'method_exists' => 1,
    'property_exists' => 1,
];

/** UTF-8 encodings of the bidi control characters relevant to Trojan Source. */
const BIDI_SEQUENCES = [
    "\xE2\x80\xAA", // U+202A LEFT-TO-RIGHT EMBEDDING
    "\xE2\x80\xAB", // U+202B RIGHT-TO-LEFT EMBEDDING
    "\xE2\x80\xAC", // U+202C POP DIRECTIONAL FORMATTING
    "\xE2\x80\xAD", // U+202D LEFT-TO-RIGHT OVERRIDE
    "\xE2\x80\xAE", // U+202E RIGHT-TO-LEFT OVERRIDE
    "\xE2\x81\xA6", // U+2066 LEFT-TO-RIGHT ISOLATE
    "\xE2\x81\xA7", // U+2067 RIGHT-TO-LEFT ISOLATE
    "\xE2\x81\xA8", // U+2068 FIRST STRONG ISOLATE
    "\xE2\x81\xA9", // U+2069 POP DIRECTIONAL ISOLATE
];

function parse_options(array $argv): array
{
    $opts = [
        'out' => null,
        'ext' => ['php', 'inc', 'phtml', 'phpt'],
        'depth' => 1,
        'max-bytes' => 4 * 1024 * 1024,
        'progress' => false,
        'roots' => [],
    ];

    foreach (array_slice($argv, 1) as $arg) {
        if ($arg === '--progress') {
            $opts['progress'] = true;
        } elseif (str_starts_with($arg, '--out=')) {
            $opts['out'] = substr($arg, 6);
        } elseif (str_starts_with($arg, '--ext=')) {
            $opts['ext'] = array_filter(explode(',', substr($arg, 6)));
        } elseif (str_starts_with($arg, '--depth=')) {
            $opts['depth'] = (int) substr($arg, 8);
        } elseif (str_starts_with($arg, '--max-bytes=')) {
            $opts['max-bytes'] = (int) substr($arg, 12);
        } elseif ($arg === '--version') {
            fwrite(STDOUT, "scan-identifiers.php " . TOOL_VERSION . "\n");
            exit(0);
        } elseif (str_starts_with($arg, '--')) {
            fwrite(STDERR, "unknown option: {$arg}\n");
            exit(2);
        } else {
            $opts['roots'][] = rtrim($arg, '/');
        }
    }

    if ($opts['roots'] === []) {
        fwrite(STDERR, "usage: php scan-identifiers.php [options] <root> [<root> ...]\n");
        exit(2);
    }

    return $opts;
}

/**
 * Validate UTF-8 without requiring ext/mbstring.
 *
 * mb_check_encoding() is roughly an order of magnitude faster and is used when
 * available, but mbstring is not part of a minimal PHP build. An empty pattern
 * with the /u modifier makes PCRE validate the subject as UTF-8 and return
 * false rather than 0 when it fails, which covers the fallback with no
 * extension dependency at all.
 */
function is_valid_utf8(string $s): bool
{
    static $haveMbstring = null;
    if ($haveMbstring === null) {
        $haveMbstring = function_exists('mb_check_encoding');
    }
    return $haveMbstring
        ? mb_check_encoding($s, 'UTF-8')
        : @preg_match('//u', $s) === 1;
}

function has_high_byte(string $s): bool
{
    // This mirrors the ASCII fast path a strict mode implementation in the
    // engine would use: if no byte is >= 0x80, no Unicode work is needed.
    return preg_match('/[\x80-\xFF]/', $s) === 1;
}

/**
 * Determine what the identifier is being used for, by looking at the nearest
 * significant token before and after it. This is a heuristic, not a parser,
 * but it is accurate enough for the declaration cases that matter.
 */
/**
 * Decode a T_CONSTANT_ENCAPSED_STRING to its byte value. Returns null when the
 * literal uses an escape this does not handle, so that an undecoded literal is
 * skipped rather than counted wrongly.
 */
function decode_literal(string $tok): ?string
{
    if (strlen($tok) < 2) {
        return null;
    }
    $quote = $tok[0];
    if ($quote !== "'" && $quote !== '"') {
        return null;
    }
    $body = substr($tok, 1, -1);

    if ($quote === "'") {
        return str_replace(['\\\\', "\\'"], ['\\', "'"], $body);
    }

    $out = '';
    $len = strlen($body);
    for ($i = 0; $i < $len; $i++) {
        $c = $body[$i];
        if ($c !== '\\') {
            $out .= $c;
            continue;
        }
        $n = $body[++$i] ?? '';
        switch ($n) {
            case 'n': $out .= "\n"; break;
            case 't': $out .= "\t"; break;
            case 'r': $out .= "\r"; break;
            case 'v': $out .= "\v"; break;
            case 'f': $out .= "\f"; break;
            case 'e': $out .= "\x1B"; break;
            case '\\': $out .= '\\'; break;
            case '$': $out .= '$'; break;
            case '"': $out .= '"'; break;
            case 'x':
                if (preg_match('/^[0-9A-Fa-f]{1,2}/', substr($body, $i + 1), $m)) {
                    $out .= chr(hexdec($m[0]));
                    $i += strlen($m[0]);
                } else {
                    $out .= '\\x';
                }
                break;
            case 'u':
                if (preg_match('/^\{([0-9A-Fa-f]+)\}/', substr($body, $i + 1), $m)) {
                    $out .= mb_chr_compat((int) hexdec($m[1]));
                    $i += strlen($m[0]);
                } else {
                    $out .= '\\u';
                }
                break;
            default:
                if (preg_match('/^[0-7]{1,3}/', substr($body, $i), $m)) {
                    $out .= chr(octdec($m[0]) & 0xFF);
                    $i += strlen($m[0]) - 1;
                } else {
                    return null;
                }
        }
    }
    return $out;
}

/** UTF-8 encode a code point without requiring ext/mbstring. */
function mb_chr_compat(int $cp): string
{
    if ($cp < 0x80) {
        return chr($cp);
    }
    if ($cp < 0x800) {
        return chr(0xC0 | $cp >> 6) . chr(0x80 | $cp & 0x3F);
    }
    if ($cp < 0x10000) {
        return chr(0xE0 | $cp >> 12) . chr(0x80 | $cp >> 6 & 0x3F) . chr(0x80 | $cp & 0x3F);
    }
    return chr(0xF0 | $cp >> 18) . chr(0x80 | $cp >> 12 & 0x3F)
         . chr(0x80 | $cp >> 6 & 0x3F) . chr(0x80 | $cp & 0x3F);
}

/** Index of the next token that is not whitespace or a comment. */
function next_significant(array $tokens, int $i): int
{
    $n = count($tokens);
    for ($j = $i + 1; $j < $n; $j++) {
        $t = $tokens[$j];
        if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        return $j;
    }
    return $n;
}

function is_char(array $tokens, int $i, string $c): bool
{
    return isset($tokens[$i]) && !is_array($tokens[$i]) && $tokens[$i] === $c;
}

function is_kind(array $tokens, int $i, int $kind): bool
{
    return isset($tokens[$i]) && is_array($tokens[$i]) && $tokens[$i][0] === $kind;
}

/**
 * Collect names created or looked up through a string literal in source.
 * Returns [context, decoded name, line] tuples. Only names containing a byte
 * >= 0x80 are of interest, so the caller filters.
 */
function collect_names(array $tokens): array
{
    $out = [];
    $n = count($tokens);

    for ($i = 0; $i < $n; $i++) {
        $tok = $tokens[$i];

        // ${'literal'} and Foo::${'literal'}
        if (!is_array($tok) && $tok === '$') {
            $a = next_significant($tokens, $i);
            if (is_char($tokens, $a, '{')) {
                $b = next_significant($tokens, $a);
                if (is_kind($tokens, $b, T_CONSTANT_ENCAPSED_STRING)
                    && is_char($tokens, next_significant($tokens, $b), '}')) {
                    $ctx = ($i > 0 && is_kind($tokens, $i - 1, T_DOUBLE_COLON))
                        ? 'static_property' : 'variable_variable';
                    $out[] = [$ctx, $tokens[$b][1], $tokens[$b][2]];
                }
            }
            continue;
        }

        // ->{'literal'} and ?->{'literal'}
        if (is_array($tok)
            && ($tok[0] === T_OBJECT_OPERATOR || $tok[0] === T_NULLSAFE_OBJECT_OPERATOR)) {
            $a = next_significant($tokens, $i);
            if (is_char($tokens, $a, '{')) {
                $b = next_significant($tokens, $a);
                if (is_kind($tokens, $b, T_CONSTANT_ENCAPSED_STRING)
                    && is_char($tokens, next_significant($tokens, $b), '}')) {
                    $out[] = ['object_member', $tokens[$b][1], $tokens[$b][2]];
                }
            }
            continue;
        }

        // define('NAME', ...), class_alias(..., 'NAME'), constant('NAME'), ...
        if (is_array($tok) && $tok[0] === T_STRING) {
            $fn = strtolower($tok[1]);
            if (!isset(NAME_FUNCTIONS[$fn])) {
                continue;
            }
            // A method call or a namespaced name is a different function.
            if ($i > 0 && is_kind($tokens, $i - 1, T_OBJECT_OPERATOR)) {
                continue;
            }
            $a = next_significant($tokens, $i);
            if (!is_char($tokens, $a, '(')) {
                continue;
            }
            $wanted = NAME_FUNCTIONS[$fn];
            $arg = 0;
            $j = next_significant($tokens, $a);
            $depth = 0;
            while ($j < $n) {
                if (is_char($tokens, $j, '(') || is_char($tokens, $j, '[')) {
                    $depth++;
                } elseif (is_char($tokens, $j, ')') || is_char($tokens, $j, ']')) {
                    if ($depth === 0) {
                        break;
                    }
                    $depth--;
                } elseif ($depth === 0 && is_char($tokens, $j, ',')) {
                    $arg++;
                } elseif ($depth === 0 && $arg === $wanted
                          && is_kind($tokens, $j, T_CONSTANT_ENCAPSED_STRING)) {
                    $out[] = [$fn, $tokens[$j][1], $tokens[$j][2]];
                }
                $j = next_significant($tokens, $j);
            }
        }
    }

    return $out;
}

function classify_role(array $tokens, int $i): string
{
    $prev = null;
    for ($j = $i - 1; $j >= 0; $j--) {
        $t = $tokens[$j];
        if (is_array($t) && in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }
        $prev = $t;
        break;
    }

    if (is_array($prev)) {
        switch ($prev[0]) {
            case T_CLASS:      return 'class_decl';
            case T_INTERFACE:  return 'interface_decl';
            case T_TRAIT:      return 'trait_decl';
            case T_ENUM:       return 'enum_decl';
            case T_FUNCTION:   return 'function_decl';
            case T_CONST:      return 'const_decl';
            case T_NAMESPACE:  return 'namespace_decl';
            case T_GOTO:       return 'goto_label';
            case T_OBJECT_OPERATOR:
            case T_NULLSAFE_OBJECT_OPERATOR:
                return 'property_or_method';
            case T_DOUBLE_COLON:
                return 'static_member';
            case T_NEW:
                return 'class_use';
            case T_ATTRIBUTE:
                return 'attribute';
        }
    }

    // A ':' directly after a T_STRING at statement level is a goto label; we
    // do not track statement level, so this stays in 'other'.
    return 'other';
}

function scan_file(string $path, string $pkg, string $rel, int $maxBytes, $out): void
{
    $size = @filesize($path);
    if ($size === false || $size > $maxBytes) {
        return;
    }

    $src = @file_get_contents($path);
    if ($src === false) {
        return;
    }

    // Files carrying a .php extension are not necessarily PHP source. SQLite
    // databases, caches and uploads are routinely renamed to .php to keep the
    // web server from serving them. Feeding those to token_get_all() produces
    // spurious "identifiers" from binary noise, so they must be excluded.
    // Real PHP source practically never contains a NUL byte; the engine's own
    // scanner treats \x00 as a terminator.
    if (str_contains($src, "\x00")) {
        fwrite($out, json_encode([
            'type' => 'skip',
            'pkg' => $pkg,
            'file' => $rel,
            'reason' => 'binary',
            'bytes' => $size,
        ], JSON_UNESCAPED_UNICODE) . "\n");
        return;
    }

    if (!preg_match('/<\?(php\b|=|\s|$)/i', $src)) {
        fwrite($out, json_encode([
            'type' => 'skip',
            'pkg' => $pkg,
            'file' => $rel,
            'reason' => 'no_open_tag',
            'bytes' => $size,
        ], JSON_UNESCAPED_UNICODE) . "\n");
        return;
    }

    $bom = str_starts_with($src, "\xEF\xBB\xBF");
    $validUtf8 = is_valid_utf8($src);

    $bidi = false;
    foreach (BIDI_SEQUENCES as $seq) {
        if (str_contains($src, $seq)) {
            $bidi = true;
            break;
        }
    }

    $declareEncoding = preg_match('/declare\s*\(\s*encoding\s*=/i', $src) === 1;

    $lexError = false;
    $tokens = [];
    try {
        // Lexer only: syntax errors from newer language versions do not matter.
        $tokens = @token_get_all($src);
    } catch (\Throwable $e) {
        $lexError = true;
    }

    $fileRecord = [
        'type' => 'file',
        'pkg' => $pkg,
        'file' => $rel,
        'bytes' => $size,
        'valid_utf8' => $validUtf8,
        'bom' => $bom,
        'bidi' => $bidi,
        'declare_encoding' => $declareEncoding,
        'lex_error' => $lexError,
        'tokens' => count($tokens),
    ];
    fwrite($out, json_encode($fileRecord, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");

    if ($lexError) {
        return;
    }

    // Aggregate per (name, role) so that a loop variable used 200 times does
    // not dominate the corpus.
    $found = [];
    foreach ($tokens as $i => $tok) {
        if (!is_array($tok) || !in_array($tok[0], IDENTIFIER_TOKENS, true)) {
            continue;
        }

        $text = $tok[1];
        if (!has_high_byte($text)) {
            continue;
        }

        $kind = token_name($tok[0]);
        $role = classify_role($tokens, $i);

        // Split off the sigil / namespace separators so that each record holds
        // exactly one identifier as the lexer's LABEL rule would produce it.
        $parts = [];
        if ($tok[0] === T_VARIABLE) {
            $parts[] = ltrim($text, '$');
        } elseif ($tok[0] === T_START_HEREDOC) {
            $parts[] = trim(substr($text, 3), " \t\"'\r\n");
            $role = 'heredoc_label';
        } else {
            foreach (explode('\\', $text) as $p) {
                if ($p !== '') {
                    $parts[] = $p;
                }
            }
        }

        foreach ($parts as $name) {
            if (!has_high_byte($name)) {
                continue; // e.g. Foo\Bär -> only Bär is interesting
            }
            $key = $name . "\0" . $role . "\0" . $kind;
            if (!isset($found[$key])) {
                $found[$key] = [
                    'type' => 'ident',
                    'pkg' => $pkg,
                    'file' => $rel,
                    'name' => $name,
                    'name_hex' => bin2hex($name),
                    'role' => $role,
                    'kind' => $kind,
                    'line' => $tok[2],
                    'n' => 0,
                ];
            }
            $found[$key]['n']++;
        }
    }

    foreach ($found as $rec) {
        fwrite($out, json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
    }

    // Names, as distinct from identifiers. Same non-ASCII filter, so the
    // overwhelmingly common define('ASCII_CONST') costs nothing.
    $names = [];
    foreach (collect_names($tokens) as [$ctx, $literal, $line]) {
        $decoded = decode_literal($literal);
        if ($decoded === null || !has_high_byte($decoded)) {
            continue;
        }
        $key = $decoded . "\0" . $ctx;
        if (!isset($names[$key])) {
            $names[$key] = [
                'type' => 'name',
                'pkg' => $pkg,
                'file' => $rel,
                'name' => $decoded,
                'name_hex' => bin2hex($decoded),
                'context' => $ctx,
                'line' => $line,
                'n' => 0,
            ];
        }
        $names[$key]['n']++;
    }
    foreach ($names as $rec) {
        fwrite($out, json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
    }
}

function main(array $argv): int
{
    $opts = parse_options($argv);

    $out = $opts['out'] === null ? STDOUT : fopen($opts['out'], 'w');
    if ($out === false) {
        fwrite(STDERR, "cannot open output file\n");
        return 1;
    }

    fwrite($out, json_encode([
        'type' => 'meta',
        'tool_version' => TOOL_VERSION,
        'php_version' => PHP_VERSION,
        'mbstring' => function_exists('mb_check_encoding'),
        'roots' => $opts['roots'],
    ], JSON_UNESCAPED_UNICODE) . "\n");

    $extensions = array_flip(array_map('strtolower', $opts['ext']));
    $fileCount = 0;

    foreach ($opts['roots'] as $root) {
        if (!is_dir($root)) {
            fwrite(STDERR, "not a directory: {$root}\n");
            continue;
        }

        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );

        foreach ($iter as $fileInfo) {
            /** @var SplFileInfo $fileInfo */
            if (!$fileInfo->isFile()) {
                continue;
            }
            if (!isset($extensions[strtolower($fileInfo->getExtension())])) {
                continue;
            }

            $path = $fileInfo->getPathname();
            $rel = ltrim(substr($path, strlen($root)), '/');
            $segments = explode('/', $rel);
            $pkg = implode('/', array_slice($segments, 0, max(1, $opts['depth'])));

            scan_file($path, $pkg, $rel, $opts['max-bytes'], $out);

            $fileCount++;
            if ($opts['progress'] && $fileCount % 2000 === 0) {
                fwrite(STDERR, "  scanned {$fileCount} files\n");
            }
        }
    }

    if ($opts['progress']) {
        fwrite(STDERR, "  scanned {$fileCount} files (done)\n");
    }

    if ($out !== STDOUT) {
        fclose($out);
    }

    return 0;
}

exit(main($argv));
