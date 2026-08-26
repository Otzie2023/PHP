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

const IDENTIFIER_TOKENS = [
    T_STRING,
    T_VARIABLE,
    T_NAME_QUALIFIED,
    T_NAME_FULLY_QUALIFIED,
    T_NAME_RELATIVE,
    T_START_HEREDOC,
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
}

function main(array $argv): int
{
    $opts = parse_options($argv);

    $out = $opts['out'] === null ? STDOUT : fopen($opts['out'], 'w');
    if ($out === false) {
        fwrite(STDERR, "cannot open output file\n");
        return 1;
    }

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
