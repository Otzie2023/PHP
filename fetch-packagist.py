#!/usr/bin/env python3
"""fetch-packagist.py -- build a corpus from Packagist for the full Stage 0 run.

Resolves popular Packagist packages to their GitHub source repositories and
downloads the default-branch tarball, extracting only PHP files to keep
transfer and disk within reason.

Usage:
    python3 fetch-packagist.py --out corpus/packagist --limit 2000 \
        --min-downloads 10000 [--jobs 8] [--manifest manifest.json]

    python3 fetch-packagist.py --probe        # connectivity check, downloads
                                              # one known repository verbosely

--out is a DIRECTORY. One subdirectory is created per package.

Resume: packages whose directory already exists are skipped, so an interrupted
run can simply be restarted with the same arguments.

Downloading and extraction are done with urllib and tarfile rather than a
`curl | tar` shell pipeline. A pipeline hides which of the two failed, and
capturing subprocess output while also redirecting tar's stderr discards the
diagnosis entirely. Every failure below carries a reason.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request

UA = {"User-Agent": "php-identifier-survey (RFC data collection)"}

PHP_SUFFIXES = (".php", ".inc", ".phtml")

# Matches both source URLs (git@github.com:owner/repo.git,
# https://github.com/owner/repo) and dist URLs
# (https://api.github.com/repos/owner/repo/zipball/<sha>).
GITHUB_SOURCE_RE = re.compile(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$")
GITHUB_DIST_RE = re.compile(r"api\.github\.com/repos/([^/]+)/([^/]+)/")


def get_json(url: str, retries: int = 3):
    """Fetch and parse JSON. Returns None on any failure; never raises."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                time.sleep(5 * (attempt + 1))
                continue
        except Exception:
            pass
        if attempt < retries - 1:
            time.sleep(2 ** attempt)
    return None


def popular_packages(limit: int, min_downloads: int) -> list[str]:
    """Packagist's paged 'popular' list is a far better relevance signal than
    the alphabetical list.json."""
    names: list[str] = []
    page = 1
    while len(names) < limit:
        data = get_json(
            f"https://packagist.org/explore/popular.json?page={page}&per_page=100"
        )
        if not isinstance(data, dict):
            break
        packages = data.get("packages") or []
        if not packages:
            break
        for p in packages:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            if (p.get("downloads") or 0) < min_downloads:
                return names
            names.append(p["name"])
            if len(names) >= limit:
                return names
        page += 1
        time.sleep(0.5)
    return names


def source_repo(name: str):
    """Resolve a package name to (name, owner, repo), or None.

    Packagist metadata is irregular: 'source' and 'dist' may be present with a
    null value rather than absent, versions may be an empty list, and some
    packages are hosted outside GitHub. Every access is therefore defensive,
    and the whole function is guarded so that one bad package cannot abort the
    thread pool.
    """
    try:
        data = get_json(f"https://repo.packagist.org/p2/{name}.json")
        if not isinstance(data, dict):
            return None

        packages = data.get("packages") or {}
        versions = packages.get(name) or []
        if not isinstance(versions, list):
            return None

        for v in versions:
            if not isinstance(v, dict):
                continue

            # 'or {}' rather than a .get() default: the key exists with a null
            # value for a noticeable share of packages, which a default
            # argument does not catch.
            src = v.get("source") or {}
            url = src.get("url") or ""
            if "github.com" in url:
                m = GITHUB_SOURCE_RE.search(url)
                if m:
                    return name, m.group(1), m.group(2)

            dist = v.get("dist") or {}
            durl = dist.get("url") or ""
            if "api.github.com/repos/" in durl:
                m = GITHUB_DIST_RE.search(durl)
                if m:
                    return name, m.group(1), m.group(2)

        return None
    except Exception:
        return None


def download_tarball(owner: str, repo: str, timeout: int, verbose: bool = False):
    """Return (bytes, reason). Exactly one of the two is None.

    codeload serves the default branch under the ref 'HEAD'. Guessing
    'refs/heads/main' or 'refs/heads/master' is wrong for any repository whose
    default branch is neither, and it is unnecessary.
    """
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
    if verbose:
        print(f"  GET {url}", flush=True)
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if verbose:
                print(f"  HTTP {r.status} {r.headers.get('Content-Type')}", flush=True)
            data = r.read()
    except urllib.error.HTTPError as e:
        return None, f"http_{e.code}"
    except urllib.error.URLError as e:
        return None, f"network:{type(e.reason).__name__}"
    except TimeoutError:
        return None, "timeout"
    except Exception as e:
        return None, f"error:{type(e).__name__}"

    if not data:
        return None, "empty_response"
    if data[:2] != b"\x1f\x8b":
        return None, f"not_gzip:{data[:24]!r}"
    if verbose:
        print(f"  {len(data)} bytes, gzip magic ok", flush=True)
    return data, None


def extract_php(data: bytes, dest: str, verbose: bool = False):
    """Extract only PHP sources, stripping the leading archive directory.
    Returns (file count, reason)."""
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                if not member.name.lower().endswith(PHP_SUFFIXES):
                    continue
                parts = member.name.split("/", 1)
                if len(parts) != 2 or not parts[1]:
                    continue
                member.name = parts[1]          # --strip-components=1
                try:
                    tf.extract(member, path=dest, filter="data")
                except Exception:
                    continue                    # one bad member must not stop the rest
                count += 1
    except tarfile.TarError as e:
        return 0, f"tar:{type(e).__name__}"
    except Exception as e:
        return 0, f"extract:{type(e).__name__}"
    if verbose:
        print(f"  extracted {count} PHP files", flush=True)
    return count, None


def fetch(job, out_dir: str, timeout: int) -> tuple[str, str]:
    """Download one repository. Returns (package name, status)."""
    name, owner, repo = job
    dest = os.path.join(out_dir, name.replace("/", "__"))
    if os.path.isdir(dest):
        return name, "cached"

    data, reason = download_tarball(owner, repo, timeout)
    if data is None:
        return name, reason

    os.makedirs(dest, exist_ok=True)
    count, reason = extract_php(data, dest)
    if reason:
        shutil.rmtree(dest, ignore_errors=True)
        return name, reason
    if count == 0:
        shutil.rmtree(dest, ignore_errors=True)
        return name, "no_php_files"
    return name, "ok"


def probe(timeout: int) -> int:
    """Verify that codeload is reachable and extraction works, verbosely."""
    print("probe: packagist.org")
    meta = get_json("https://repo.packagist.org/p2/symfony/cache.json")
    print(f"  metadata endpoint: {'ok' if meta else 'UNREACHABLE'}")

    print("probe: codeload.github.com (symfony/cache)")
    data, reason = download_tarball("symfony", "cache", timeout, verbose=True)
    if data is None:
        print(f"  FAILED: {reason}")
        print("\ncodeload.github.com is not reachable from this machine.")
        print("Check proxy settings (https_proxy), DNS, or a firewall rule.")
        return 1

    dest = os.path.join(".", "_probe_symfony_cache")
    shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)
    count, reason = extract_php(data, dest, verbose=True)
    shutil.rmtree(dest, ignore_errors=True)
    if reason or count == 0:
        print(f"  FAILED: {reason or 'no PHP files found'}")
        return 1
    print("\nprobe ok: downloads and extraction work. Run without --probe.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build a PHP source corpus from Packagist.",
        epilog="--out is a directory, not a file.",
    )
    ap.add_argument("--out", metavar="DIR",
                    help="output DIRECTORY; one subdirectory per package")
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--min-downloads", type=int, default=10000)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--manifest", metavar="FILE",
                    help="write the resolved package list here for reproducibility")
    ap.add_argument("--probe", action="store_true",
                    help="check connectivity and extraction on one repository, then exit")
    args = ap.parse_args()

    if args.probe:
        return probe(args.timeout)
    if not args.out:
        ap.error("--out is required (or use --probe)")

    if os.path.isfile(args.out):
        print(f"--out must be a directory, but {args.out!r} is a file", file=sys.stderr)
        return 2
    if os.path.splitext(args.out)[1] and not os.path.isdir(args.out):
        print(f"note: --out is a directory; creating {args.out!r} as one", file=sys.stderr)
    os.makedirs(args.out, exist_ok=True)

    print("resolving popular packages ...", flush=True)
    names = popular_packages(args.limit, args.min_downloads)
    print(f"  {len(names)} packages above {args.min_downloads} downloads", flush=True)
    if not names:
        print("no packages resolved -- is packagist.org reachable?", file=sys.stderr)
        return 1

    print("resolving source repositories ...", flush=True)
    jobs, unresolved = [], []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = {ex.submit(source_repo, n): n for n in names}
        for i, fut in enumerate(cf.as_completed(futures), 1):
            res = fut.result()          # source_repo never raises
            (jobs if res else unresolved).append(res or futures[fut])
            if i % 100 == 0:
                print(f"  {i}/{len(names)} resolved={len(jobs)}", flush=True)
    print(f"  {len(jobs)} GitHub-hosted, {len(unresolved)} not resolvable", flush=True)
    if unresolved:
        print(f"  examples: {', '.join(unresolved[:5])}", flush=True)

    if args.manifest:
        with open(args.manifest, "w", encoding="utf-8") as fh:
            json.dump({
                "limit": args.limit,
                "min_downloads": args.min_downloads,
                "resolved": [{"name": n, "owner": o, "repo": r} for n, o, r in jobs],
                "unresolved": unresolved,
            }, fh, indent=1, ensure_ascii=False)
        print(f"  manifest written to {args.manifest}", flush=True)

    print("downloading ...", flush=True)
    stats = collections.Counter()
    failures = []
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = [ex.submit(fetch, j, args.out, args.timeout) for j in jobs]
        for i, fut in enumerate(cf.as_completed(futures), 1):
            name, status = fut.result()
            stats[status] += 1
            if status not in ("ok", "cached") and len(failures) < 10:
                failures.append(f"{name}: {status}")
            if i % 50 == 0:
                print(f"  {i}/{len(jobs)} {dict(stats)}", flush=True)

    print(f"done: {dict(stats)}")
    if failures:
        print("first failures:")
        for f in failures:
            print(f"  {f}")
    if stats["ok"] == 0 and stats["cached"] == 0:
        print("\nnothing downloaded. Run with --probe for a verbose single-repository test.",
              file=sys.stderr)
        return 1

    print(f"corpus in {args.out}/ -- next:")
    print(f"  php scan-identifiers.php --progress --out=scan.jsonl {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
