#!/usr/bin/env python3
"""Download GitHub tarballs and extract only PHP sources, to keep disk use low."""
import concurrent.futures as cf
import json
import os
import subprocess
import sys

OUT = sys.argv[1]
LISTS = sys.argv[2].split(",")
LIMIT = int(sys.argv[3])
MAX_KB = int(sys.argv[4])

repos = []
seen = set()
for path in LISTS:
    for r in json.load(open(path)):
        if r["full_name"] in seen:
            continue
        if r["size_kb"] > MAX_KB:
            continue
        seen.add(r["full_name"])
        repos.append(r)
repos = repos[:LIMIT]
os.makedirs(OUT, exist_ok=True)


def fetch(r):
    owner, name = r["full_name"].split("/", 1)
    dest = os.path.join(OUT, f"{owner}__{name}")
    if os.path.isdir(dest):
        return r["full_name"], "cached"
    os.makedirs(dest, exist_ok=True)
    url = f"https://codeload.github.com/{owner}/{name}/tar.gz/refs/heads/{r['default_branch']}"
    cmd = (
        f"curl -sSL --max-time 300 --retry 2 {url} | "
        f"tar -xz -C {dest} --strip-components=1 --wildcards "
        f"'*.php' '*.inc' '*.phtml' 2>/dev/null"
    )
    p = subprocess.run(["bash", "-c", cmd], capture_output=True)
    n = sum(len(f) for _, _, f in os.walk(dest))
    if n == 0:
        subprocess.run(["rm", "-rf", dest])
        return r["full_name"], "empty"
    return r["full_name"], f"{n} files"


ok = 0
with cf.ThreadPoolExecutor(max_workers=8) as ex:
    for i, (fn, status) in enumerate(ex.map(fetch, repos), 1):
        if "files" in status or status == "cached":
            ok += 1
        if i % 20 == 0:
            print(f"  {i}/{len(repos)} ({ok} with PHP files)", flush=True)
print(f"done: {ok}/{len(repos)} repositories")
