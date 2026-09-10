#!/usr/bin/env python3
"""
cpe_match.py -- correct CPE 2.3 matching (adopted PATTERN from cve-search's cpe/version logic, NOT the
dependency). Replaces naive product-string matching in the CVE-RAG correlation path: it understands CPE
2.3 fields (vendor/product/version), ANY (`*`) / NA (`-`) wildcards, and NVD version-range constraints
(versionStartIncluding/Excluding, versionEndIncluding/Excluding). Offline, stdlib-only.

    from cpe_match import cpe_matches, config_matches
    cpe_matches("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "apache", "log4j", "2.14.1",
                {"versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"})   # -> True
"""
from __future__ import annotations

import re


def parse_cpe(uri: str) -> dict:
    """Parse a CPE 2.3 formatted-string URI into its fields. Unknown/short URIs degrade gracefully."""
    parts = (uri or "").split(":")
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        f = parts[2:]
    elif uri.startswith("cpe:/"):                       # legacy cpe:/a:vendor:product:version
        f = uri[5:].split(":")
    else:
        f = []
    keys = ["part", "vendor", "product", "version", "update", "edition",
            "language", "sw_edition", "target_sw", "target_hw", "other"]
    out = {k: (f[i] if i < len(f) else "*") for i, k in enumerate(keys)}
    return out


def _wild(a: str, b: str) -> bool:
    """Match a CPE field with ANY(*)/NA(-) semantics (case-insensitive)."""
    a, b = (a or "*").lower(), (b or "*").lower()
    if a in ("*", "-") or b in ("*", "-"):
        return True
    return a == b


def _ver_tuple(v: str):
    """Split a version into a comparable tuple of (int-or-str) chunks; numeric chunks compare numerically."""
    out = []
    for chunk in re.split(r"[.\-_+~]", (v or "").strip()):
        if not chunk:
            continue
        for sub in re.findall(r"\d+|[a-zA-Z]+", chunk):
            out.append((0, int(sub)) if sub.isdigit() else (1, sub))   # numbers sort before/among strings
    return out


def ver_cmp(a: str, b: str) -> int:
    """-1/0/1 comparing two version strings (numeric-aware). Missing -> lowest."""
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    return (ta > tb) - (ta < tb)


def _in_range(version: str, rng: dict) -> bool:
    """NVD range constraints. Empty rng -> the CPE's own version field must have matched already."""
    if not version or version in ("*", "-"):
        return True
    if "versionStartIncluding" in rng and ver_cmp(version, rng["versionStartIncluding"]) < 0:
        return False
    if "versionStartExcluding" in rng and ver_cmp(version, rng["versionStartExcluding"]) <= 0:
        return False
    if "versionEndIncluding" in rng and ver_cmp(version, rng["versionEndIncluding"]) > 0:
        return False
    if "versionEndExcluding" in rng and ver_cmp(version, rng["versionEndExcluding"]) >= 0:
        return False
    return True


def cpe_matches(cpe_uri: str, vendor: str, product: str, version: str = "*", rng: dict = None) -> bool:
    """True iff an installed (vendor, product, version) matches the CPE (+ optional NVD version range).
    A range (rng) overrides the CPE's own version field (NVD puts ranges on a `*`-version CPE)."""
    c = parse_cpe(cpe_uri)
    if not (_wild(c["vendor"], vendor) and _wild(c["product"], product)):
        return False
    if rng:
        return _in_range(version, rng)
    # no range: honour the CPE's own version field (ANY/NA -> match; else exact numeric-aware equality)
    cv = c["version"]
    if cv in ("*", "-") or not version or version in ("*", "-"):
        return True
    return ver_cmp(cv, version) == 0


def config_matches(cpe_match_list: list, vendor: str, product: str, version: str) -> list:
    """Given an NVD `configurations` cpe_match list ([{criteria|cpe23Uri, versionStart..., vulnerable}]),
    return the entries the installed (vendor, product, version) matches -- i.e. is it in the vulnerable set."""
    hits = []
    for m in cpe_match_list or []:
        uri = m.get("criteria") or m.get("cpe23Uri") or m.get("cpe") or ""
        rng = {k: m[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                 "versionEndIncluding", "versionEndExcluding") if m.get(k)}
        if cpe_matches(uri, vendor, product, version, rng or None):
            hits.append(m)
    return hits


def _selftest():
    cases = [
        # (cpe, vendor, product, version, rng, expected)
        ("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "apache", "log4j", "2.14.1",
         {"versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"}, True),
        ("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "apache", "log4j", "2.15.0",
         {"versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"}, False),
        ("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*", "openssl", "openssl", "1.0.1", None, True),
        ("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*", "openssl", "openssl", "1.0.2", None, False),
        ("cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", "other", "app", "1.0", None, False),   # vendor mismatch
        ("cpe:2.3:a:*:app:*:*:*:*:*:*:*:*", "anyone", "app", "9", None, True),        # vendor ANY
        ("cpe:2.3:a:n:p:*:*:*:*:*:*:*:*", "n", "p", "1.9", {"versionEndIncluding": "1.9"}, True),  # boundary incl
    ]
    ok = 0
    for cpe, ven, prod, ver, rng, exp in cases:
        got = cpe_matches(cpe, ven, prod, ver, rng)
        flag = "OK" if got == exp else "FAIL"
        ok += got == exp
        print(f"  [{flag}] {prod} {ver} rng={rng} -> {got} (want {exp})")
    print(f"cpe_match selftest: {ok}/{len(cases)} passed")
    return ok == len(cases)


if __name__ == "__main__":
    import sys
    sys.exit(0 if _selftest() else 1)
