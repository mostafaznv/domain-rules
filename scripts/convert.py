#!/usr/bin/env python3
"""
Convert selected lists from v2fly/domain-list-community into:
  - Clash domain RULE-SETs  (*.yaml)
  - One Shadowrocket .conf  (shadowrocket.conf)

Correctly handles include: ... @attr / @-attr filtering and brand TLDs.
"""

import requests
from pathlib import Path
from collections import OrderedDict
from typing import List, Set, Tuple, Optional, Dict
from datetime import datetime, timezone

BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

# ------------------------------------------------------------
# Configure what you want to generate
# name → (list of source files, Shadowrocket policy)
# ------------------------------------------------------------
TARGETS: Dict[str, Tuple[List[str], str]] = {
    "apple": (
        ["apple"],
        "DIRECT",
    ),
    "iran": (
        ["category-ir"],
        "DIRECT",
    ),
    "ads": (
        ["category-ads-all"],
        "REJECT",
    ),
}

# ------------------------------------------------------------
# Shadowrocket [General] defaults – edit as you like
# ------------------------------------------------------------
GENERAL = """\
[General]
bypass-system = true
skip-proxy = 127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com, *.apple.com, *.icloud.com, *.icloud-content.com
tun-excluded-routes = 100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,255.255.255.255/32
dns-server = 1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,208.67.222.222,208.67.220.220
fallback-dns-server = system
ipv6 = false
prefer-ipv6 = false
dns-direct-system = true
icmp-auto-reply = true
# update-url will be filled automatically if you host the file

[Host]
localhost = 127.0.0.1
"""

FINAL_RULE = """\
DOMAIN-SUFFIX,ir,DIRECT
IP-CIDR,192.168.0.0/16,DIRECT
IP-CIDR,172.16.0.0/12,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT
GEOIP,IR,DIRECT
FINAL,PROXY
"""


def fetch(name: str) -> str:
    url = BASE + name
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text


def parse_attrs(tokens: List[str]) -> Tuple[Set[str], Set[str]]:
    must, ban = set(), set()
    for t in tokens:
        if not t.startswith("@"):
            continue
        attr = t[1:]
        if attr.startswith("-") or attr.startswith("!"):
            ban.add(attr[1:])
        else:
            must.add(attr)
    return must, ban


def rule_matches(rule_attrs: Set[str], must: Set[str], ban: Set[str]) -> bool:
    if must and not must.issubset(rule_attrs):
        return False
    if ban and ban.intersection(rule_attrs):
        return False
    if must and not rule_attrs:
        return False
    return True


def parse(
    content: str,
    seen: Set[str],
    must_attrs: Optional[Set[str]] = None,
    ban_attrs: Optional[Set[str]] = None,
) -> List[Tuple[str, str]]:
    if must_attrs is None:
        must_attrs = set()
    if ban_attrs is None:
        ban_attrs = set()

    rules = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("include:"):
            rest = line[8:].strip()
            parts = rest.split()
            include_name = parts[0]
            child_must, child_ban = parse_attrs(parts[1:])

            combined_must = must_attrs | child_must
            combined_ban = ban_attrs | child_ban

            key = f"{include_name}|{sorted(combined_must)}|{sorted(combined_ban)}"
            if key in seen:
                continue
            seen.add(key)

            try:
                child_content = fetch(include_name)
                rules.extend(parse(child_content, seen, combined_must, combined_ban))
            except Exception as e:
                print(f"  Warning: cannot fetch {include_name}: {e}")
            continue

        tokens = line.split()
        first = tokens[0]
        attrs = {t[1:] for t in tokens[1:] if t.startswith("@")}

        if not rule_matches(attrs, must_attrs, ban_attrs):
            continue

        if first.startswith("full:"):
            rules.append(("full", first[5:]))
        elif first.startswith("keyword:"):
            rules.append(("keyword", first[8:]))
        elif first.startswith("regexp:"):
            rules.append(("regexp", first[7:]))
        elif first.startswith("domain:"):
            rules.append(("domain", first[7:]))
        else:
            domain = first
            if domain and ("." in domain or domain.isalpha()):
                rules.append(("domain", domain))

    return rules


def generate_one(name: str, sources: List[str]) -> List[Tuple[str, str]]:
    print(f"\n=== Generating {name} ===")
    seen: Set[str] = set()
    all_rules: List[Tuple[str, str]] = []

    for src in sources:
        print(f"  Processing {src} ...")
        content = fetch(src)
        all_rules.extend(parse(content, seen))

    # Deduplicate
    unique = OrderedDict()
    for typ, val in all_rules:
        key = (typ, val.lower())
        if key not in unique:
            unique[key] = (typ, val)

    # ----- Clash YAML -----
    lines = ["payload:"]
    for typ, val in unique.values():
        if typ == "full":
            lines.append(f"  - '{val}'")
        elif typ == "domain":
            lines.append(f"  - '+.{val}'")
        else:
            lines.append(f"  # unsupported {typ}: {val}")

    Path(f"clash-{name}.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  → clash-{name}.yaml  ({len(unique)} entries)")

    return list(unique.values())


def generate_shadowrocket(results: Dict[str, Tuple[List[Tuple[str, str]], str]]) -> None:
    """Build a complete shadowrocket.conf"""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    conf = []
    conf.append(f"# Generated on {now}")
    conf.append("# Source: v2fly/domain-list-community")
    conf.append("")
    conf.append(GENERAL.strip())
    conf.append("")
    conf.append("[Rule]")
    conf.append("# ---------- Auto-generated rules ----------")

    # Order matters: more specific / important first
    # We put REJECT (ads) first, then DIRECT categories, then others
    order = sorted(
        results.keys(),
        key=lambda k: (0 if results[k][1] == "REJECT" else 1 if results[k][1] == "DIRECT" else 2, k)
    )

    for name in order:
        rules, policy = results[name]
        conf.append(f"")
        conf.append(f"# ===== {name} → {policy} =====")
        for typ, val in rules:
            if typ == "full":
                conf.append(f"DOMAIN,{val},{policy}")
            elif typ == "domain":
                conf.append(f"DOMAIN-SUFFIX,{val},{policy}")
            # keyword / regexp are skipped (or you can add DOMAIN-KEYWORD if you want)

    conf.append("")
    conf.append("# ---------- Final fallback ----------")
    conf.append(FINAL_RULE)
    conf.append("")

    Path("shadowrocket.conf").write_text("\n".join(conf), encoding="utf-8")
    print(f"\n→ shadowrocket.conf generated")


def main():
    results: Dict[str, Tuple[List[Tuple[str, str]], str]] = {}

    for name, (sources, policy) in TARGETS.items():
        rules = generate_one(name, sources)
        results[name] = (rules, policy)

    generate_shadowrocket(results)


if __name__ == "__main__":
    main()