#!/usr/bin/env python3
"""Build-time only: splice backend/ops/freeradius/sites-default.snippets.conf
into the image's stock sites-available/default at the same points as the prod
hub (authorize -> right after `preprocess`, accounting -> right after
`detail`; verified against the live hub 2026-10-02), and point rest.conf's
connect_uri at $ENV{WYFY_RADIUS_API_URI} so the target API is set per
deployment, never baked in. Same logic as ~/wyfy-ops/aruba-ap21/radius-harness.
"""
import os
import re
import sys

root = sys.argv[1]
out = os.path.join(root, "out")
os.makedirs(out, exist_ok=True)


def read(name):
    with open(os.path.join(root, name)) as f:
        return f.read()


def top_block_body(text, name):
    lines = text.split("\n")
    for i, ln in enumerate(lines):
        if re.match(rf"^{name}\s*\{{", ln):
            depth, body = 0, []
            for j in range(i, len(lines)):
                code = lines[j].split("#", 1)[0]
                depth += code.count("{") - code.count("}")
                if j > i:
                    if depth == 0:
                        return body
                    body.append(lines[j])
            raise SystemExit(f"unterminated {name} block")
    raise SystemExit(f"no top-level {name} block")


def insert_after(text, section, anchor_re, insertion):
    lines = text.split("\n")
    in_sec, depth = False, 0
    for i, ln in enumerate(lines):
        if not in_sec and re.match(rf"^{section}\s*\{{", ln):
            in_sec, depth = True, 0
        if in_sec:
            code = ln.split("#", 1)[0]
            depth += code.count("{") - code.count("}")
            if depth == 1 and re.match(anchor_re, ln):
                return "\n".join(lines[: i + 1] + insertion + lines[i + 1 :])
            if depth == 0 and i > 0 and "}" in code:
                break
    raise SystemExit(f"anchor {anchor_re!r} not found in {section}")


snip = read("snippets.conf")
site = read("stock-default")
site = insert_after(site, "authorize", r"^\s*preprocess\s*$",
                    ["\t# --- wyfy (backend/ops/freeradius snippets) ---"] + top_block_body(snip, "authorize"))
site = insert_after(site, "accounting", r"^\s*detail\s*$",
                    ["\t# --- wyfy (backend/ops/freeradius snippets) ---"] + top_block_body(snip, "accounting"))
with open(os.path.join(out, "default"), "w") as f:
    f.write(site)

rest, n = re.subn(r'connect_uri\s*=\s*"[^"]*"', 'connect_uri = "$ENV{WYFY_RADIUS_API_URI}"', read("rest.conf"))
if n != 1:
    raise SystemExit("connect_uri not found exactly once in rest.conf")
with open(os.path.join(out, "rest"), "w") as f:
    f.write(rest)
print("gen_site: default + rest written")
