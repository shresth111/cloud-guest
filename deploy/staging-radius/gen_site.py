#!/usr/bin/env python3
"""Build-time only: splice backend/ops/freeradius/sites-default.snippets.conf
into the image's stock sites-available/default at the same points as the prod
hub (authorize -> right after `preprocess`, accounting -> right after
`detail`; verified against the live hub 2026-10-02), and point rest.conf's
connect_uri at $ENV{WYFY_RADIUS_API_URI} so the target API is set per
deployment, never baked in. Same logic as ~/wyfy-ops/aruba-ap21/radius-harness.

`gen_site.py <dir> radsec` additionally writes out/radsec: the same spliced
site renamed `server radsec`, for the RadSec (TCP/TLS 2083) listener. A RadSec
client is matched by a catch-all `clients radsec` entry (its source address
says nothing about which venue it is), so the per-NAS identity cannot come from
%{client:...}. Instead `wyfy_radsec_new_connection` (radsec/wyfy_radsec.policy)
maps the client certificate to a NAS once per TLS connection, and every request
on that connection reads it back into control:Tmp-String-8/9. The header lines
are the only lines that differ from the UDP site.
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


def drop_listen_blocks(text):
    """Remove the stock `listen { ... }` blocks inside `server ... {`: the
    RadSec listener is defined once, in radsec/listen-radsec.conf."""
    lines, out, depth, skip = text.split("\n"), [], 0, None
    for ln in lines:
        code = ln.split("#", 1)[0]
        if skip is None and depth == 1 and re.match(r"^\s*listen\s*\{", ln):
            skip = depth
        if skip is None:
            out.append(ln)
        depth += code.count("{") - code.count("}")
        if skip is not None and depth == skip:
            skip = None
    return "\n".join(out)


def must_sub(pattern, repl, text, count):
    new, n = re.subn(pattern, repl, text)
    if n != count:
        raise SystemExit(f"radsec: expected {count} x {pattern!r}, found {n}")
    return new


if len(sys.argv) > 2 and sys.argv[2] == "radsec":
    rs = must_sub(r"(?m)^server default \{", "server radsec {", site, 1)
    rs = drop_listen_blocks(rs)
    if re.search(r"(?m)^\s*listen\s*\{", rs):
        raise SystemExit("radsec: a listen block survived")
    rs = must_sub(r"%\{client:shortname\}", "%{control:Tmp-String-8}", rs, 2)
    rs = must_sub(r"%\{client:backend_secret\}", "%{control:Tmp-String-9}", rs, 2)
    if "%{client:" in rs:
        raise SystemExit("radsec: a %{client:...} reference is left")
    # Every request on a RadSec connection: identify first, or reject.
    rs = must_sub(r"(?m)^(authorize \{)$", "\\1\n\twyfy_radsec_identify", rs, 1)
    rs = must_sub(r"(?m)^(accounting \{)$", "\\1\n\twyfy_radsec_identify", rs, 1)
    rs = must_sub(r"(?ms)^(\tAutz-Type New-TLS-Connection \{\n)\s*ok\n(\t\})",
                  "\\1\t\twyfy_radsec_new_connection\n\\2", rs, 1)
    with open(os.path.join(out, "radsec"), "w") as f:
        f.write(rs)
    print("gen_site: radsec written")
