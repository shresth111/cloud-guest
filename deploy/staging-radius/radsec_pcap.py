#!/usr/bin/env python3
"""STAGING ONLY. Read a tcpdump capture of RadSec (TCP 2083) and print what an
unknown RADIUS/TLS client did: the ClientHello (SNI, offered versions), the
TLS version and alerts the server sent, and -- because the listener is pinned
to TLS 1.2 during discovery, where the Certificate message is still cleartext --
the client's certificate chain. Each certificate is written to <outdir> as PEM
so it can be enrolled with radsec-map.sh (trust-add for its CA, add --cert for
the leaf).

  radsec_pcap.py <capture.pcap> <outdir> [port]

Stdlib only (the box has no tshark). Handles Ethernet, Linux SLL and SLL2
captures (`tcpdump -i any` writes SLL/SLL2), IPv4 and IPv6.
"""
import base64
import os
import struct
import subprocess
import sys

HS = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
      13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
      16: "ClientKeyExchange", 20: "Finished", 4: "NewSessionTicket", 8: "EncryptedExtensions"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
          45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
          49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
          112: "unrecognized_name", 116: "certificate_required", 120: "no_application_protocol"}
VER = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            e = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            e = ">"
        else:
            raise SystemExit("not a pcap file (pcapng is not supported: use tcpdump -w)")
        linktype = struct.unpack(e + "I", hdr[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts, _us, incl, _orig = struct.unpack(e + "IIII", rh)
            yield ts, linktype, f.read(incl)


def l3(linktype, frame):
    if linktype == 1:      # Ethernet
        et, off = struct.unpack("!H", frame[12:14])[0], 14
        while et == 0x8100:
            et, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        return et, frame[off:]
    if linktype == 113:    # Linux SLL
        return struct.unpack("!H", frame[14:16])[0], frame[16:]
    if linktype == 276:    # Linux SLL2
        return struct.unpack("!H", frame[0:2])[0], frame[20:]
    if linktype == 101:    # raw IP
        return (0x0800 if frame[0] >> 4 == 4 else 0x86DD), frame
    raise SystemExit(f"unsupported linktype {linktype}")


def tcp_segments(path, port):
    for ts, lt, fr in packets(path):
        et, p = l3(lt, fr)
        if et == 0x0800:
            ihl = (p[0] & 0x0F) * 4
            if p[9] != 6:
                continue
            src, dst = ".".join(map(str, p[12:16])), ".".join(map(str, p[16:20]))
            tot = struct.unpack("!H", p[2:4])[0]
            t = p[ihl:tot]
        elif et == 0x86DD:
            if p[6] != 6:
                continue
            import ipaddress
            src, dst = str(ipaddress.IPv6Address(p[8:24])), str(ipaddress.IPv6Address(p[24:40]))
            t = p[40:40 + struct.unpack("!H", p[4:6])[0]]
        else:
            continue
        sp, dp, seq = struct.unpack("!HHI", t[:8])
        off = (t[12] >> 4) * 4
        flags = t[13]
        if port not in (sp, dp):
            continue
        yield ts, (src, sp), (dst, dp), seq, flags, t[off:]


def streams(path, port):
    conns = {}
    for ts, a, b, seq, flags, data in tcp_segments(path, port):
        key = (a, b)
        c = conns.setdefault(key, {"first": ts, "isn": None, "segs": {}, "fin": False, "rst": False})
        if flags & 0x02:                       # SYN
            c["isn"] = seq + 1
        if flags & 0x01:
            c["fin"] = True
        if flags & 0x04:
            c["rst"] = True
        if data:
            c["segs"].setdefault(seq, data)
    out = {}
    for key, c in conns.items():
        if not c["segs"]:
            out[key] = (c, b"")
            continue
        base = c["isn"] if c["isn"] is not None else min(c["segs"])
        buf, nxt = bytearray(), base
        for s in sorted(c["segs"], key=lambda s: (s - base) & 0xFFFFFFFF):
            d = c["segs"][s]
            rel = (s - nxt) & 0xFFFFFFFF
            if rel > 0x7FFFFFFF:               # overlap/retransmission
                skip = (nxt - s) & 0xFFFFFFFF
                d = d[skip:] if skip < len(d) else b""
            elif rel != 0:                      # gap: stop, we cannot parse past it
                break
            buf += d
            nxt = (nxt + len(d)) & 0xFFFFFFFF
        out[key] = (c, bytes(buf))
    return out


def tls_records(buf):
    i = 0
    while i + 5 <= len(buf):
        ct, ver, ln = buf[i], struct.unpack("!H", buf[i + 1:i + 3])[0], struct.unpack("!H", buf[i + 3:i + 5])[0]
        yield ct, ver, buf[i + 5:i + 5 + ln]
        i += 5 + ln


def handshake_msgs(buf):
    hs = bytearray()
    for ct, _ver, frag in tls_records(buf):
        if ct == 20:            # ChangeCipherSpec: everything after is encrypted
            break
        if ct == 22:
            hs += frag
        if ct == 21 and len(frag) == 2:
            yield ("alert", frag)
    i = 0
    while i + 4 <= len(hs):
        t, ln = hs[i], int.from_bytes(hs[i + 1:i + 4], "big")
        yield (t, bytes(hs[i + 4:i + 4 + ln]))
        i += 4 + ln


def client_hello(body):
    info = {"legacy_version": VER.get(struct.unpack("!H", body[:2])[0], body[:2].hex())}
    p = 34
    p += 1 + body[p]
    cs = struct.unpack("!H", body[p:p + 2])[0]
    info["cipher_suites"] = cs // 2
    p += 2 + cs
    p += 1 + body[p]
    if p + 2 > len(body):
        return info
    end = p + 2 + struct.unpack("!H", body[p:p + 2])[0]
    p += 2
    while p + 4 <= end:
        et, el = struct.unpack("!HH", body[p:p + 4])
        ed = body[p + 4:p + 4 + el]
        if et == 0 and len(ed) > 5:
            info["sni"] = ed[5:5 + struct.unpack("!H", ed[3:5])[0]].decode(errors="replace")
        elif et == 43 and ed:
            info["supported_versions"] = [VER.get(struct.unpack("!H", ed[1 + k:3 + k])[0], "?")
                                          for k in range(0, ed[0], 2)]
        elif et == 13:
            info["sig_algs"] = len(ed) // 2 - 1
        p += 4 + el
    return info


def certs_from(body, tls13=False):
    p = 0
    if tls13:
        p = 1 + body[0]
    total = int.from_bytes(body[p:p + 3], "big")
    p += 3
    end = p + total
    out = []
    while p + 3 <= end:
        ln = int.from_bytes(body[p:p + 3], "big")
        out.append(body[p + 3:p + 3 + ln])
        p += 3 + ln
        if tls13:
            p += 2 + struct.unpack("!H", body[p:p + 2])[0]
    return out


def describe(der, path):
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
        base64.b64encode(der).decode()[i:i + 64] for i in range(0, len(base64.b64encode(der)), 64)) + \
        "\n-----END CERTIFICATE-----\n"
    with open(path, "w") as f:
        f.write(pem)
    r = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-nameopt", "compat", "-subject", "-issuer",
                        "-serial", "-dates", "-fingerprint", "-sha256", "-ext",
                        "subjectAltName,extendedKeyUsage,basicConstraints"], capture_output=True, text=True)
    return r.stdout.strip()


def main():
    path, outdir = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 2083
    os.makedirs(outdir, exist_ok=True)
    st = streams(path, port)
    clients = sorted({k for k in st if k[1][1] == port}, key=lambda k: st[k][0]["first"])
    if not clients:
        print(f"no TCP connections to port {port} in {path}")
    for n, ck in enumerate(clients, 1):
        cinfo, cbuf = st[ck]
        sk = (ck[1], ck[0])
        sinfo, sbuf = st.get(sk, ({"rst": False, "fin": False}, b""))
        print(f"\n=== connection {n}: {ck[0][0]}:{ck[0][1]} -> {ck[1][0]}:{ck[1][1]}"
              f"  client->server {len(cbuf)} B, server->client {len(sbuf)} B"
              f"{'  (RST)' if cinfo['rst'] or sinfo['rst'] else ''}")
        if cbuf and cbuf[0] != 22:
            print(f"  client did not speak TLS (first byte 0x{cbuf[0]:02x}: plain RADIUS/TCP or something else)")
            continue
        server_ver = None
        for t, body in handshake_msgs(sbuf):
            if t == "alert":
                print(f"  server ALERT level={body[0]} {ALERTS.get(body[1], body[1])}")
            elif t == 2:
                v = struct.unpack("!H", body[:2])[0]
                server_ver = VER.get(v, hex(v))
                print(f"  ServerHello {server_ver}")
            elif t == 13:
                print("  server sent CertificateRequest (client certificate required)")
        for t, body in handshake_msgs(cbuf):
            if t == "alert":
                print(f"  client ALERT level={body[0]} {ALERTS.get(body[1], body[1])}"
                      "  <- e.g. 48 unknown_ca / 42 bad_certificate = it rejected OUR server certificate")
            elif t == 1:
                print(f"  ClientHello {client_hello(body)}")
            elif t == 11:
                chain = certs_from(body)
                if not chain:
                    print("  client sent an EMPTY Certificate message: it has no client certificate to offer")
                for i, der in enumerate(chain):
                    p = os.path.join(outdir, f"conn{n}-cert{i}.pem")
                    print(f"  client certificate [{i}] -> {p}")
                    for ln in describe(der, p).splitlines():
                        print(f"      {ln}")
            elif t == 16:
                print("  ClientKeyExchange")
        if sbuf and server_ver == "TLS1.2" and not any(ct == 20 for ct, _v, _f in tls_records(sbuf)):
            print("  server ended the handshake before ChangeCipherSpec: it REJECTED the client "
                  "(certificate not trusted / missing) -- see the radsec container log for the reason")
        elif server_ver == "TLS1.2":
            print("  handshake completed; the RADIUS verdict is in connections.log (radsec-connection lines)")
        if server_ver == "TLS1.3":
            print("  (TLS 1.3: the client certificate is encrypted; set RADSEC_TLS_MAX=1.2 to see it)")


if __name__ == "__main__":
    main()
