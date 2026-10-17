#!/usr/bin/env python3
"""Local WiFi configuration tool for Haier KZW-W002 air-conditioner WiFi modules.

A KZW-W002 module (sold under Haier, Candy, Hoover, and rebrands such as Thermor /
Atlantic / Sauter "Nagano") that has lost its WiFi credentials falls back to a SoftAP:
it broadcasts an OPEN network whose SSID contains "U-AC", "U-AIC" or "Haier-uAC".
In that mode the module listens on TCP 192.168.0.1:56797 and accepts a "set parameter"
command that hands it the SSID and password of the network to join. This tool speaks
that protocol directly, so you can re-pair a module to the WiFi you want without the
vendor app and without any cloud account.

The protocol was reverse-engineered from the official Android apps; see PROTOCOL.md.
No dependencies: standard library only, Python 3.8+.

    python3 haier_kzw_w002.py scan                      # find the module's open network
    python3 haier_kzw_w002.py info                       # read the module (read-only)
    python3 haier_kzw_w002.py config --ssid "MyWiFi"     # password is prompted
    python3 haier_kzw_w002.py find --mac 2C37C5502A4A    # locate it after it reconnects

Connect your computer to the module's open WiFi first (and only that network: no wired
link to a 192.168.0.x LAN).
"""

import argparse
import getpass
import ipaddress
import random
import shutil
import socket
import struct
import subprocess
import sys

HOST = "192.168.0.1"
PORT = 56797

# Command codes carried in the 16-byte header (see PROTOCOL.md).
CMD_GET = 26001       # read parameters / AP list
CMD_GET_ACK = 26002
CMD_SET = 26003       # "plain" config: 652-byte struct, cleartext password
CMD_SET_TLV = 26015   # "secure" config: TLV, password masked by XOR
CMD_SET_ACK = 26004   # reply to both 26003 and 26015

GET_FIXED_LEN = 0x11C     # fixed part of the 26002 reply; the AP list follows
AP_ENTRY_LEN = 36
SET_BODY_LEN = 652
OFF_TYPEID, OFF_SSID, OFF_PASSWORD = 0x40, 0x120, 0x140

# Cloud gateway Smart Clima passes in secure mode (domain + port). Point --domain at an
# unreachable host to keep the module off the vendor cloud.
VENDOR_GATEWAY = "gw.haieriot.net:56808"

SOFTAP_SSID_MARKERS = ("Haier-uAC", "U-AC", "U-AIC")
# Encryption codes seen in the AP list. Firmware 2.18 does not follow the app's own enum,
# so unknown values are shown as-is rather than guessed.
ENCRYPTION = {0: "open", 1: "open", 2: "WEP", 3: "WPA/WPA2"}

# 1024-byte table used by uplus_get_code_key (identical in Smart Clima and HaierSmartAir2).
KEY_TABLE = bytes.fromhex(
    "3375e0f536b30d2bc5f9696956071af6c8def75b104f57a327985b6f5d0f663df6495e20b12cd7d6996adefd58546a47"
    "d5f83972207f9d773f3dfe1756f00f432b1a7d1b95daab645a6d9b3ce201b2f3048a7c4a977883f6ab357c409c71c080"
    "3f34f4e7fd0f3b5813fad91533d3bac39fd4a0e50c1c07ca1a28f61fb42acd1dd84d4b8c793bce7d076fa77fa739dfc1"
    "a5f9594e06ee39dde723676c91d89d8750f95e938a7641e22a8765f6cc41103d49042b0e839a3fe0a39919e420dea871"
    "b235de8828fc805927e74b79d29fd1c971df7235f4ead148915f2b49bc43fe4e3fdcd0fdbeab12f6db99e08952acbc3e"
    "b7db5f573f51becb292e935e39afc1d86b330f8a2c078b97d885842e5663fcb56baef00c3ce1676815a3976ddc71a78c"
    "de5f444743349857637ce77260e5538e0f6e81ef385741dc35c154c1e0fb7a2c776bf1d1cb00f71af63212e3e1f413ec"
    "d81aba21f38c55ad9d6c392df3e21abcc4c5ec4a0157fe83be3cda1545f925b8b2909ac3a504bfa395ed8a03b6e17606"
    "0c41de59904f13819d18711e6602851bbc96f38075e1344b99f2de1dc0551795449342a69e9daf3f2824579893ba4505"
    "48d2ee81006ef5f3560f24579b4196bd9bd6ea5f421de42f292462a392f908a9dbd405f7d7975fb132b4979344492213"
    "f20bfab607cc55891d3fbce11bb6857eb10b0596fe6e5cddc3bfceb52e39fd6edc906c6269ce3945378062f8d70c0cbe"
    "3a4a1214f2277012d56bb0a5befdfd6d23af0b9a5fecd923dad7a6156abb796b164ca42e9c1b2fb1e85b7851d0a90ef0"
    "c211791e4e8e18a422982f6366a843c69caa84a35fc6c1de3192382831f0ab1e6a45aaad91446810daf97518d3daf1d7"
    "576751378f4ce68293fc51202230e85d01bc698f78c04e6e07984869ae7ea0e987e67f31f56eeec72ee67c305a63eddc"
    "1dced00e46dae88edbf1471166e2818c1c72d3de50173f204f01c5d682adf20e8cb5d0f5b18ee50342e96a4e5ffbd691"
    "bd34ea0dce54d03efae18c133ad4c6254f8fb018e47887a2d849f9e372e1f99046be32121755b01ce802846b14c14c1c"
    "99de87cc00dc2685703a9498ead0d66544846cc342ee81f383be36671482f82fd38ac36a96a3ad8b0ecb2b3689296daf"
    "7b60b07ddc9c7747ea5a7c93b44957601c5c2451add61d55ecf2050d00ecd351e08b6a20e7f85c5a7379870164ec0774"
    "41823ee0c1a306caf8843a6df84530f19ea9578f59448cb4a3265ac306e5b77449907a01c2df119454be393010fe3f7c"
    "94bd0bb21565f9a2374e4ef4ed53b12d6a7c171a9080fa22d44044afd30952a055afebf484e42ab31e410e31e6f5ceb0"
    "149f239985211125838b7149c9f5cbd026cc3546ec6e363d7bb6991930b4fb54643a04716a00b5139d08a9e06a00a6c4"
    "83c4741b97544b56a6c5c4d1f9193e30"
)
assert len(KEY_TABLE) == 1024


class ProtocolError(Exception):
    pass


# --- Encoding -------------------------------------------------------------------------


def frame(cmd, body=b"", sn=0):
    # 16-byte big-endian header: cmd u32, two u16 zeros, sn u32, body length u32.
    return struct.pack(">IHHII", cmd, 0, 0, sn, len(body)) + body


def crc16_arc(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def uplus_xor(data, key_index):
    # uplus_get_code_key + uplus_get_encode_data: key of (key_index >> 11) + 1 bytes read
    # from KEY_TABLE starting at key_index & 0x7ff (wrapped at 1024). Symmetric.
    start, n = key_index & 0x7FF, (key_index >> 11) + 1
    key = bytes(KEY_TABLE[(start + i) & 0x3FF] for i in range(n))
    return bytes(b ^ key[i % n] for i, b in enumerate(data))


def build_plain_body(type_id, ssid, password):
    """26003 body, as the native usdk_json2devconf builds it: only typeId/SSID/password."""
    body = bytearray(SET_BODY_LEN)
    body[OFF_TYPEID:OFF_TYPEID + 32] = type_id[:32].ljust(32, b"\0")
    s, p = ssid.encode()[:32], password.encode()[:64]
    body[OFF_SSID:OFF_SSID + len(s)] = s
    body[OFF_PASSWORD:OFF_PASSWORD + len(p)] = p
    return bytes(body)


def build_tlv_body(ssid, password, domain=None, country=None, key_index=None):
    """26015 body, as the native cae_su_codec_softAp_setParam_tlv builds it."""
    if key_index is None:
        key_index = random.randrange(0x10000)
    s = ssid.encode()[:32]
    # The app leaves 4 uninitialised bytes before the encrypted password; they only feed
    # the CRC. We send zeros.
    pwd = (bytes(4) + uplus_xor(password.encode(), key_index))[:68]
    crc = crc16_arc(pwd)
    key_field = bytes([(key_index >> 8) ^ (crc & 0xFF), (key_index & 0xFF) ^ (crc >> 8)])
    body = bytes([2, len(s)]) + s + bytes([3, len(pwd)]) + pwd + bytes([1, 2]) + key_field
    if domain:
        d = domain.encode()[:64]
        body += bytes([7, len(d)]) + d
    if country:
        c = country.encode()[:2]
        body += bytes([8, len(c)]) + c
    return body


# --- Decoding -------------------------------------------------------------------------


def cstr(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def parse_get_body(body):
    """26002 reply, per usdk_json_devstate_ack."""
    if len(body) < GET_FIXED_LEN:
        raise ProtocolError(f"26002 reply too short ({len(body)} bytes)")
    (err,) = struct.unpack_from(">I", body, 0)
    (ap_num,) = struct.unpack_from(">I", body, 0x58)
    aps = []
    for i in range(ap_num):
        off = GET_FIXED_LEN + i * AP_ENTRY_LEN
        if off + AP_ENTRY_LEN > len(body):
            break
        enc, power = struct.unpack_from(">HH", body, off + 32)
        aps.append({"ssid": cstr(body[off:off + 32]), "encryption": enc, "power": power})
    return {
        "err": err,
        "type_id": body[4:36],
        "mac": cstr(body[0x28:0x38]),
        "ip": cstr(body[0x38:0x48]),
        "protocol": cstr(body[0x48:0x58]),
        "room": cstr(body[0x9C:0xDC]),
        "password_len": len(cstr(body[0xDC:0x11C])),
        "aps": aps,
        "raw": body,
    }


# --- Networking -----------------------------------------------------------------------


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError(f"connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def get_extra_len(body):
    # usdk_get_uwt_para: if the module announces exactly 0x11C bytes, the AP list follows
    # outside the declared length.
    if len(body) == GET_FIXED_LEN:
        (ap_num,) = struct.unpack_from(">I", body, 0x58)
        return ap_num * AP_ENTRY_LEN
    return 0


def transact(host, port, data, expect_cmd, timeout, extra=None):
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(data)
        cmd, _, _, _, length = struct.unpack(">IHHII", recv_exact(sock, 16))
        if cmd != expect_cmd:
            raise ProtocolError(f"got command {cmd}, expected {expect_cmd}")
        body = recv_exact(sock, length) if length else b""
        if extra:
            body += recv_exact(sock, extra(body))
    return body


def read_device(args):
    body = transact(args.host, args.port, frame(CMD_GET), CMD_GET_ACK, args.timeout, get_extra_len)
    info = parse_get_body(body)
    if info["err"]:
        raise ProtocolError(f"module returned error {info['err']} to the read command")
    return info


# --- WiFi / LAN helpers (Linux: nmcli / iproute2) -------------------------------------


def current_wifi_ssid():
    if shutil.which("nmcli"):
        out = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if line.startswith("yes:"):
                return line[4:]
    if shutil.which("iwgetid"):
        return subprocess.run(["iwgetid", "-r"], capture_output=True, text=True).stdout.strip() or None
    return None


def check_on_softap(args):
    """Refuse to talk to 192.168.0.1 unless the host is on a module's SoftAP, so this can
    never accidentally reconfigure a module that is already on your real network."""
    if args.force or args.host != HOST:
        return
    ssid = current_wifi_ssid()
    if ssid and any(m in ssid for m in SOFTAP_SSID_MARKERS):
        print(f"Current WiFi: {ssid} (module SoftAP)")
        return
    if ssid:
        sys.exit(f"This host is on '{ssid}', not a Haier module's open network "
                 f"({', '.join(SOFTAP_SSID_MARKERS)}). Aborting. (use --force to override)")
    sys.exit("Could not read the current WiFi SSID (no nmcli or iwgetid). Make sure you are "
             "on the module's open network, then re-run with --force.")


def has_carrier(iface):
    # Virtual bridges (virbr0, docker0...) can be admin-up with no carrier and no real LAN
    # behind them; skip those so we don't sweep dead subnets.
    try:
        with open(f"/sys/class/net/{iface}/carrier") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return True  # unknown: keep it rather than silently drop a real interface


def active_ipv4_ifaces():
    """[(iface, ip, prefixlen), ...] for up, carrier-bearing, non-loopback IPv4 interfaces."""
    if not shutil.which("ip"):
        return []
    out = subprocess.run(["ip", "-o", "-4", "addr", "show", "up"], capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 4 and f[1] != "lo" and "/" in f[3] and has_carrier(f[1]):
            ip, prefix = f[3].split("/")
            res.append((f[1], ip, int(prefix)))
    return res


def arp_entries():
    """{mac_lower: [(ip, state), ...]} from `ip neigh`. A MAC can appear several times
    (one per interface, and stale entries for IPs it used to hold), so callers must verify."""
    table = {}
    if shutil.which("ip"):
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            f = line.split()
            if len(f) >= 5 and f[3] == "lladdr":
                table.setdefault(f[4].lower(), []).append((f[0], f[-1]))
    return table


def ping_host(ip, count=1):
    # No -I: let the kernel route. On a host with two interfaces on the same subnet,
    # forcing an interface can wrongly fail.
    return subprocess.run(["ping", "-c", str(count), "-W1", str(ip)],
                          capture_output=True).returncode == 0


def ping_sweep(network):
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=64) as pool:
        list(pool.map(ping_host, network.hosts()))


def tcp_open(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


# --- Commands -------------------------------------------------------------------------


def print_info(info, raw=False):
    print(f"MAC           : {info['mac']}  ({len(info['mac'])} chars)")
    print(f"IP            : {info['ip']}")
    print(f"Protocol ver. : {info['protocol']!r}")
    print(f"typeId        : {info['type_id'].hex()}")
    print(f"Room name     : {info['room']!r}")
    print(f"Stored pwd    : {info['password_len']} chars")
    print(f"Networks the module can see ({len(info['aps'])}):")
    for ap in sorted(info["aps"], key=lambda a: -a["power"]):
        enc = ENCRYPTION.get(ap["encryption"], f"type {ap['encryption']}")
        print(f"  {ap['power']:4d}  {enc:9s}  {ap['ssid']}")
    if raw:
        r = info["raw"]
        print(f"\nRaw 26002 reply ({len(r)} bytes):")
        for off in range(0, GET_FIXED_LEN, 16):
            print(f"  {off:04x}  {r[off:min(off + 16, GET_FIXED_LEN)].hex(' ')}")
        for off in range(GET_FIXED_LEN, len(r), AP_ENTRY_LEN):
            print(f"  {off:04x}  {r[off:off + 32].hex(' ')} | {r[off + 32:off + 36].hex(' ')}")


def cmd_info(args):
    check_on_softap(args)
    print_info(read_device(args), raw=args.raw)


def cmd_config(args):
    check_on_softap(args)
    info = read_device(args)
    print_info(info)

    mode = args.mode
    if mode == "auto":
        # Smart Clima's rule (DeviceManager.configDeviceBySoftApConfig): secure if the MAC
        # is 16 chars, plain otherwise. SmartAir2 always uses plain.
        mode = "secure" if len(info["mac"]) == 16 else "plain"
    print(f"\nMode: {mode}")

    if not any(ap["ssid"] == args.ssid for ap in info["aps"]):
        print(f"WARNING: '{args.ssid}' is not in the list of networks the module sees "
              "(5 GHz only? hidden SSID? too far?).")
    if len(args.ssid.encode()) > 32:
        sys.exit("SSID too long (32 bytes max).")

    password = args.password if args.password is not None else getpass.getpass(
        f"WiFi password for '{args.ssid}': ")
    if len(password.encode()) > 63:
        sys.exit("Password too long (63 chars max for WPA2).")

    if mode == "plain":
        data = frame(CMD_SET, build_plain_body(info["type_id"], args.ssid, password))
    else:
        data = frame(CMD_SET_TLV, build_tlv_body(args.ssid, password, args.domain, args.country))

    if args.dry_run:
        print(f"[dry-run] {len(data)} bytes, not sent:\n{data.hex()}")
        return
    if input(f"Send '{args.ssid}' to module {info['mac']}? [y/N] ").strip().lower() not in ("y", "yes"):
        sys.exit("Cancelled.")

    body = transact(args.host, args.port, data, CMD_SET_ACK, args.timeout)
    err = struct.unpack_from(">I", body, 0)[0] if len(body) >= 4 else None
    if err != 0:
        sys.exit(f"Failed: module returned error {err}. Try the other --mode.")
    print(f"OK: the module accepted the configuration and will join '{args.ssid}'.\n"
          f"Reconnect this host to '{args.ssid}', then locate the module with:\n"
          f"  python3 {sys.argv[0]} find --mac {info['mac']}\n"
          f"MAC for the Home Assistant integration: {info['mac']}")


def cmd_scan(args):
    if not shutil.which("nmcli"):
        sys.exit("scan needs nmcli (NetworkManager). List WiFi yourself and connect to the "
                 f"open network whose name contains {', '.join(SOFTAP_SSID_MARKERS)}.")
    subprocess.run(["nmcli", "dev", "wifi", "rescan"], capture_output=True)
    out = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
                         capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        # nmcli -t escapes ':' in the BSSID as '\:'
        parts = line.replace("\\:", "§").split(":")
        ssid = parts[0].replace("§", ":")
        if any(m in ssid for m in SOFTAP_SSID_MARKERS) and ssid not in [f[0] for f in found]:
            found.append((ssid, line.replace("§", ":")))
    if not found:
        sys.exit("No Haier module SoftAP found. Put a module into pairing mode and retry.")
    print("Module SoftAP networks found:")
    for ssid, _ in found:
        print(f"  {ssid}")
    if args.connect:
        ssid = found[0][0]
        print(f"Connecting to '{ssid}' ...")
        r = subprocess.run(["nmcli", "dev", "wifi", "connect", ssid], capture_output=True, text=True)
        print((r.stdout + r.stderr).strip())


def cmd_find(args):
    mac = args.mac.lower().replace("-", "").replace(":", "")
    mac_colon = ":".join(mac[i:i + 2] for i in range(0, len(mac), 2))
    ifaces = active_ipv4_ifaces()
    if not ifaces:
        sys.exit("find needs iproute2 (`ip`). Look the module up in your router's DHCP list "
                 f"(MAC {mac_colon}).")
    # Always sweep fresh: a cached ARP entry may point at an IP the module no longer holds
    # (e.g. after a DHCP lease change), which would make us report a dead address.
    nets = {ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            for _, ip, prefix in ifaces}
    for net in sorted(nets, key=str):
        if net.num_addresses <= 1024:
            print(f"Sweeping {net} ...")
            ping_sweep(net)
    # Candidate IPs for this MAC, REACHABLE first; only keep one that actually answers now.
    cands = sorted(arp_entries().get(mac_colon, []),
                   key=lambda e: 0 if e[1] == "REACHABLE" else 1)
    ip = next((cip for cip, _ in cands if ping_host(cip, count=2)), None)
    if not ip:
        extra = f" (stale cache points at {', '.join(c for c, _ in cands)})" if cands else ""
        sys.exit(f"Module {mac_colon} not reachable on the local subnets{extra}. It may still "
                 "be connecting or asleep; retry shortly, or check the router's DHCP list.")
    port_ok = any(tcp_open(ip, 56800) for _ in range(3))
    print(f"Module {mac_colon} is at {ip}")
    if port_ok:
        print("  TCP 56800 (local control): open")
    else:
        print("  TCP 56800 (local control): no response right now (module may be asleep; "
              "it usually answers on demand — Home Assistant retries)")
    print(f"\nHome Assistant (ddnlv/haier-kzw-w002-local): IP {ip}, MAC {mac}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default=HOST, help=f"module address in SoftAP mode (default {HOST})")
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--timeout", type=float, default=15)
    p.add_argument("--force", action="store_true", help="skip the SoftAP-SSID safety check")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="find a module's open SoftAP network (needs nmcli)")
    s.add_argument("--connect", action="store_true", help="connect to the first one found")
    s.set_defaults(func=cmd_scan)

    i = sub.add_parser("info", help="read the module's parameters (read-only)")
    i.add_argument("--raw", action="store_true", help="also dump the raw reply in hex")
    i.set_defaults(func=cmd_info)

    c = sub.add_parser("config", help="send the SSID + password of the network to join")
    c.add_argument("--ssid", required=True)
    c.add_argument("--password", help="discouraged (shell history); prompted otherwise")
    c.add_argument("--mode", choices=("auto", "plain", "secure"), default="auto",
                   help="auto = like Smart Clima: secure if the MAC is 16 chars, else plain")
    c.add_argument("--domain", default=VENDOR_GATEWAY,
                   help="secure mode only: cloud gateway host:port (point it at an unreachable "
                        "host to keep the module off the vendor cloud)")
    c.add_argument("--country", help="secure mode only (2 letters)")
    c.add_argument("--dry-run", action="store_true", help="read the module and print the frame, send nothing")
    c.set_defaults(func=cmd_config)

    f = sub.add_parser("find", help="locate the module on your LAN after it reconnects")
    f.add_argument("--mac", required=True, help="module MAC (from `info`)")
    f.set_defaults(func=cmd_find)

    args = p.parse_args()
    try:
        args.func(args)
    except (OSError, ProtocolError) as e:
        sys.exit(f"Error: {e}")


if __name__ == "__main__":
    main()
