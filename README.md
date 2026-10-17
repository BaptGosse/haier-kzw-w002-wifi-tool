# haier-kzw-w002-wifi-tool

Reconnect a **Haier KZW-W002** air-conditioner WiFi module to the network of your choice,
locally, with no vendor app and no cloud account.

The KZW-W002 is the USB-A WiFi stick used by Haier air conditioners and heat pumps and by
many rebrands — Candy, Hoover, and (in France) **Thermor / Atlantic / Sauter "Nagano"**. When
a module has no valid WiFi credentials it falls back to a **SoftAP**: it broadcasts an *open*
network whose name contains `U-AC`, `U-AIC` or `Haier-uAC`, and listens on
`192.168.0.1:56797`. The vendor apps use that channel to hand the module the SSID and password
of your home network. When those apps stop working (discontinued, incompatible with your key
revision, or regionally locked), a module that drops off WiFi can become impossible to
re-pair. This tool reproduces the exact SoftAP handshake so you can re-pair it yourself.

The protocol was reverse-engineered from the official Android apps (Haier Smart Clima and
HaierSmartAir2). The encoder is byte-for-byte identical to the apps' native code, verified by
emulating those functions; the "plain" path is also validated on real hardware (firmware
`2.18`). Full write-up in [PROTOCOL.md](PROTOCOL.md).

> ⚠️ This tool **writes to your device**. Use it only on a module that is already in SoftAP
> (pairing) mode, i.e. broadcasting its own open `U-AC…` network. The built-in safety check
> refuses to talk to `192.168.0.1` unless your computer is currently joined to such a network,
> so it cannot accidentally reconfigure a module that is already online. Use at your own risk.

## Requirements

- Python 3.8+ — **standard library only**, nothing to install.
- Linux for the convenience commands `scan` and `find` (they call `nmcli` and `ip`). `info`
  and `config` work on any OS once you are joined to the module's WiFi.

## Usage

Put the module into pairing mode (see your unit's manual — often a button combo or a power
cycle sequence), then join its open network. On Linux:

```sh
python3 haier_kzw_w002.py scan --connect     # find and join the module's U-AC… network
```

Read the module (this is read-only and a good first check):

```sh
python3 haier_kzw_w002.py info
```

```
MAC           : AABBCCDDEEFF  (12 chars)
IP            :
Protocol ver. : '2.18'
typeId        : 2008610800820324021200118009090000000000000000000000000000000040
Room name     : ''
Stored pwd    : 0 chars
Networks the module can see (3):
    56  WPA/WPA2   MyWiFi
    42  open       Guest
    40  WPA/WPA2   DIRECT-48-HP DeskJet 4200 series
```

Check that your network appears in the list (the module only sees **2.4 GHz**). Then send it:

```sh
python3 haier_kzw_w002.py config --ssid "MyWiFi"
```

The password is prompted (never put it on the command line / in shell history). After `OK`,
the module leaves SoftAP mode and joins your network. Reconnect your computer to that network
and locate the module:

```sh
python3 haier_kzw_w002.py find --mac AABBCCDDEEFF
```

```
Module AA:BB:CC:DD:EE:FF is at 192.168.1.42
  TCP 56800 (local control): open

Home Assistant (ddnlv/haier-kzw-w002-local): IP 192.168.1.42, MAC AABBCCDDEEFF
```

### Modes

`config` picks the mode the way the vendor apps do (`--mode auto`):

- **plain** (command 26003) — SSID and password only; password sent in clear over the module's
  own AP. Used when the module's MAC is 12 characters (the common case).
- **secure** (command 26015) — password masked, and it can additionally carry the **cloud
  gateway domain** (`--domain host:port`) and a country code. Used when the MAC is 16 chars.

Force one with `--mode plain` / `--mode secure`. `--dry-run` reads the module and prints the
frame without sending anything.

## Keeping the module off the vendor cloud / blocking firmware updates

Once reconnected the module reaches the Haier cloud, and a firmware update pushed from there
has been known to break local control. The module **always uses DHCP** — you cannot set a
static IP or a custom DNS on the module itself through this protocol — so block at the network
level instead:

1. Give the module a **DHCP reservation** (fixed IP) in your router, keyed to its MAC.
2. Either **deny it Internet access** entirely (firewall rule on its IP/MAC), or point your
   DHCP's DNS at a **Pi-hole / AdGuard Home** and sinkhole the vendor domains. The ones the
   device and apps use (confirm against your Pi-hole query log for the module's IP):
   - `gw.haieriot.net`, `gw-gea-euro.haieriot.net` — cloud gateway (the device's long-lived
     connection)
   - `standardcfm-gea-euro.haieriot.net` — config/firmware file server (OTA source)
   - `uhome.haieriot.net`, `uws-euro.haieriot.net`, `uws-gea-euro.haieriot.net`,
     `uws-clima-euro.haieriot.net` — web services (mostly app-side)

Alternatively, in **secure** mode you can set the module's cloud gateway to an unreachable host
at pairing time, e.g. `--mode secure --domain 127.0.0.1:1`, so it never reaches the real cloud.
This is device-side and survives DHCP changes, but is less reversible than a DNS/firewall rule
and is only honored by firmware that accepts the secure command.

## Home Assistant

After reconnection the module exposes the local control protocol on **TCP 56800**. Control it
with the [`ddnlv/haier-kzw-w002-local`](https://github.com/ddnlv/haier-kzw-w002-local)
integration, using the IP and the 12-character MAC that `find` prints.

## Limitations

- **DHCP only**: no static IP / custom DNS on the module (the config fields exist in the app
  but the native code never transmits them).
- **No firmware flashing**: the module is a fixed-function WiFi co-processor talking UART to
  the AC mainboard; there is no local path to run arbitrary code or replace its firmware. Its
  updates come from the cloud config-file server, which is why blocking that server is the way
  to freeze the firmware.
- Validated on `2.18` firmware with a 12-char MAC (plain mode). The secure path is validated
  against the apps' native code in emulation, not yet on real hardware here. A module with a
  16-char MAC may need adapting for integrations that expect 12.

## Legal

For use on hardware you own or are authorized to manage. The protocol was reverse-engineered
for interoperability and local control. Haier, Candy, Hoover, Thermor, Atlantic, Sauter and
Nagano are trademarks of their respective owners; this project is not affiliated with or
endorsed by any of them.

## License

[MIT](LICENSE) © 2026 Baptiste Gosselin
