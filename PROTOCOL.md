# KZW-W002 SoftAP configuration protocol

Reverse-engineered from the official Haier Android apps (Smart Clima 4.0.1 and
HaierSmartAir2 4.0.1), both of which embed the same native SDK library
`liball-in-one.so` and the same uSDK Java layer (`com.haier.uhome.*`). The Java side builds
JSON; the actual exchange with the module happens in the native library (sources
`config/softap/sdk_softap.c`, `softap_mgr.c`, and the `cae_su_*` layer). Both apps use the
same protocol, offsets and key table.

The tool's encoder is verified byte-for-byte against those native functions, run under an
ARM64 emulator. The **plain** path is additionally confirmed on real hardware (a KZW-W002 on
firmware `2.18`, 12-character MAC): the module accepted the config and joined the target
network. The **secure** path is confirmed only against the apps' native code.

## How the vendor app does it

1. A module without WiFi credentials broadcasts an **open** network. The app recognizes it if
   the SSID contains `Haier-uAC`, `U-AC` or `U-AIC` (`CheckSoftApUtil.checkHaierSSID`); the SDK
   additionally requires it to start with `U-` (`uSDKDeviceManager.l()`).
2. The phone joins it with no password. The module is at **192.168.0.1**.
3. **Read** (`softap_aplist_get_req`, command 26001): the reply carries MAC, model id
   (`typeId`), firmware/protocol version and the list of networks the module can see.
4. **Write** (`softap_config_req`): the SSID and password of the network to join, in one of two
   variants:
   - **plain** (command 26003): a 652-byte struct, password in clear. *SmartAir2 always uses
     this.*
   - **secure** (command 26015): TLV, password masked. *Smart Clima uses this when the read-back
     MAC is 16 characters, plain otherwise* (`DeviceManager.configDeviceBySoftApConfig`), and
     adds the cloud gateway domain `gw.haieriot.net:56808`.
5. The module replies (26004), leaves AP mode and joins the network.

## Transport

One **TCP connection to `192.168.0.1:56797`** (`0xDDDD`) per command: connect, send, read
reply, close.

## Header (16 bytes, big-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | u32 | command |
| 4 | u16 | 0 |
| 6 | u16 | 0 |
| 8 | u32 | sequence number (0 is accepted) |
| 12 | u32 | body length |

| Command | Direction | Body |
|---|---|---|
| 26001 | → module | empty (read) |
| 26002 | ← module | info (below) |
| 26003 | → module | **plain** config, 652 bytes |
| 26015 | → module | **secure** config, TLV |
| 26004 | ← module | u32 error code (0 = OK); reply to both 26003 and 26015 |

## 26002 reply

The module announces a length of `0x11C` (284 bytes). The AP list follows **outside** that
length: `ap_num × 36` bytes (`usdk_get_uwt_para`).

| Offset | Size | Field |
|---|---|---|
| 0x00 | u32 | error code |
| 0x04 | 32 | typeId (binary; the app renders it as hex) |
| 0x24 | u32 | (unknown; observed = 1) |
| 0x28 | 16 | MAC (string) |
| 0x38 | 16 | IP |
| 0x48 | 16 | protocol version |
| 0x58 | u32 | number of APs (`ap_num`) |
| 0x9C | 64 | room name |
| 0xDC | 64 | stored password |
| 0x11C + 36·i | 32 + u16 + u16 | SSID, encryption, signal |

SSIDs are raw UTF-8. After the trailing `\0`, each entry keeps leftover bytes from the previous
SSID, so cut at the first `\0`. The encryption field does **not** follow the app's own enum on
firmware 2.18 (observed: `0` for an open guest hotspot, `1` for another open network, `6` for
both a WPA2 network and a Wi-Fi-Direct printer), so treat it as informational only. "Signal" is
a positive quality scale.

## Plain config (26003, 652 bytes)

This is `usdk_json2devconf`: all zero except:

| Offset | Size | Field |
|---|---|---|
| 0x40 | 32 | typeId, **copied from the 26002 reply** (required: without it the app aborts) |
| 0x120 | 32 | target SSID (`strncpy`) |
| 0x140 | 64 | target password, in clear |

The app's JSON request object also has `dhcpType`, `ip`, `mask`, `gateway`, `dns` fields, but
the native encoder never serializes them — so a static IP / custom DNS cannot be pushed to the
module this way; it uses DHCP.

## Secure config (26015, TLV `type, length, value`)

Order produced by `cae_su_codec_softAp_setParam_tlv`:

1. `02 L ssid` (max 32 bytes)
2. `03 L [4 bytes][encrypted password]` (L = len + 4, max 68)
3. `01 02 [masked key]`
4. `07 L domain:port`, if provided (max 64)
5. `08 L country`, if provided (max 2)

Crypto (`uplus_*`):

- `key_index = rand() & 0xFFFF`;
- key of `(key_index >> 11) + 1` bytes, read from a static 1024-byte table starting at
  `key_index & 0x7FF` (wrapped at 1024); the table is embedded in the tool;
- password XOR key (repeated);
- the 4 bytes before the password are **uninitialised** in the app (stack residue, confirmed in
  emulation); the tool sends zeros;
- `crc = CRC-16/ARC` (poly 0xA001 reflected, init 0) over the whole value of TLV 3;
- masked key = `[(key_index >> 8) ^ (crc & 0xFF), (key_index & 0xFF) ^ (crc >> 8)]`.

## After reconnection

The module gets an address by DHCP and exposes the local control protocol on **TCP 56800**
(TCP 56797 is only open in SoftAP mode). It also opens a long-lived connection to the cloud
gateway and periodically checks the config/firmware file server. See the README for how to
block those at the network level.

## Related cloud endpoints (from the apps)

- `gw.haieriot.net`, `gw-gea-euro.haieriot.net` — cloud gateway (device long connection)
- `standardcfm-gea-euro.haieriot.net` — config/firmware file server (OTA source)
- `uhome.haieriot.net`, `uws-euro.haieriot.net`, `uws-gea-euro.haieriot.net`,
  `uws-clima-euro.haieriot.net` — web services (mostly app-side)

## Uncertainties

- Which mode a given module needs depends on its MAC length (read it with `info`).
- The secure path is not yet confirmed on real hardware here.
- The `0x24` field and the exact signal scale are not decoded.
