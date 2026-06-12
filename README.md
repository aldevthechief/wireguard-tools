# AmneziaWG WARP Tools

A small collection of Python tools for generating configurable Cloudflare WARP
profiles for AmneziaWG and testing alternative WARP endpoint IP addresses.

The config generator supports multiple `I1` packet styles, selectable endpoint
ports, Cloudflare or Google DNS, custom DNS addresses, custom QUIC domains, and
configurable persistent keepalive values. The endpoint tester automates
AmneziaWG in the background so it does not take over the mouse or interrupt
normal user activity.

## Tools Overview

### `generate_config.py`

Registers a new Cloudflare WARP profile and writes an AmneziaWG-compatible
configuration to `WARP.conf`.

Available options:

- `--i1`: `stun`, `quic-captured`, or `quic-obfuscated`
- `-p`, `--port`: endpoint port `2408` or `4500`
- `-d`, `--dns`: `cloudflare`, `google`, or custom comma-separated addresses
- `-k`, `--keepalive`: `PersistentKeepalive` value
- `-do`, `--domain`: domain used to generate QUIC packets

### `generate_packet.py`

Provides the packet-generation functions used by `generate_config.py`:

- STUN binding-request I1 packets
- QUIC Initial packets generated for a selected domain
- Rebuilt QUIC packets padded to make DPI identification more difficult

### `ip_bruteforce.py`

Tests Cloudflare WARP endpoint ranges from `cf_ips_v4.txt` on ports `2408` and
`4500`. It creates temporary configurations, imports them into AmneziaWG,
checks connectivity, and records the results in `connection_log.txt`.

The AmneziaWG automation runs in the background and does not require you to
stop using the computer while endpoints are being tested.

### `us_ip.py`

Generates NAT64-formatted WARP endpoints from the IPv4 addresses and IPv6
prefixes defined in the script.

## Generate a Config in Google Colab

Google Colab is the recommended way to generate `WARP.conf` when Cloudflare
WARP registration requests are blocked by the local network or ISP. The
registration request is made from the Colab runtime instead of your local
connection.

1. Open [Google Colab](https://colab.research.google.com/) and create a new
   notebook.
2. Install the config generator dependencies:

```python
!pip install requests wireguard-tools aioquic cryptography
```

3. Upload `generate_config.py` and `generate_packet.py`:

```python
from google.colab import files
files.upload()
```

4. Generate a config with the defaults:

```python
!python generate_config.py
```

You can pass the same command-line options in Colab:

```python
!python generate_config.py --i1 quic-obfuscated --domain zoom.us -p 4500 -d google -k 15
```

5. Download the generated config:

```python
files.download("WARP.conf")
```

Import `WARP.conf` into AmneziaWG. The file contains your private key, so do
not share it and delete it from the Colab runtime when you are finished.

## Local Installation

Clone or download the repository, open a terminal in its directory, and install
the dependencies:

```bash
pip install requests wireguard-tools aioquic cryptography pywinauto
```

`ip_bruteforce.py` requires Windows and an installed AmneziaWG client.

## Generate a Config Locally

Local generation works when the Cloudflare WARP registration API is reachable
from your connection. Otherwise, use the Google Colab method above.

Generate a config with the defaults:

```bash
python generate_config.py
```

The defaults use a STUN I1 packet, port `2408`, Cloudflare DNS,
`PersistentKeepalive = 5`, and `zoom.us` as the QUIC domain.

Generate a captured-style QUIC config for a custom domain:

```bash
python generate_config.py --i1 quic-captured --domain example.com
```

Generate an obfuscated QUIC config with Google DNS and port `4500`:

```bash
python generate_config.py --i1 quic-obfuscated -p 4500 -d google -k 15
```

Pass custom DNS addresses as one quoted, comma-separated value:

```bash
python generate_config.py -d "9.9.9.9, 149.112.112.112"
```

View every option:

```bash
python generate_config.py --help
```

After generation, import `WARP.conf` into AmneziaWG.

## Test WARP Endpoints

1. Generate or place `WARP.conf` in the repository directory.
2. Set `anmezia_wg_path` in `ip_bruteforce.py` to your AmneziaWG executable.
3. Set `file_dir_path` to the repository directory, including its trailing
   path separator, for example `C:\Users\name\wireguard-tools\`.
4. Make sure `cf_ips_v4.txt` contains the Cloudflare endpoint prefixes to test.
5. Run:

```bash
python ip_bruteforce.py
```

Test results are printed in the terminal and appended to
`connection_log.txt`. Temporary numbered WARP configs are removed as testing
progresses.
