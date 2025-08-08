# WireGuard Tools for AmneziaWG
This repository contains two essential scripts to simplify working with AmneziaWG, a privacy-enhanced WireGuard protocol. These tools help generate optimized configurations and verify connectivity to **Cloudflare WARP 1.1.1.1 VPN**. 

The combination of AmneziaWG's advanced obfuscation with WARP's privacy infrastructure creates powerful dual-layer protection for your connections.

## Tools Overview

### 1. generate_config.py
Generates WireGuard configurations compatible with AmneziaWG using Cloudflare's WARP service.

**HOW TO USE**:
1. Open [Google Colab](https://colab.research.google.com/)
2. Create a new notebook
3. Run this installation command in a new terminal:
```bash
pip install wireguard-tools
```
4. Copy-paste the contents of generate_config.py into a new cell
5. Run the script
6. Download the generated WARP.conf file
7. Import this configuration into your AmneziaWG client

### 2. ip_bruteforce.py
Tests WireGuard configurations and finds working Cloudflare WARP endpoint IPs on your local machine.

**PREREQUISITIES**:
- Place your `WARP.conf` inside the local copy of the repo
- Install pywinauto library
```bash
pip install pywinauto
```
- Edit these paths in the script before running:
```python
root_dir_path = "" # repo folder
amnezia_wg_path = "" # amnezia wg install path
```
- Close unnecessary applications and run the script

⚠️ **Do not interact with your machine during execution** ⚠️  
   *(The script automates UI interactions - mouse/keyboard input will disrupt it)*

**Connection status info for each tested ip will be printed out in the console.**
