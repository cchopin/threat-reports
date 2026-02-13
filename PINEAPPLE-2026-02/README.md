# PINEAPPLE - Pyramid C2 / JeffreyEpstein Forensic Analysis

Forensic analysis of a malware sample named "JeffreyEpstein" that deploys the Pyramid C2 framework with Chisel SOCKS5 reverse tunneling. Discovered embedded in a 3D printing file. C2 infrastructure hosted on Omegatech LTD bulletproof hosting (Seychelles shell company, AS202412).

**The malware was NEVER executed -- analysis is purely preventive/threat intelligence.**

## Key Findings

- **Malware:** JeffreyEpstein (Python-based loader for Pyramid C2)
- **C2 Framework:** Pyramid C2 (@naksyn) with Chisel SOCKS5 tunneling
- **C2 Infrastructure:** Omegatech LTD (AS202412), bulletproof hosting, Seychelles shell company
- **Post-exploitation tools:** secretsdump, DonPAPI (DPAPI credential theft), BeaconHunter (EDR evasion)
- **C2 Servers:** `158[.]94[.]210[.]160` (primary), `178[.]16[.]53[.]173` (fallback)

## Contents

### English

| File | Description |
|------|-------------|
| [rapport_EN.md](rapport_EN.md) | Full forensic analysis report (EN) |

### Francais

| Fichier | Description |
|---------|-------------|
| [rapport_FR.md](rapport_FR.md) | Rapport d'analyse forensic complet (FR) |

### Detection & IOCs

| File | Description |
|------|-------------|
| [rules/pineapple.yar](rules/pineapple.yar) | YARA rules (3 rules) |
| [rules/pineapple.rules](rules/pineapple.rules) | Suricata/Snort rules (5 rules) |
| [rules/pineapple.yml](rules/pineapple.yml) | Sigma rule (1 rule) |
| [iocs/iocs.csv](iocs/iocs.csv) | Machine-readable IOCs |

## Timeline

| Date | Event |
|------|-------|
| Aug 19, 2025 | First OMEGATECH IP block registered |
| Jan 21, 2026 | BGP routes created for C2 blocks |
| Feb 10, 2026 | First OTX detections for C2 #1 |
| Feb 13, 2026 | Malware discovered in 3D printing file |
| Feb 13, 2026 | Forensic analysis (this report) |

---

*Classification: TLP:CLEAR*
*Analysts: tlecavelier, cchopin*
