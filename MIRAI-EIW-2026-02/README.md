# Mirai.EIW / XMRig Double Compromise - Incident Response & CTI

Real-world incident response and threat intelligence investigation of a server compromised by both a Mirai botnet variant (EIW) and an XMRig cryptominer, traced to Russian bulletproof hosting infrastructure (Virtualine Technologies).

## Key Findings

- **Malware:** Mirai variant EIW (34/72 VirusTotal detection)
- **Secondary payload:** XMRig cryptominer (Monero)
- **C2 Infrastructure:** Virtualine Technologies / Railnet LLC (Russian bulletproof hosting)
- **Attack vectors:** Strapi CMS misconfiguration + Next.js Server Actions exploitation
- **C2 Servers:** `91[.]92[.]241[.]12:6969`, `91[.]92[.]243[.]113:235`

## Contents

### English

| File | Description |
|------|-------------|
| [02_threat_intelligence.md](02_threat_intelligence.md) | CTI report: malware identification, infrastructure attribution, MITRE ATT&CK mapping |
| [03_writeup.md](03_writeup.md) | Narrative write-up for blog/educational purposes |

### Francais

| Fichier | Description |
|---------|-------------|
| [01_incident_report_FR.md](01_incident_report_FR.md) | Rapport d'incident complet avec timeline, IOCs et remediation |
| [02_threat_intelligence_FR.md](02_threat_intelligence_FR.md) | Rapport CTI : identification malware, attribution infrastructure, mapping MITRE ATT&CK |
| [03_writeup_FR.md](03_writeup_FR.md) | Write-up narratif pour blog/formation |

### Detection & IOCs

| File | Description |
|------|-------------|
| [rules/mirai-eiw.yar](rules/mirai-eiw.yar) | YARA rules (2 rules: binary + dropper detection) |
| [rules/mirai-eiw.rules](rules/mirai-eiw.rules) | Suricata/Snort rules (7 rules: C2, beacon, payloads) |
| [iocs/iocs.csv](iocs/iocs.csv) | Machine-readable IOCs (IPs, hashes, domains, wallets) |

## Timeline

| Date | Event |
|------|-------|
| Dec 5, 2025 | First compromise - XMRig cryptominer deployed |
| Jan 22-28, 2026 | Reconnaissance and probing via Next.js Server Actions |
| Feb 3, 2026 | Mirai dropper deployed |
| Feb 6, 2026 | Botnet active, incident detected and cleaned |

---

*Classification: TLP:CLEAR*
*Case study based on real incident. All identifying server information redacted.*
