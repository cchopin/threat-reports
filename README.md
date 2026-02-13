# threat-reports

Threat intelligence reports, IOCs, and detection rules (YARA/Sigma/Suricata) from forensic investigations on active cyber threats.

## Reports

| Date | Threat Actor | Malware | Report |
|------|-------------|---------|--------|
| 2026-02-13 | PINEAPPLE | JeffreyEpstein / Pyramid C2 | [Report](PINEAPPLE-2026-02/rapport.md) |

## Structure

Each investigation is organized in its own directory:

```
<THREAT_ACTOR>-<YYYY-MM>/
├── rapport.md           # Full analysis report
├── rules/
│   ├── *.yar            # YARA rules
│   ├── *.rules          # Suricata/Snort rules
│   └── *.yml            # Sigma rules
└── iocs/
    └── iocs.csv         # Machine-readable IOCs (type,value,description,tags)
```

## Detection Rules

Rules in the `rules/` directories are ready to deploy. Suricata and Sigma rules use real (non-defanged) IPs for direct deployment. The report itself uses defanged notation (`[.]`) for safe reading.

## License

This work is shared under [TLP:CLEAR](https://www.first.org/tlp/) unless stated otherwise in individual reports.
