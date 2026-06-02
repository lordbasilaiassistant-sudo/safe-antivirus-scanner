# YARA rules

Every `*.yar` / `*.yara` file in this directory is compiled and run against
scanned files. Add more rules here to expand detection — no code changes needed.

## Good free community rule sets

- https://github.com/Yara-Rules/rules
- https://github.com/Neo23x0/signature-base (used by THOR/LOKI)
- https://github.com/elastic/protections-artifacts

## Rule metadata the scanner reads

```
rule My_Rule {
    meta:
        description = "what it detects"
        severity = "suspicious"   // "malware" | "suspicious" | "test"
        score = "50"              // optional; weight for the scoring engine
    strings:
        $a = "indicator" nocase
    condition:
        $a
}
```

- `severity = "malware"` → reported as a high-confidence THREAT.
- `severity = "suspicious"` → goes through confidence scoring (REVIEW).
- `severity = "test"` → harmless test match (like EICAR).

## Safety

Rules describe malware; they are not malware. Never commit live samples — see
`../../CONTRIBUTING.md`.
