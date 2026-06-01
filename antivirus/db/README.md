# Signature database

Drop `*.json` files here to extend detection without touching code. Each file:

```json
{
  "name": "my-signature-pack",
  "patterns": [
    {
      "name": "Some.Family.Marker",
      "encoding": "hex",          // "hex" | "utf-8" | "latin-1"
      "pattern": "4d5a90000300",  // bytes to search for anywhere in a file
      "description": "why this matches",
      "severity": "malware"       // "malware" | "pup" | "test"
    }
  ],
  "hashes": [
    {
      "name": "Some.Sample.SHA256",
      "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "description": "exact known-bad file",
      "severity": "malware"
    }
  ]
}
```

## Open-source safety rule (non-negotiable)

**Never commit a live, runnable malware sample to this repository.** Contribute
only *fingerprints*: SHA-256 hashes and short byte patterns. A hash cannot
reconstruct a virus. Malformed or unsafe entries are skipped at load time and
never crash the scanner.
