# Contributing

Thanks for helping make this safer and better. A few hard rules, because people
run this tool on their own machines.

## The one rule that is never bent

**Never commit a live, runnable malware sample.** Not in tests, not in fixtures,
not "encrypted in a zip." Contribute detection as **fingerprints only**:

- a SHA-256 hash, and/or
- a short byte pattern (hex),

added as a JSON file under `antivirus/db/` (see `antivirus/db/README.md`). A hash
or short pattern cannot be used to rebuild a virus. The only sample artifact used
anywhere in this project is the harmless EICAR test string.

## Safety-first review bar

Any change is rejected if it could let a *scan* modify, delete, rename, or
execute a user's files, or follow a symlink out of the scan root. The read-only
guarantee in `SECURITY.md` is the product. If you add a feature that acts on
files, it must be: opt-in, confirmed, reversible, and limited to known-bad
matches — never heuristics.

## Before you open a PR

```powershell
py -m unittest discover -s tests -v   # all tests must pass
```

New detection logic needs a test. New heuristics should err toward fewer false
positives — a noisy scanner that cries wolf is worse than a quiet one.
