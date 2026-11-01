# Qualification receipts

Reviewed `qualification-receipt-v1` receipts, one per pull request, named `<host-class>-<YYYY-MM-DD>.json`. See the [qualification guide](../../qualification.md) for how to produce one, the expected gaps per host class and what a receipt does not prove. No receipt from a required host class has been committed yet.

| Receipt | Class | Source | Binary | Result |
|---|---|---|---|---|
| [wsl-2026-11-01.json](wsl-2026-11-01.json) | `wsl` (optional) | `1e2affb` | checkout build | 26 of 26 groups passed, no gaps; WSL2 on amd64 with systemd enabled, run by the maintainer's account, which is in `adm` |
