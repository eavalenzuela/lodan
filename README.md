# lodan

Local Shodan. Point it at a CIDR you own, get a Shodan-style report — offline,
free, with diff-over-time as the killer feature.

See [PLAN.md](PLAN.md) for the full design.

## Status

Early scaffold. `lodan init` works; everything else prints "not implemented."

## Install (dev)

```
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/lodan --version
```

## Scan what you own

lodan is reconnaissance, not attack tooling, and it is only for ranges you
operate. Every workspace's `config.toml` declares an `authorized_ranges`
allowlist; the scanner refuses targets outside it. Public cloud prefixes are
blocked unless you explicitly opt in with a written justification that is
logged into the scan's metadata.

No exploitation. No credential testing. No brute force. lodan looks; it does
not touch.
