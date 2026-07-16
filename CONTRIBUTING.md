# Contributing to lodan

Thanks for helping. lodan is a detection-only reconnaissance tool; every
contribution must preserve that posture — see [SECURITY.md](SECURITY.md) for the
"scan what you own", detection-only, and accountability contracts. A change that
sends a credential, probes outside `authorized_ranges`, or weakens the
authorization guard will not be accepted.

## Dev setup

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Tests

```sh
.venv/bin/pytest                     # full suite, offline, ~sub-3s
```

The suite is mostly parser-level and fully offline. The Docker-backed
integration tests under `tests/docker/` are opt-in — they stand up nginx (plain
+ TLS), Redis, MongoDB, and OpenSSH on loopback and drive the real probes:

```sh
LODAN_DOCKER_TESTS=1 .venv/bin/pytest tests/docker/   # needs docker + compose
```

Without that env var they skip, so the default run stays offline.

Guidelines:

- New parsing code needs **malformed / truncated / oversized** fixtures, not
  just happy-path ones — a hostile or broken responder must never crash the
  probe phase. The TLS/SMB/RDP parser tests are the pattern to follow.
- Prefer pure, offline, byte-level tests. Split network I/O from parsing (as the
  probes do with `fetch()` vs `parse_*()`) so the parser is testable without a
  socket.

## Lint

```sh
.venv/bin/ruff check .               # the lint gate; matches CI
```

## Invariants worth knowing

- **Authorization runs at scan time, always.** Editing `authorized_ranges` (CLI
  or UI) only changes the allowlist; `authz.check_workspace` and
  `authz.check_target` still gate every scan, as does the cloud-prefix guard.
- **Result canonicalization happens once, at the storage boundary.**
  `lodan.normalize` is applied in `writer.update_service_from_probe`, so banners,
  tech names, SANs, and fingerprints land canonical. Don't write these columns
  through another path, or you'll reintroduce noisy diffs and split pivots.
- **The authorization ledger is append-only.** `authz_ledger` is immutable by DB
  trigger and has no cascading FK to `scans` (it must survive retention prune).
  Only ever `INSERT` into it, via `writer.record_authz_decision`.
- **Schema changes** go in `store/schema.sql` as `CREATE ... IF NOT EXISTS`;
  `store.db.ensure_schema` runs it (plus targeted index/column migrations) at
  scan start so existing workspaces pick up new tables without a re-`init`.

## Commit style

Follow the feature-sized commits visible in `git log` — one logical change per
commit, with a message that says *why* alongside *what*.
