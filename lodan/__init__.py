"""lodan — a local, offline, detection-only reconnaissance tool for ranges you
own or are explicitly authorized to assess.

The contract, enforced in code and never optional (see SECURITY.md):

- **Scan what you own.** Targets must fall inside a workspace's
  `authorized_ranges`; `lodan.authz` refuses anything else at config load and
  again per target during the scan. Public cloud prefixes are refused unless the
  workspace opts in with a recorded justification.
- **Look, don't touch.** Every probe is detection-only — no credentials, no auth
  attempts, no exploitation, no evasion.
- **Stay accountable.** Each scan appends a JSONL audit record to the
  workspace's `scan.log` and writes an immutable authorization ledger of what it
  was cleared to touch and what it refused.
"""

__version__ = "0.0.1"
