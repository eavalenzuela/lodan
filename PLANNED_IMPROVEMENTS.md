# lodan — Planned Improvements & Feature Roadmap

Scoping document only. This is an engineering roadmap for the existing
detection-only reconnaissance tool; it defines *what to harden and build next*,
not *how to attack*. lodan stays reconnaissance-only — no credentials, no
exploitation, no evasion. Every item below preserves that posture.

Current state for context: feature-complete against PLAN.md M1–M9, ~320 tests
(mostly offline parser-only), ruff-clean, single-Python CI. The items below are
prioritized as an incremental hardening path from that baseline.

## Improvements

1. **Wire up structured audit logging.** `structlog` is a declared dependency
   and PLAN.md specifies a per-workspace `scan.log`, but it is not actually
   used in the code today — every scan should emit a structured, append-only
   JSON audit record (targets in scope, authz decisions, probe outcomes,
   operator + timestamp) so runs are reconstructable after the fact.

2. **Promote authorization rejections to a first-class audit trail.** Today
   out-of-scope hits land only in `scan_errors`; add an immutable, separately
   queryable authorization ledger so "what did we touch and what did we refuse"
   is auditable independent of scan bookkeeping — the core accountability
   guarantee for a scanning tool.

3. **Add a pre-scan scope preview / confirmation gate.** Before firing,
   enumerate and display the exact address/port scope (with a size warning and
   an explicit confirm for large ranges like `1-65535` or wide CIDRs) so an
   operator can catch a mis-typed `authorized_ranges` before any packet leaves.

4. **Harden the hand-rolled binary parsers against malformed input.** The
   TLS/SMB/RDP ClientHello/ServerHello and negotiate parsers are the highest
   crash-risk surface; add malformed/truncated/oversized fixtures and defensive
   bounds checks so a hostile or broken responder can never crash the probe
   phase or corrupt a result row.

5. **Introduce DB schema versioning + forward migrations.** The schema evolves
   via ad-hoc `ALTER TABLE` today; add an explicit `schema_version` and an
   idempotent migration runner so upgrading lodan never leaves an old workspace
   DB in an unreadable state — portability is a stated non-negotiable.

6. **Expand test coverage beyond parsers into the orchestration path.** Most
   tests are `parse()`-only; add coverage for discovery-backend output edge
   cases, the rate-limit/token-bucket, scan resume, and the orchestrator's
   failure/rollback paths so regressions in the glue (not just the leaves) are
   caught.

7. **Raise CI to production gates.** Add a Python-version matrix, a coverage
   floor, a packaging check (build sdist+wheel, `twine check`), and — because
   this is a security tool — dependency vulnerability scanning and static
   analysis in the pipeline, so releases are reproducible and supply-chain
   aware.

8. **Normalize result parsing/output for stable diffs and pivots.** Canonicalize
   banners, tech names, and cert fields so cosmetic variance (whitespace, case,
   field ordering) stops producing noisy `changed` diffs and so pivots on the
   same underlying value reliably collate.

9. **Tune the store and query layer for large workspaces.** Review FTS5 usage,
   add covering indexes for the hot pivots (JA3S / host-key / favicon / SAN),
   size write transactions during high-volume discovery, and add a lightweight
   benchmark so performance on big ranges is measured, not assumed.

10. **Fill the documentation and responsible-use gaps.** Populate the empty
    `contrib/` (the promised sample scheduler unit), add CONTRIBUTING and a
    SECURITY / responsible-use guide, document the audit-log format and the
    authorization model prominently, and tighten module docstrings so the
    "scan what you own" contract is unmissable.

## New Features

1. **Shareable, integrity-checked reports.** Render a scan or diff into a
   self-contained report (HTML plus machine-readable formats such as SARIF/CSV)
   with a checksum/manifest, so findings can be handed to stakeholders offline
   without shipping the whole workspace DB.

2. **Scheduled rescans with change notifications.** Make the "what changed since
   last time" killer feature push-driven: a scheduling helper plus an opt-in
   notification hook (webhook/email) that fires a diff summary only when
   something actually changed, so drift is surfaced without manual polling.

3. **Broaden detection-only coverage.** Extend the probe set to additional
   common services and broaden the set of surfaced finding types (e.g. more
   protocol fingerprints and misconfiguration/exposure categories), all under
   the same strict no-credentials, look-don't-touch contract — capability
   breadth described at the roadmap level only.

4. **IPv6 support.** Lift the v1 IPv4-only limitation across `authorized_ranges`,
   discovery, and enrichment (including the already-noted deferred IP2Location
   LITE IPv6 DB), since dual-stack estates are increasingly the norm for the
   ranges operators own.

5. **Multi-user, read-only web UI sharing with view auditing.** Add
   authenticated per-workspace read-only access tokens plus an audit trail of
   who viewed or queried what, with TLS-termination guidance for non-loopback
   binds, so results can be shared with a team without granting scan or
   configuration rights.
