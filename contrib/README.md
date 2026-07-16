# contrib/

Operator-facing extras that ship with lodan but aren't imported by the package.

## Scheduled rescans — `lodan-scan@.service` + `lodan-scan@.timer`

A sample systemd **user** service + timer, templated on the workspace name.
`lodan scan` is idempotent per workspace and auto-diffs against the previous
scan, so a timer is all you need to turn "what changed since last time" into a
push-free, always-current view.

```sh
mkdir -p ~/.config/systemd/user
cp lodan-scan@.service lodan-scan@.timer ~/.config/systemd/user/
# edit ExecStart in the .service to point at your lodan binary, then:
systemctl --user enable --now lodan-scan@home-lab.timer
systemctl --user list-timers
journalctl --user -u lodan-scan@home-lab.service   # last run's output
```

The service sets `LODAN_OPERATOR=systemd-timer`, so scheduled runs are
distinguishable from hand-run scans in `scan.log` and the authorization ledger.

Raw-socket note: the masscan/scapy discovery backends need `CAP_NET_RAW`; the
naabu backend and every probe run unprivileged. A cron entry works equally well
(`lodan scan home-lab`) if you'd rather not use systemd.

## Store/query benchmark — `benchmark.py`

Populates a throwaway workspace through the real write path (batched discovery
inserts + probe merges) and times the hot pivots, so performance on large ranges
is measured, not assumed. No network, no external tools.

```sh
python contrib/benchmark.py --services 50000 --probe-frac 0.2
```

Reports discovery insert throughput and per-pivot latency (the SAN pivot is a
substring `LIKE` and is expected to be a full scan — no index can serve it).
