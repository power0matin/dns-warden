## dns-warden v1.6.0

A rewrite of the resolver benchmark around real DNS queries, with safer apply and restore.

### Highlights
- Direct UDP and TCP DNS queries instead of ICMP ping.
- DNSSEC validation probe with a separate AD-flag signal.
- Optional `version.bind` fingerprint and `--bind-only` filter.
- Per-query details report next to the ranked report.
- `--apply` validates its target and resolves hostnames to an IP.
- Restore also offers to remove the `systemd-resolved` drop-in.
- 89-entry resolver catalog (Iranian public, ISP-routed, international).
- English and Persian documentation, tests, ShellCheck and CI.

### Requirements
Ubuntu 20.04+, `bash`, `dig` (`dnsutils`), `getent`, root.

### Verify the download
```bash
sha256sum --check --ignore-missing SHA256SUMS
```

Resolver list entries are community candidates and are not endorsed or verified. See [CHANGELOG.md](https://github.com/power0matin/dns-warden/blob/main/CHANGELOG.md) for details.
