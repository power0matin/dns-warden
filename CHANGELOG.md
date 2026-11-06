# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.6.0] - 2026-11-06

### Added
- Real DNS benchmarking with `dig`: queries are sent directly to each resolver over UDP against a fixed domain matrix.
- TCP reachability check; TCP failures are penalised in the ranking.
- DNSSEC probe (signed positive control plus `dnssec-failed.org`, normal and with CD) with the classes `VALIDATES`, `LIKELY_VALIDATES`, `DOES_NOT_VALIDATE`, `INCONSISTENT` and `INCONCLUSIVE`, and a separate AD-flag signal.
- Optional `version.bind` fingerprint and the `--bind-only` filter.
- Per-query details report (RCODE, answer count, A records, latency, AD flag).
- `--count`, `--timeout`, `--list` and `-V`/`--version` options.
- Expanded resolver catalog (89 unique entries) covering Iranian public, ISP-routed and international resolvers.
- Hostname targets for `--apply` are resolved to an IP before being written.
- Restoring a backup now offers to remove the `systemd-resolved` drop-in created by dns-warden.
- Test suite, ShellCheck linting and a tag-triggered release workflow.
- English `README.md` and Persian `README.fa.md`.

### Changed
- Resolver health is based on real DNS answers instead of ICMP ping; `ping` is no longer required.
- `dig` (`dnsutils`) is now a required dependency.

### Fixed
- `--apply` and the menu now reject invalid targets instead of writing them to `resolv.conf` or the resolved drop-in.
- The `version.bind` fingerprint is written to its own column in the details report.
- Replaced `ls | grep` backup listing with a safe glob loop.

[1.6.0]: https://github.com/power0matin/dns-warden/releases/tag/v1.6.0
