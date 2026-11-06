<h1 align="center">dns-warden</h1>

<p align="center">
  Benchmark DNS resolvers with real queries and switch between them safely on Ubuntu.
</p>

<p align="center">
  <a href="https://github.com/power0matin/dns-warden/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/power0matin/dns-warden/ci.yml?branch=main&style=flat-square&label=CI" alt="CI"></a>
  <a href="https://github.com/power0matin/dns-warden/releases"><img src="https://img.shields.io/github/v/release/power0matin/dns-warden?style=flat-square" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/power0matin/dns-warden?style=flat-square" alt="License"></a>
</p>

<p align="center"><a href="README.fa.md">فارسی</a></p>

## Overview

`dns-warden` is a single-file Bash tool with an interactive menu and a scriptable CLI. It sends real DNS queries directly to every resolver in a list, ranks the ones that work, and applies your choice with an automatic backup you can restore.

ICMP ping is not used. Many resolvers block it while still answering DNS, so ranking is based on actual DNS answers.

## Features

- **Direct DNS queries** over UDP against a fixed domain matrix, with success rate and average latency.
- **TCP check.** Resolvers that fail over TCP are penalised in the ranking.
- **DNSSEC probe** that reports `VALIDATES`, `LIKELY_VALIDATES`, `DOES_NOT_VALIDATE`, `INCONSISTENT` or `INCONCLUSIVE`, plus a separate AD-flag signal.
- **Optional `version.bind` fingerprint**, with a `--bind-only` filter.
- **Safe apply.** Backs up `/etc/resolv.conf`, supports `systemd-resolved`, and restores from the menu.
- **Detailed reports** per query (RCODE, answers, latency, AD flag).
- **Editable resolver list** with Iranian, ISP-routed and international public candidates.

## Requirements

- Ubuntu 20.04 or newer
- `bash`, `dig` (package `dnsutils`), `getent`
- Root privileges (the script re-runs itself with `sudo` when needed)

```bash
sudo apt-get update && sudo apt-get install -y dnsutils
```

## Install

Download the latest release, verify it, and run it:

```bash
curl -fsSLO https://github.com/power0matin/dns-warden/releases/latest/download/dns-warden.sh
curl -fsSLO https://github.com/power0matin/dns-warden/releases/latest/download/dns-list.txt
curl -fsSLO https://github.com/power0matin/dns-warden/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Or clone the repository:

```bash
git clone https://github.com/power0matin/dns-warden.git && cd dns-warden
```

## Usage

```bash
sudo bash dns-warden.sh                    # interactive menu
sudo bash dns-warden.sh --test             # benchmark only, no changes
sudo bash dns-warden.sh --test --count 2 --timeout 2
sudo bash dns-warden.sh --test --bind-only
sudo bash dns-warden.sh --apply 1.1.1.1 --method auto --yes
```

| Option | Description |
| --- | --- |
| `--test` | Run the benchmark and print the ranked report. |
| `--apply <ip\|host>` | Apply a resolver. Requires `--yes`. Hostnames are resolved to an IP first. |
| `--method auto\|resolved\|force` | `auto` uses `systemd-resolved` when it manages `resolv.conf`; `force` rewrites the file. |
| `--count <1-5>` | Queries per domain (default 1). |
| `--timeout <1-10>` | Seconds per query (default 1). |
| `--list <path>` | Use a different resolver list. |
| `--bind-only` | Show only resolvers with a BIND-like fingerprint. |
| `-V`, `--version` | Print the version. |

Backups are stored in `/var/backups/dns-warden` and reports in `/var/log/dns-warden`. Restoring a backup from the menu also offers to remove the `systemd-resolved` drop-in created by this tool.

## Resolver list

Edit `dns-list.txt`: one IP address or hostname per line, `#` for comments. Entries are community candidates and are **not endorsed or verified**. Private ISP addresses only work inside that ISP's network. Remove anything you do not trust.

## Notes

- Testing reveals the queried domain names to each resolver operator.
- Results reflect the network path of the machine you run it on; a server abroad cannot reproduce results from an Iranian ISP.
- DNSSEC and fingerprint probes are indicative, not a security audit.
- DNS does not change your public IP and cannot bypass IP-based restrictions.
- `--test` never modifies your DNS configuration.

## Development

```bash
bash -n dns-warden.sh
shellcheck -S warning dns-warden.sh tests/*.sh
bash tests/test-dnssec-classification.sh
bash tests/test-apply-target.sh
```

## License

[MIT](LICENSE) © [Matin Shahabadi](https://github.com/power0matin)
