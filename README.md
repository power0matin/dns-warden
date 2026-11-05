# dns-warden — DNS Resolver Benchmark & Safe Switcher

`dns-warden` is a Bash CLI/TUI for Ubuntu servers. It benchmarks configured DNS resolvers by sending **real DNS queries directly to each resolver**, ranks working endpoints, and can apply a selected resolver with backup/restore support.

## What it measures

- UDP DNS A-query success rate against a small, fixed domain matrix.
- Average DNS query latency for successful answers.
- TCP DNS query reachability. TCP failures receive a ranking penalty because reliable DNS service should support both transports.
- DNSSEC behavior using a signed positive test domain (`cloudflare.com`) and the intentionally broken test domain (`dnssec-failed.org`). Results are indicative, not a formal DNSSEC audit.
- Optional `version.bind` CHAOS TXT fingerprint. Network errors are reported as `NO_RESPONSE`; a hidden response is **inconclusive**. Only an explicit BIND version-like response is classified as a BIND candidate.
- Per-domain A-record values, answer count, RCODE, latency, and AD flag in a separate detail report.
- Resolver list includes Iranian public/community candidates, ISP-routed/private candidates, and international public baselines.

**Important:** DNS cannot change your public IP or bypass IP-geolocation sanctions. It may help only where a service is affected by DNS-level filtering or resolution. DNS latency is not download throughput. Private addresses such as `10.202.x.x`, `10.x.x.x`, `172.16/12` and `192.168/16` are tested only if the server's network routes them.

## Requirements

- Ubuntu 20.04+
- Root access for applying DNS; tests can also be run as root by the current script.
- `bash`, `dig` (`dnsutils`), `getent`, `awk`, `sort`.

Install the DNS query tool:

```bash
sudo apt-get update
sudo apt-get install -y dnsutils
```

## Run a benchmark on a server

Recommended: clone the repository and inspect the script before running it as root.

```bash
git clone https://github.com/power0matin/dns-warden.git
cd dns-warden
set -euo pipefail
bash -n dns-warden.sh
python3 - <<'PY'
import ipaddress
from pathlib import Path

entries = []
for raw in Path("dns-list.txt").read_text().splitlines():
    value = raw.split("#", 1)[0].strip()
    if not value:
        continue
    ipaddress.ip_address(value)
    entries.append(value)

assert entries, "DNS catalog is empty"
assert len(entries) == len(set(entries)), "Duplicate DNS entries found"
print(f"{len(entries)} unique IP resolvers")
PY
sudo bash ./dns-warden.sh --test
```

Tune repetitions and timeout:

```bash
sudo bash ./dns-warden.sh --test --count 2 --timeout 2
```

Only show resolvers that explicitly expose a BIND-like fingerprint:

```bash
sudo bash ./dns-warden.sh --test --bind-only
```

This filter is intentionally conservative. Many legitimate BIND servers hide `version.bind`; those are marked `HIDDEN` and cannot be confirmed from the outside.

## Interactive menu

```bash
sudo bash ./dns-warden.sh
```

1. Test all entries.
2. Select a resolver from the ranked results and apply it.
3. Inspect the current DNS configuration.
4. Edit the resolver list.
5. Restore a previous backup.

## Apply from CLI

Only apply after reviewing the benchmark. The script requires an explicit `--yes` flag in non-interactive mode.

```bash
sudo bash ./dns-warden.sh --apply 178.22.122.100 --method auto --yes
```

- `auto`: use `systemd-resolved` when its managed symlink is detected; otherwise use the direct file method.
- `resolved`: write a systemd-resolved drop-in.
- `force`: replace `/etc/resolv.conf`; this can break a symlink and should be avoided unless intentional.

Backups are stored under `/var/backups/dns-warden`; benchmark reports are stored under `/var/log/dns-warden`.
The ranked report is accompanied by a per-query report in `/var/log/dns-warden/*.details.txt`. It includes resolver, queried domain, transport, RCODE, answer count, A-record values, query time, AD flag, and the BIND fingerprint result. The summary's `AD` column counts authenticated responses from the main test matrix; it is a signal, not a complete DNSSEC audit. The `DNSSEC` column is based on the positive and intentionally-broken DNSSEC test domains; filtering, interception, or test-domain changes can make it inconclusive.


## Catalog format

Edit `dns-list.txt`: one IP address or hostname per line; blank lines and `#` comments are ignored. Entries are candidates gathered from public lists and provider reports. Their current ownership, public reachability, privacy policy, free tier, and BIND implementation are **not independently guaranteed** by inclusion in this list. Remove entries you do not trust.

## Safety and interpretation

- Benchmarking sends DNS queries to every configured resolver. This reveals the tested domain names to those resolver operators.
- A resolver may be reachable by UDP but not TCP, or vice versa; both are tested and TCP failure affects ranking.
- DNSSEC validation is probed independently from the main ranking. A `NO_VALIDATION_SIGNAL` result is not proof that the server never validates DNSSEC.
- ICMP ping is not used for ranking because DNS servers commonly rate-limit or block ping while still answering DNS.
- DNS query timing is measured from this server's current network path. A VPS outside Iran cannot reproduce an Iranian ISP's resolver reachability or latency.
- The tool does not silently change DNS during `--test`.
- Do not apply an unknown resolver solely because it has a low latency score.

## Development checks

```bash
bash -n dns-warden.sh
python3 - <<'PY'
from pathlib import Path
entries = []
for line in Path("dns-list.txt").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#"):
        entries.append(line)
assert entries, "DNS list is empty"
assert len(entries) == len(set(entries)), "Duplicate DNS entries found"
print(f"{len(entries)} unique resolver entries")
PY
```

## License

MIT. See [LICENSE](LICENSE).
