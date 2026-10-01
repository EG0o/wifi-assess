# WiFi-Assess

WiFi-Assess is a Go CLI for **offline analysis of 802.11 packet captures**. Given a PCAP or PCAPNG file, it inventories observed access points and clients, produces limited review findings, and compares AP observations with an optional saved baseline. It prints a console summary or JSON report.

## What it does

- Frame counts; AP SSID, BSSID, channel, privacy bit, beacon/probe counts; client probes and observed association exchanges.
- Assessment observations: privacy bit unset (open network), unknown privacy status, and low mean received signal when at least five RadioTap signal samples exist.
- Info-level observations for an SSID advertised by multiple BSSIDs and AP changes relative to a saved baseline.
- PCAP and PCAPNG input, console and JSON output. Reading capture files does not require libpcap or Npcap.

## Project status

This release analyzes completed, offline PCAP/PCAPNG files containing raw 802.11 frames. Live capture, monitor-mode management, and active testing are outside this release. The tool does **not** classify WPA/WPA2/WPA3, RSN/AKM suites, PMF, or WPS. A set privacy bit means the AP advertises protected operation, not that its security configuration is known or safe.

## Architecture

PCAP/PCAPNG → capture reader → 802.11 parser → AP/client tracker → assessment and detection → console/JSON report. See [architecture](docs/architecture.md).

## Requirements

- Go 1.24.2 or newer.
- A PCAP/PCAPNG capture containing raw 802.11 frames. Ordinary Ethernet captures lack the management frames this tool needs. The capture may come from a separate tool, such as `dumpcap`, with a compatible monitor-mode adapter configured by the user.

## Quick start

From the repository root:

```bash
go build ./...
go run ./cmd/wifi-assess /path/to/capture.pcap
go run ./cmd/wifi-assess -format json /path/to/capture.pcapng > report.json
```

The paths above are placeholders for captures you are authorized to analyze. The CLI accepts a single capture path and `-format console|json`. Malformed captures and read errors return errors. No real-world capture is distributed with the public repository.

## Baseline comparison

```bash
go run ./cmd/wifi-assess -save-baseline baseline.json first.pcapng
go run ./cmd/wifi-assess -baseline baseline.json later.pcapng
```

A baseline stores AP identity, known channel/frequency and the advertised privacy bit when observed. Findings for new or absent BSSIDs are **observations**, not a determination that an AP is rogue or has disappeared. Captures may differ in channel coverage, duration, location or hardware. Fields unknown in either capture do not trigger a change finding. Use different paths for `-baseline` and `-save-baseline`; for baselines created by earlier project versions, save a fresh baseline to include the capability-known marker.

## Interpretation and limitations

| Output | Meaning and limit |
| --- | --- |
| `privacy=set` | Advertised privacy bit; specific encryption and authentication are unknown. |
| Unset Privacy bit (Medium) | WLAN confidentiality is not advertised; review whether an open network is intended before treating it as a policy violation. |
| `assoc_target` | An association request or response addressed this AP; it may have failed. |
| `assoc_success` | A success status was seen in an association response; it does not prove the client remains connected. |
| Duplicate SSID (Info) | Multiple BSSIDs advertise the name; common on legitimate multi-AP networks. |
| Missing baseline AP (Info) | AP was not observed in this capture; capture coverage may differ. |
| Low average signal (Info) | Received signal measured by this capture device; not itself a security weakness. |

The tool does not decrypt traffic, prove an evil twin, or identify an attacker. Its findings are intended for human review. The baseline is a point-in-time observation, not an authoritative inventory; its coverage depends on capture duration, channel coverage, location, adapter and hardware.

## Build and test

```bash
go mod verify
go build ./...
go test ./...
go test -race ./...
go vet ./...
```

Tests create deterministic temporary captures and synthetic frames for CLI integration, PCAP/PCAPNG reading, selected 802.11 parsing cases, association status, baseline changes, assessment rules and JSON output. Public fixtures use invented names and locally administered addresses; broader validation with diverse sanitized real captures remains needed. See [validation plan](docs/validation-plan.md).

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/wifi-assess` | File-based CLI |
| `internal/capture` | PCAP/PCAPNG readers |
| `internal/wifi` | 802.11 parser |
| `internal/discovery` | AP/client inventory and baseline comparison |
| `internal/assessment`, `internal/detection` | Review rules and observations |
| `internal/storage`, `internal/reporting` | Baseline JSON and report output |
| `pkg/models` | Shared data types |

## Roadmap

Future work may include richer security capability parsing (RSN, AKM, ciphers, WPA/WPA2/WPA3, PMF and WPS) backed by a wider sanitized validation corpus. Integration with a separate capture tool could analyze completed rotating PCAP files.

## Responsible use

Analyze only captures and wireless networks you are authorized to inspect.
