# Validation plan

These are future validation goals, not completed results. Public tests currently use small deterministic in-memory frames and temporary PCAP/PCAPNG captures. Real-world captures are excluded from the repository unless identifiers, probe history and payloads have been reviewed and sanitization verified.

- Expand synthetic management-frame cases: probe responses, association requests and malformed responses, varied BSSID/address combinations, multiple/unknown IEs and truncated bodies.
- Validate capture readers with PCAP and PCAPNG across link types and multiple interfaces where supported.
- Review sanitized, authorized captures from several adapters, channels and bands (2.4/5/6 GHz where available) without publishing private identifiers.
- When RSN parsing is implemented, add deterministic WPA/WPA2/WPA3, AKM, cipher, PMF and WPS capability cases.
- Review false positives and interpretation of each assessment rule across differing capture duration, channel coverage and hardware.

Do not use these goals as evidence of detection accuracy until results are measured and documented.
