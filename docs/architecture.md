# Architecture

The CLI opens a completed PCAP or PCAPNG file through the `capture.Source` interface and its `PCAPSource` implementation, calls `wifi.ParsePacket` on each packet, and accumulates AP/client observations in `discovery.Tracker`. `assessment` evaluates the resulting APs; `detection` produces informational duplicate-SSID and optional baseline observations. `storage` loads/saves point-in-time baseline JSON; `reporting` prints a console summary or JSON document.

The parser reads management information elements from raw Dot11 payloads because gopacket's automatic chaining varies across management subtypes. It reads association-response status before recording an observed successful exchange. Unknown values from incomplete captures are distinct from known negatives in baseline comparison.

The `Source` interface leaves room for future inputs, but the current public release implements file-based capture analysis only. PCAPNG captures with several interfaces or mixed link types need additional validation. A baseline is a point-in-time snapshot whose completeness depends on channel coverage, capture duration, location and hardware; missing observations are not proof of absence. Assessment and detection findings require human interpretation.
