package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"wifi-assess/internal/assessment"
	"wifi-assess/internal/capture"
	"wifi-assess/internal/detection"
	"wifi-assess/internal/discovery"
	"wifi-assess/internal/reporting"
	"wifi-assess/internal/storage"
	"wifi-assess/internal/wifi"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "wifi-assess:", err)
		os.Exit(1)
	}
}

func run(args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("wifi-assess", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseline := flags.String("baseline", "", "previous baseline JSON to compare")
	saveBaseline := flags.String("save-baseline", "", "save this run's baseline JSON")
	format := flags.String("format", "console", "output format: console or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: wifi-assess [-baseline file] [-save-baseline file] [-format console|json] <capture.pcap|capture.pcapng>")
	}
	if *format != "json" && *format != "console" {
		return fmt.Errorf("format must be console or json")
	}
	if *saveBaseline != "" && *baseline == *saveBaseline {
		return fmt.Errorf("baseline and save-baseline must be different paths")
	}
	name := flags.Arg(0)
	var src capture.Source = capture.NewPCAPSource(name)
	if err := src.Open(); err != nil {
		return fmt.Errorf("open capture: %w", err)
	}
	defer src.Close()
	r := reporting.Report{CapturedAt: time.Now(), Source: name, FrameCounts: map[string]int{}}
	tracker := discovery.NewTracker()
	for {
		pkt, err := src.ReadPacket()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read packet: %w", err)
		}
		r.PacketCount++
		parsed, err := wifi.ParsePacket(pkt)
		if err != nil {
			r.Skipped++
			continue
		}
		r.FrameCounts[parsed.FrameType]++
		tracker.Observe(parsed)
	}
	r.AccessPoints = tracker.AccessPoints()
	sort.Slice(r.AccessPoints, func(i, j int) bool { return r.AccessPoints[i].BSSID < r.AccessPoints[j].BSSID })
	r.Clients = tracker.Clients()
	sort.Slice(r.Clients, func(i, j int) bool { return r.Clients[i].MAC < r.Clients[j].MAC })
	findings := assessment.DefaultEngine().AssessAccessPoints(r.AccessPoints)
	for _, dup := range detection.FindDuplicateSSIDs(r.AccessPoints) {
		findings = append(findings, detection.DuplicateSSIDToFinding(dup))
	}
	if *baseline != "" {
		prev, err := storage.LoadBaseline(*baseline)
		if err != nil {
			return fmt.Errorf("load baseline: %w", err)
		}
		for _, a := range detection.FromBaselineDiff(prev.Diff(discovery.NewBaseline(tracker))) {
			findings = append(findings, detection.AnomalyToFinding(a))
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.BSSID != b.BSSID {
			return a.BSSID < b.BSSID
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.SSID < b.SSID
	})
	r.Findings = findings
	if *saveBaseline != "" {
		if err := storage.SaveBaseline(*saveBaseline, discovery.NewBaseline(tracker)); err != nil {
			return fmt.Errorf("save baseline: %w", err)
		}
	}
	if *format == "json" {
		return reporting.WriteJSON(out, r)
	}
	if err := reporting.WriteConsole(out, r); err != nil {
		return err
	}
	if *saveBaseline != "" {
		_, err := fmt.Fprintf(out, "\nBaseline saved to %s\n", *saveBaseline)
		return err
	}
	return nil
}
