package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflinePCAPAndPCAPNG(t *testing.T) {
	for _, ext := range []string{"pcap", "pcapng"} {
		t.Run(ext, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input."+ext)
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte{0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 0, 0}
			if ext == "pcap" {
				w := pcapgo.NewWriter(f)
				err = w.WriteFileHeader(65535, layers.LinkTypeIEEE802_11)
				if err == nil {
					err = w.WritePacket(gopacket.CaptureInfo{CaptureLength: len(payload), Length: len(payload)}, payload)
				}
			} else {
				var w *pcapgo.NgWriter
				w, err = pcapgo.NewNgWriter(f, layers.LinkTypeIEEE802_11)
				if err == nil {
					err = w.WritePacket(gopacket.CaptureInfo{CaptureLength: len(payload), Length: len(payload)}, payload)
				}
				if err == nil {
					err = w.Flush()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			s := NewPCAPSource(path)
			if err = s.Open(); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			p, err := s.ReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Data()) != len(payload) {
				t.Fatalf("packet length %d", len(p.Data()))
			}
			_, err = s.ReadPacket()
			if err != io.EOF {
				t.Fatalf("expected EOF, got %v", err)
			}
		})
	}
}
func TestInvalidCaptureClosesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(path, []byte("this is not a capture"), 0600); err != nil {
		t.Fatal(err)
	}
	s := NewPCAPSource(path)
	if err := s.Open(); err == nil {
		t.Fatal("accepted invalid capture")
	}
	if _, err := s.ReadPacket(); err == nil {
		t.Fatal("read accepted closed source")
	}
}
