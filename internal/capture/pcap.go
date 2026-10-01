package capture

import (
	"bufio"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// PCAPSource reads classic pcap and pcapng files without requiring libpcap.
type PCAPSource struct {
	fileName     string
	file         *os.File
	packetSource *gopacket.PacketSource
}

func NewPCAPSource(fileName string) *PCAPSource { return &PCAPSource{fileName: fileName} }

func (p *PCAPSource) Open() error {
	if p.file != nil {
		return fmt.Errorf("capture: source already open")
	}
	f, err := os.Open(p.fileName)
	if err != nil {
		return err
	}
	r := bufio.NewReader(f)
	magic, err := r.Peek(4)
	if err != nil {
		f.Close()
		return fmt.Errorf("capture: read magic: %w", err)
	}
	var reader packetReader
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		reader, err = pcapgo.NewNgReader(r, pcapgo.NgReaderOptions{})
	} else {
		reader, err = pcapgo.NewReader(r)
	}
	if err != nil {
		f.Close()
		return fmt.Errorf("capture: open capture: %w", err)
	}
	p.file = f
	p.packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	return nil
}

func (p *PCAPSource) ReadPacket() (gopacket.Packet, error) {
	if p.packetSource == nil {
		return nil, fmt.Errorf("capture: source not open")
	}
	return p.packetSource.NextPacket()
}
func (p *PCAPSource) Close() error {
	if p.file == nil {
		return nil
	}
	err := p.file.Close()
	p.file = nil
	p.packetSource = nil
	return err
}

var _ Source = (*PCAPSource)(nil)
