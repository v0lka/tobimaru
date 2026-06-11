package capture

import (
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// CaptureHandle wraps a pcap handle for live 802.11 frame capture.
type CaptureHandle struct {
	handle    *pcap.Handle
	closeOnce sync.Once
}

// OpenCapture opens a live pcap handle on the given interface for 802.11 capture.
func OpenCapture(iface string, snaplen int, promisc bool, timeout time.Duration, bufferSize int) (*CaptureHandle, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create inactive pcap handle for %s: %w", iface, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snaplen); err != nil {
		return nil, fmt.Errorf("failed to set snaplen: %w", err)
	}
	if err := inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("failed to set promiscuous mode: %w", err)
	}
	if err := inactive.SetTimeout(timeout); err != nil {
		return nil, fmt.Errorf("failed to set timeout: %w", err)
	}
	if err := inactive.SetRFMon(true); err != nil {
		return nil, fmt.Errorf("failed to enable monitor mode capturing: %w", err)
	}
	if err := inactive.SetBufferSize(bufferSize); err != nil {
		return nil, fmt.Errorf("failed to set buffer size: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("failed to activate pcap handle: %w", err)
	}

	// BPF filter is intentionally NOT set.
	//
	// On macOS, BPF captures include a variable-length radiotap header before
	// each 802.11 frame. The BPF filter "type mgt or type ctl or type data"
	// checks the frame type at a FIXED offset from the link-layer start,
	// which does not correctly account for the variable radiotap length.
	// When the filter reads radiotap bytes that happen to match management/
	// control/data type values, non‑802.11 noise passes through. gopacket
	// then decodes the noise at the correct offset (it reads the radiotap
	// length field per-packet) but the data is noise — creating fake BSSIDs
	// and spamming the state engine with hundreds of phantom APs/clients.
	//
	// Without a BPF filter, the kernel delivers all packets from the BPF
	// device (in RFMON mode these are exclusively 802.11 frames). gopacket
	// correctly parses all of them using the per-packet radiotap length,
	// and the Go-level parser drops invalid frames via validateParsedFrame.

	return &CaptureHandle{
		handle: handle,
	}, nil
}

// PacketSource returns a gopacket PacketSource backed by the pcap handle.
// The source produces packets with LinkTypeIEEE80211Radio for RadioTap + Dot11 decoding.
func (c *CaptureHandle) PacketSource() *gopacket.PacketSource {
	return gopacket.NewPacketSource(c.handle, layers.LinkTypeIEEE80211Radio)
}

// Close closes the pcap handle, unblocking any blocking reads.
// It is safe to call multiple times.
func (c *CaptureHandle) Close() {
	c.closeOnce.Do(func() {
		if c.handle != nil {
			c.handle.Close()
		}
	})
}
