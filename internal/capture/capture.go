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

	// Set BPF filter for 802.11 management, control, and data frames.
	filter := "type mgt or type ctl or type data"
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

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
