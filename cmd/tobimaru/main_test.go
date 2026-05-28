package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vkochetkov/tobimaru/internal/detector"
	"github.com/vkochetkov/tobimaru/internal/parser"
)

func TestConsumeFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	frames := make(chan *parser.ParsedFrame, 10)

	done := make(chan struct{})
	go func() {
		consumeFrames(ctx, frames)
		close(done)
	}()

	// Send a few frames.
	for range 3 {
		frames <- &parser.ParsedFrame{
			FrameType: parser.FrameTypeBeacon,
			Channel:   6,
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeFrames did not stop after context cancellation")
	}
}

func TestConsumeFramesChannelClose(t *testing.T) {
	ctx := context.Background()
	frames := make(chan *parser.ParsedFrame, 10)

	done := make(chan struct{})
	go func() {
		consumeFrames(ctx, frames)
		close(done)
	}()

	frames <- &parser.ParsedFrame{FrameType: parser.FrameTypeDeauth, Channel: 11}
	close(frames)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeFrames did not stop after channel close")
	}
}

func TestConsumeAlerts(t *testing.T) {
	alerts := make(chan *detector.SecurityEvent, 10)

	done := make(chan struct{})
	go func() {
		consumeAlerts(context.Background(), alerts)
		close(done)
	}()

	src, _ := net.ParseMAC("00:11:22:33:44:55")
	bss, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Send events of each severity and wait for channel close
	// to ensure all are consumed.
	alerts <- &detector.SecurityEvent{
		EventType:   "deauth_flood",
		Severity:    detector.SeverityCritical,
		SrcMAC:      src,
		BSSID:       bss,
		Channel:     6,
		SSID:        "TestNet",
		Description: "test critical alert",
	}
	alerts <- &detector.SecurityEvent{
		EventType: "suspicious_probe",
		Severity:  detector.SeverityWarning,
		SrcMAC:    src,
		BSSID:     bss,
		Channel:   1,
	}
	alerts <- &detector.SecurityEvent{
		EventType: "new_device",
		Severity:  detector.SeverityInfo,
		SrcMAC:    src,
		BSSID:     bss,
		Channel:   11,
	}
	close(alerts)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeAlerts did not stop after channel close")
	}
}

func TestConsumeAlertsChannelClose(t *testing.T) {
	ctx := context.Background()
	alerts := make(chan *detector.SecurityEvent, 10)

	done := make(chan struct{})
	go func() {
		consumeAlerts(ctx, alerts)
		close(done)
	}()

	alerts <- &detector.SecurityEvent{
		EventType: "test",
		Severity:  detector.SeverityInfo,
		SrcMAC:    net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		BSSID:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	close(alerts)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeAlerts did not stop after channel close")
	}
}
