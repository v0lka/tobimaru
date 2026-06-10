# Tobimaru on macOS — Setup Guide

## Prerequisites

- macOS 13 (Ventura) or later
- Administrative (root) access for packet capture
- No additional utilities required — channel switching uses the built-in CoreWLAN framework

## 1. BPF Device Permissions

Packet capture on macOS requires access to `/dev/bpf*` Berkeley Packet Filter
devices. By default these are owned by `root:wheel` with permissions `rw-------`
and are reset on every reboot.

### Option A: Run as Root (Simplest)

```bash
sudo ./tobimaru-darwin-arm64 -config configs/tobimaru.yaml
```

### Option B: ChmodBPF (Persistent)

Install a LaunchDaemon that sets BPF permissions on boot, similar to Wireshark's
ChmodBPF. Create `/Library/LaunchDaemons/org.tobimaru.chmodbpf.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.tobimaru.chmodbpf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>chgrp admin /dev/bpf* && chmod 660 /dev/bpf*</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

Load it:

```bash
sudo launchctl load /Library/LaunchDaemons/org.tobimaru.chmodbpf.plist
```

Add your user to the `admin` group (usually already there) and you can run
Tobimaru without `sudo`.

### Option C: LaunchDaemon for Tobimaru

Create a LaunchDaemon that runs Tobimaru as root at boot:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.vkochetkov.tobimaru</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/tobimaru</string>
        <string>-config</string>
        <string>/etc/tobimaru.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/tobimaru.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/tobimaru.log</string>
</dict>
</plist>
```

## 3. Configuration for macOS

Set `monitor.interface` to your Wi-Fi interface. On most Macs this is `en0`.
You can find the correct interface with:

```bash
ifconfig | grep -B 1 -A 5 status:.*active
```

Look for the interface with `ether` (MAC address) that is not `awdl0` or `llw0`.

Recommended macOS configuration in `configs/tobimaru.yaml`:

```yaml
monitor:
  interface: "en0"
  channel_hopping:
    enabled: true
    dwell: 2s              # Channel switching via CoreWLAN has 1-3s overhead
    weighted_dwell:
      enabled: true
      primary_channels: [1, 6, 11]
      multiplier: 2.5
    channels_2ghz: [1, 6, 11]  # Reduced set for single-channel macOS
    include_5ghz: false
```

The Pipeline automatically enforces a minimum dwell of 1 second on macOS,
but 2 seconds is recommended for stable operation. Reducing the channel
list (e.g., to primary channels 1, 6, 11 only) improves results since
macOS can only listen on one channel at a time.

## 4. Known Limitations on macOS

| Feature | Status |
|---------|--------|
| Monitor mode capture | Supported via BPF (pcap.SetRFMon) |
| Channel hopping | Supported via CoreWLAN cgo bridge (1-3s per switch) |
| Frame injection | **Not supported** on built-in adapters |
| Simultaneous monitor + WiFi connection | **Not supported** (single adapter) |
| External USB WiFi adapter | Requires kext (blocked since Big Sur) or DriverKit |
| Apple Silicon (M1/M2/M3/M4) | Monitor mode available but less stable than Intel Macs |
| macOS 14.4+ (Sonoma/Sequoia/Tahoe) | Airport utility deprecated; CoreWLAN bridge used instead |

The `IsSupported()` check returns `true` on macOS, but platform capabilities
are detected at runtime and logged. Active countermeasures (frame injection
from Phase 7) will log as unavailable and will never be attempted.

## 5. Verifying the Installation

### Check the binary works

```bash
./tobimaru-darwin-arm64 --version
```

Expected output: `Tobimaru v<version> (commit: <hash>, built: <date>)`

### Start monitoring

```bash
sudo ./tobimaru-darwin-arm64 -config configs/tobimaru.yaml
```

Watch the log output. You should see:

```
INFO platform capabilities monitor_mode=true frame_injection=false channel_hopping=true slow_hopping=true single_adapter=true
WARN platform limitation detail="frame injection is not supported"
WARN platform limitation detail="single channel only; full channel hopping is not available"
WARN platform limitation detail="channel switching has high overhead; increase dwell time"
WARN platform limitation detail="single WiFi adapter; cannot operate in monitor and managed mode simultaneously"
INFO enabling monitor mode via BPF SetRFMon; ensure WiFi is disconnected manually before capture interface=en0
INFO capture started interface=en0 channel_hopping=true
```

### Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Permission denied` on `/dev/bpf*` | Not running as root | Use `sudo` or set up ChmodBPF |
| `pcap: no such device` | Wrong interface name | Check interface with `ifconfig` |
| No frames captured after start | Interface still connected to WiFi | Disconnect from WiFi before starting capture |

## 6. Uninstalling

```bash
sudo launchctl unload /Library/LaunchDaemons/org.tobimaru.chmodbpf.plist 2>/dev/null
sudo rm /Library/LaunchDaemons/org.tobimaru.chmodbpf.plist 2>/dev/null
```
