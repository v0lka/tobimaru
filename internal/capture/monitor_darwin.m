//go:build darwin

#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>

// GetSupportedWLANChannels returns all supported channel numbers for the
// given WiFi interface as a space-separated string (e.g. "1 6 11 36 40").
// Returns NULL on failure, in which case *errStr is set to a heap-allocated
// error message (caller must free both with free()). On success, *errStr
// is set to NULL and the returned string must be freed with free().
char* GetSupportedWLANChannels(const char *iface, char **errStr) {
    @autoreleasepool {
        NSString *ifName = [NSString stringWithUTF8String:iface];
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        if (!client) {
            *errStr = strdup("CWWiFiClient sharedWiFiClient returned nil");
            return NULL;
        }

        CWInterface *interface = [client interfaceWithName:ifName];
        if (!interface) {
            NSString *reason = [NSString stringWithFormat:
                @"CWWiFiClient interfaceWithName returned nil for '%@'", ifName];
            *errStr = strdup([reason UTF8String]);
            return NULL;
        }

        NSSet *supportedChannels = [interface supportedWLANChannels];
        if (!supportedChannels || [supportedChannels count] == 0) {
            NSString *reason = [NSString stringWithFormat:
                @"supportedWLANChannels is empty for '%@'", ifName];
            *errStr = strdup([reason UTF8String]);
            return NULL;
        }

        NSMutableString *channels = [NSMutableString string];
        for (CWChannel *ch in supportedChannels) {
            [channels appendFormat:@"%ld ", (long)[ch channelNumber]];
        }
        *errStr = NULL;
        return strdup([channels UTF8String]);
    }
}

// SetInterfaceChannel sets the WiFi interface to the specified channel number
// via CoreWLAN. Returns NULL on success, or a heap-allocated C string (owned
// by the caller, must be freed with free()) describing the failure reason.
//
// IMPORTANT: This function looks up the CWChannel object from the interface's
// supportedWLANChannels set. Do NOT attempt to create a new CWChannel object
// with [[CWChannel alloc] init...] — this crashes with NSException on macOS
// 14.4+ (see bettercap PR #1100 / commit 0dc5f66).
char* SetInterfaceChannel(const char *iface, int channel) {
    @autoreleasepool {
        NSString *ifName = [NSString stringWithUTF8String:iface];
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        if (!client) {
            return strdup("CWWiFiClient sharedWiFiClient returned nil");
        }

        CWInterface *interface = [client interfaceWithName:ifName];
        if (!interface) {
            NSString *reason = [NSString stringWithFormat:
                @"CWWiFiClient interfaceWithName returned nil for '%@' — "
                @"Wi-Fi may be turned off or the interface name is incorrect", ifName];
            return strdup([reason UTF8String]);
        }

        // Log interface state for diagnostics.
        NSLog(@"[tobimaru] CoreWLAN interface=%@ powerOn=%d serviceActive=%d ssid=%@ bssid=%@",
              [interface interfaceName],
              [interface powerOn],
              [interface serviceActive],
              [interface ssid] ?: @"(none)",
              [interface bssid] ?: @"(none)");

        NSSet *supportedChannels = [interface supportedWLANChannels];
        if (!supportedChannels || [supportedChannels count] == 0) {
            NSString *reason = [NSString stringWithFormat:
                @"supportedWLANChannels is empty for '%@' — "
                @"the interface may not be ready", ifName];
            return strdup([reason UTF8String]);
        }

        for (CWChannel *ch in supportedChannels) {
            if ([ch channelNumber] == channel) {
                NSError *error = nil;
                BOOL ok = [interface setWLANChannel:ch error:&error];
                if (!ok) {
                    NSString *reason = [NSString stringWithFormat:
                        @"setWLANChannel:%d on '%@' failed: %@ (domain=%@, code=%ld)",
                        channel, ifName,
                        [error localizedDescription] ?: @"(no description)",
                        [error domain] ?: @"(no domain)",
                        (long)[error code]];
                    return strdup([reason UTF8String]);
                }
                return NULL;
            }
        }

        // Channel not found in supported set — list what IS supported.
        NSMutableString *supported = [NSMutableString string];
        for (CWChannel *ch in supportedChannels) {
            [supported appendFormat:@"%ld ", (long)[ch channelNumber]];
        }
        NSString *reason = [NSString stringWithFormat:
            @"channel %d is not in supportedWLANChannels for '%@'. Supported: %@",
            channel, ifName, supported];
        return strdup([reason UTF8String]);
    }
}
