//go:build darwin

#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>

// SetInterfaceChannel sets the WiFi interface to the specified channel number
// via CoreWLAN. Returns true on success, false if the interface is not found
// or the channel is not supported.
//
// IMPORTANT: This function looks up the CWChannel object from the interface's
// supportedWLANChannels set. Do NOT attempt to create a new CWChannel object
// with [[CWChannel alloc] init...] — this crashes with NSException on macOS
// 14.4+ (see bettercap PR #1100 / commit 0dc5f66).
bool SetInterfaceChannel(const char *iface, int channel) {
    @autoreleasepool {
        NSString *ifName = [NSString stringWithUTF8String:iface];
        CWInterface *interface = [[CWWiFiClient sharedWiFiClient] interfaceWithName:ifName];
        if (!interface) {
            return false;
        }

        NSSet *supportedChannels = [interface supportedWLANChannels];
        for (CWChannel *ch in supportedChannels) {
            if ([ch channelNumber] == channel) {
                [interface setWLANChannel:ch error:nil];
                return true;
            }
        }
        return false;
    }
}
