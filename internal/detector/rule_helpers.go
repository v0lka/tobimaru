package detector

import (
	"fmt"
	"net"

	"github.com/vkochetkov/tobimaru/internal/parser"
)

func invalidRuleConfig(ruleName, message string) error {
	return fmt.Errorf("%s invalid config: %s", ruleName, message)
}

func normalizeMAC(value string) (string, error) {
	mac, err := net.ParseMAC(value)
	if err != nil {
		return "", err
	}

	return mac.String(), nil
}

func isBroadcastMAC(mac net.HardwareAddr) bool {
	return len(mac) == 6 &&
		mac[0] == 0xff &&
		mac[1] == 0xff &&
		mac[2] == 0xff &&
		mac[3] == 0xff &&
		mac[4] == 0xff &&
		mac[5] == 0xff
}

func frameTypeName(frameType parser.FrameType) string {
	switch frameType {
	case parser.FrameTypeAssocReq:
		return "assoc_req"
	case parser.FrameTypeReassocReq:
		return "reassoc_req"
	case parser.FrameTypeAuth:
		return "auth"
	case parser.FrameTypeProbeRequest:
		return "probe_request"
	default:
		return frameType.String()
	}
}
