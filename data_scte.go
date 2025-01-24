package astits

import (
	"fmt"

	"github.com/asticode/go-astikit"
)

const (
	scte35TableID = 0xfc
)

func extractSCTE35Payload(it *astikit.BytesIterator) ([]byte, error) {
	payload := it.Dump()
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty payload")
	}
	start := int(payload[0]) + 1
	if start >= len(payload) || start < 0 {
		return nil, fmt.Errorf("invalid SCTE35 start index: %d, payload length %d", start, len(payload))
	}
	if payload[start] != scte35TableID {
		return nil, fmt.Errorf("invalid SCTE35 table id: %x", payload[0])
	}
	b0 := payload[start+1]
	b1 := payload[start+2]
	size := uint16(b0&0xf)<<8 | uint16(b1)
	end := size + 4
	if int(end) > len(payload) {
		return nil, fmt.Errorf("invalid SCTE35 end index: %d, payload length %d", end, len(payload))
	}
	return payload[start:end], nil
}
