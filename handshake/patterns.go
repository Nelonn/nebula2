package handshake

import (
	"fmt"

	"github.com/slackhq/nebula/header"
)

type msgFlags struct {
	expectsPayload bool
	expectsCert    bool
}

type subtypeInfo struct {
	msgs []msgFlags
}

var subtypeInfos = map[header.MessageSubType]subtypeInfo{
	header.HandshakeHPKE0: {
		msgs: []msgFlags{
			{expectsPayload: true, expectsCert: true},
			{expectsPayload: true, expectsCert: true},
		},
	},
}

func subtypeInfoFor(subtype header.MessageSubType) (subtypeInfo, error) {
	if info, ok := subtypeInfos[subtype]; ok {
		return info, nil
	}
	return subtypeInfo{}, fmt.Errorf("%w: %d", ErrUnknownSubtype, subtype)
}
