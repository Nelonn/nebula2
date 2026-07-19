package nebula

import (
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/handshake"
	"github.com/slackhq/nebula/noiseutil"
)

const ReplayWindow = 1024

type ConnectionState struct {
	eKey           noiseutil.CipherState
	dKey           noiseutil.CipherState
	myCert         cert.Certificate
	peerCert       *cert.CachedCertificate
	initiator      bool
	messageCounter atomic.Uint64
	window         *Bits
	writeLock      sync.Mutex
}

func newConnectionStateFromResult(r *handshake.Result) *ConnectionState {
	ci := &ConnectionState{
		myCert:    r.MyCert,
		initiator: r.Initiator,
		peerCert:  r.RemoteCert,
		eKey:      noiseutil.NewCipherState(r.EKey, r.Cipher),
		dKey:      noiseutil.NewCipherState(r.DKey, r.Cipher),
		window:    NewBits(ReplayWindow),
	}
	ci.messageCounter.Add(r.MessageIndex)
	for i := uint64(1); i <= r.MessageIndex; i++ {
		ci.window.Update(nil, i)
	}
	return ci
}

func (cs *ConnectionState) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{
		"certificate":     cs.peerCert,
		"initiator":       cs.initiator,
		"message_counter": cs.messageCounter.Load(),
	})
}

func (cs *ConnectionState) Curve() cert.Curve {
	return cs.myCert.Curve()
}
