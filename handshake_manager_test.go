package nebula

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/test"
	"github.com/slackhq/nebula/udp"
)

type mockEncWriter struct{}

func (mw *mockEncWriter) SendMessageToVpnAddr(_ header.MessageType, _ header.MessageSubType, _ netip.Addr, _, _, _ []byte) {
}
func (mw *mockEncWriter) SendVia(_ *HostInfo, _ *Relay, _, _, _ []byte, _ bool) {
}
func (mw *mockEncWriter) SendMessageToHostInfo(_ header.MessageType, _ header.MessageSubType, _ *HostInfo, _, _, _ []byte) {
}
func (mw *mockEncWriter) Handshake(_ netip.Addr) {}
func (mw *mockEncWriter) GetHostInfo(_ netip.Addr) *HostInfo { return nil }
func (mw *mockEncWriter) GetCertState() *CertState {
	return &CertState{initiatingVersion: cert.Version3}
}

func Test_NewHandshakeManagerVpnIp(t *testing.T) {
	l := test.NewLogger()
	localrange := netip.MustParsePrefix("10.1.1.1/24")
	ip := netip.MustParseAddr("172.1.1.2")

	preferredRanges := []netip.Prefix{localrange}
	mainHM := newHostMap(l)
	mainHM.preferredRanges.Store(&preferredRanges)

	lh := newTestLighthouse()

	cs := &CertState{
		initiatingVersion: cert.Version3,
		privateKey:        []byte{},
		v3Cert:            &dummyCert{version: cert.Version3},
	}
	_ = cs

	blah := NewHandshakeManager(l, mainHM, lh, &udp.NoopConn{}, defaultHandshakeConfig)
	blah.f = &Interface{handshakeManager: blah, pki: &PKI{}, l: l}

	_, _ = blah.GetOrHandshake(ip, nil)
	blah.OutboundHandshakeTimer.Advance(time.Now())
	_, _ = blah.OutboundHandshakeTimer.Purge()
	blah.NextOutboundHandshakeTimerTick(time.Now())
	_ = blah.QueryVpnAddr(ip)
	// Using a minimal callback to avoid nil pointer dereference
	blah.ForEachVpnAddr(func(_ *HostInfo) {})
}
