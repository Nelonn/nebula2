package nebula

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv6"

	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
	"golang.org/x/net/ipv4"
)

const (
	minFwPacketLen = 4
)

var ErrOutOfWindow = errors.New("out of window packet")

func (f *Interface) readOutsidePackets(via ViaSender, out []byte, packet []byte, h *header.H, fwPacket *firewall.Packet, lhf *LightHouseHandler, nb []byte, q int, localCache firewall.ConntrackCache) {
	// Prioritized dispatch: data first (fast path), then legacy, then handshake.

	// 1. Data packet — one AES-ECB decrypt, O(1) session lookup (fast path)
	//    Run BEFORE handshake continuation to avoid false collision (1/2^32).
	if len(packet) >= 16 {
		var encHdr [16]byte
		copy(encHdr[:], packet[:16])
		var decHdr [16]byte
		f.pki.HeaderBlock().Decrypt(decHdr[:], encHdr[:])
		sessionID := binary.BigEndian.Uint32(decHdr[0:4])
		if hi := f.hostMap.QueryIndex(sessionID); hi != nil && hi.ConnectionState != nil {
			f.processDataPacketV2(via, hi, packet, decHdr, nb, out, lhf, fwPacket, q, localCache)
			return
		}
	}

	// 2. Handshake msg2 continuation — O(1) index lookup
	if len(packet) > 4 {
		idx := binary.BigEndian.Uint32(packet[:4])
		if hh := f.handshakeManager.QueryIndex(idx); hh != nil {
			f.handshakeManager.HandleIncoming(via, packet[4:], idx)
			return
		}
	}

	// 3. Try legacy header.Parse — lighthouse/recverror have plaintext headers.
	//    If parse fails, it's not a legacy packet — fall through to TrialDecap.
	parseErr := h.Parse(packet)
	if parseErr == nil {
		if h.Version == header.Version && h.IsValidSubType() {
			if via.IsRelayed || !f.myVpnNetworksTable.Contains(via.UdpAddr.Addr()) {
				if h.Type != header.Message {
					f.messageMetrics.Rx(h.Type, h.Subtype, 1)
				}
				switch h.Type {
				case header.RecvError:
					f.handleRecvError(via.UdpAddr, h)
					return
				case header.LightHouse:
					lhf.HandleRequest(via.UdpAddr, nil, packet, f)
					return
				}
			}
		}
	}

	// 4. TrialDecap — asymmetric crypto, last resort for handshake msg1.
	if len(packet) > 16 {
		f.handshakeManager.TrialDecap(via, packet)
	}
}

func (f *Interface) processDataPacketV2(via ViaSender, hostinfo *HostInfo, packet []byte, decHdr [16]byte, nb, out []byte, lhf *LightHouseHandler, fwPacket *firewall.Packet, q int, localCache firewall.ConntrackCache) {
	c := binary.BigEndian.Uint64(decHdr[6:14])
	msgType := header.MessageType(decHdr[4])
	msgSubtype := header.MessageSubType(decHdr[5])
	ci := hostinfo.ConnectionState
	if ci == nil {
		return
	}

	if !ci.window.Check(f.l, c) {
		return
	}

	pt, err := ci.dKey.DecryptDanger(out, packet[:16], packet[16:], c, nb)
	if err != nil {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Failed to decrypt packet", "error", err, "from", via)
		}
		return
	}
	if !ci.window.Update(f.l, c) {
		return
	}

	f.handleHostRoaming(hostinfo, via)
	f.connectionManager.In(hostinfo)

	switch msgType {
	case header.Message:
		switch msgSubtype {
		case header.MessageNone:
			f.handleOutsideMessagePacket(hostinfo, pt, packet, fwPacket, nb, q, localCache)
		default:
			hostinfo.logger(f.l).Error("unexpected message subtype", "from", via, "subtype", msgSubtype)
		}
	case header.CloseTunnel:
		hostinfo.logger(f.l).Info("Close tunnel received, tearing down.", "from", via)
		f.closeTunnel(hostinfo)
	case header.Control:
		f.relayManager.HandleControlMsg(hostinfo, pt, f)
	case header.Test:
		switch msgSubtype {
		case header.TestReply:
		case header.TestRequest:
			f.send(header.Test, header.TestReply, ci, hostinfo, pt, nb, packet)
		}
	case header.LightHouse:
		if !via.IsRelayed && lhf != nil {
			lhf.HandleRequest(via.UdpAddr, hostinfo.vpnAddrs, pt, f)
		}
	default:
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Unknown message type", "from", via, "type", msgType)
		}
	}
}

func (f *Interface) handleOutsideRelayPacket(hostinfo *HostInfo, via ViaSender, out []byte, packet []byte, h *header.H, fwPacket *firewall.Packet, lhf *LightHouseHandler, nb []byte, q int, localCache firewall.ConntrackCache) {
	// The entire body is sent as AD, not encrypted.
	// The packet consists of a 16-byte parsed Nebula header, Associated Data-protected payload, and a trailing 16-byte AEAD signature value.
	// The packet is guaranteed to be at least 16 bytes at this point, b/c it got past the h.Parse() call above. If it's
	// otherwise malformed (meaning, there is no trailing 16 byte AEAD value), then this will result in at worst a 0-length slice
	// which will gracefully fail in the DecryptDanger call.
	signedPayload := packet[:len(packet)-hostinfo.ConnectionState.dKey.Overhead()]
	signatureValue := packet[len(packet)-hostinfo.ConnectionState.dKey.Overhead():]
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, signedPayload, signatureValue, h.MessageCounter, nb)
	if err != nil {
		return
	}
	// Advance the replay window now that the frame is authenticated
	if !hostinfo.ConnectionState.window.Update(f.l, h.MessageCounter) {
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping out of window relay packet", "header", h)
		}
		return
	}
	// Successfully validated the thing. Get rid of the Relay header.
	signedPayload = signedPayload[header.Len:]
	// Pull the Roaming parts up here, and return in all call paths.
	f.handleHostRoaming(hostinfo, via)
	// Track usage of both the HostInfo and the Relay for the received & authenticated packet
	f.connectionManager.In(hostinfo)
	f.connectionManager.RelayUsed(h.RemoteIndex)

	relay, ok := hostinfo.relayState.QueryRelayForByIdx(h.RemoteIndex)
	if !ok {
		// The only way this happens is if hostmap has an index to the correct HostInfo, but the HostInfo is missing
		// its internal mapping. This should never happen.
		hostinfo.logger(f.l).Error("HostInfo missing remote relay index",
			"relayRemoteIndex", h.RemoteIndex,
		)
		return
	}

	switch relay.Type {
	case TerminalType:
		// If I am the target of this relay, process the unwrapped packet
		// From this recursive point, all these variables are 'burned'. We shouldn't rely on them again.
		via = ViaSender{
			UdpAddr:   via.UdpAddr,
			relayHI:   hostinfo,
			relay:     relay,
			IsRelayed: true,
		}
		f.readOutsidePackets(via, out[:0], signedPayload, h, fwPacket, lhf, nb, q, localCache)
	case ForwardingType:
		// Find the target HostInfo relay object
		targetHI, targetRelay, err := f.hostMap.QueryVpnAddrsRelayFor(hostinfo.vpnAddrs, relay.PeerAddr)
		if err != nil {
			hostinfo.logger(f.l).Info("Failed to find target host info by ip",
				"relayTo", relay.PeerAddr,
				"relayFrom", hostinfo.vpnAddrs[0],
				"error", err,
			)
			return
		}

		// If that relay is Established, forward the payload through it
		if targetRelay.State == Established {
			switch targetRelay.Type {
			case ForwardingType:
				// Forward this packet through the relay tunnel
				// Find the target HostInfo
				f.SendVia(targetHI, targetRelay, signedPayload, nb, out, false)
			case TerminalType:
				hostinfo.logger(f.l).Error("Unexpected Relay Type of Terminal")
				return
			default:
				if f.l.Enabled(context.Background(), slog.LevelDebug) {
					hostinfo.logger(f.l).Debug("Unexpected targetRelay Type", "from", via, "relayType", targetRelay.Type)
				}
				return
			}
		} else {
			hostinfo.logger(f.l).Info("Unexpected target relay state",
				"relayTo", relay.PeerAddr,
				"relayFrom", hostinfo.vpnAddrs[0],
				"targetRelayState", targetRelay.State,
			)
			return
		}
	default:
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("Unexpected relay type", "from", via, "relayType", relay.Type)
		}
	}
}

// closeTunnel closes a tunnel locally, it does not send a closeTunnel packet to the remote
func (f *Interface) closeTunnel(hostInfo *HostInfo) {
	final := f.hostMap.DeleteHostInfo(hostInfo)
	if final {
		// We no longer have any tunnels with this vpn addr, clear learned lighthouse state to lower memory usage
		f.lightHouse.DeleteVpnAddrs(hostInfo.vpnAddrs)
	}
}

// sendCloseTunnel is a helper function to send a proper close tunnel packet to a remote
func (f *Interface) sendCloseTunnel(h *HostInfo) {
	f.send(header.CloseTunnel, 0, h.ConnectionState, h, []byte{}, make([]byte, 12, 12), make([]byte, mtu))
}

func (f *Interface) handleHostRoaming(hostinfo *HostInfo, via ViaSender) {
	curRemote := hostinfo.GetRemote()
	if !via.IsRelayed && curRemote != via.UdpAddr {
		if !f.lightHouse.GetRemoteAllowList().AllowAll(hostinfo.vpnAddrs, via.UdpAddr.Addr()) {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("lighthouse.remote_allow_list denied roaming", "newAddr", via.UdpAddr)
			}
			return
		}

		if !hostinfo.lastRoam.IsZero() && via.UdpAddr == hostinfo.lastRoamRemote && time.Since(hostinfo.lastRoam) < RoamingSuppressSeconds*time.Second {
			if f.l.Enabled(context.Background(), slog.LevelDebug) {
				hostinfo.logger(f.l).Debug("Suppressing roam back to previous remote",
					"suppressSeconds", RoamingSuppressSeconds,
					"udpAddr", curRemote,
					"newAddr", via.UdpAddr,
				)
			}
			return
		}

		hostinfo.logger(f.l).Info("Host roamed to new udp ip/port.",
			"udpAddr", curRemote,
			"newAddr", via.UdpAddr,
		)
		hostinfo.lastRoam = time.Now()
		hostinfo.lastRoamRemote = curRemote
		hostinfo.SetRemote(via.UdpAddr)
	}

}

var (
	ErrPacketTooShort          = errors.New("packet is too short")
	ErrUnknownIPVersion        = errors.New("packet is an unknown ip version")
	ErrIPv4InvalidHeaderLength = errors.New("invalid ipv4 header length")
	ErrIPv4PacketTooShort      = errors.New("ipv4 packet is too short")
	ErrIPv6PacketTooShort      = errors.New("ipv6 packet is too short")
	ErrIPv6CouldNotFindPayload = errors.New("could not find payload in ipv6 packet")
)

// newPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
func newPacket(data []byte, incoming bool, fp *firewall.Packet) error {
	if len(data) < 1 {
		return ErrPacketTooShort
	}

	version := int((data[0] >> 4) & 0x0f)
	switch version {
	case ipv4.Version:
		return parseV4(data, incoming, fp)
	case ipv6.Version:
		return parseV6(data, incoming, fp)
	}
	return ErrUnknownIPVersion
}

func parseV6(data []byte, incoming bool, fp *firewall.Packet) error {
	dataLen := len(data)
	if dataLen < ipv6.HeaderLen {
		return ErrIPv6PacketTooShort
	}

	if incoming {
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[8:24])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[24:40])
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[8:24])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[24:40])
	}

	protoAt := 6             // NextHeader is at 6 bytes into the ipv6 header
	offset := ipv6.HeaderLen // Start at the end of the ipv6 header
	next := 0
	for {
		if protoAt >= dataLen {
			break
		}
		proto := layers.IPProtocol(data[protoAt])

		switch proto {
		case layers.IPProtocolESP, layers.IPProtocolNoNextHeader:
			fp.Protocol = uint8(proto)
			fp.RemotePort = 0
			fp.LocalPort = 0
			fp.Fragment = false
			return nil

		case layers.IPProtocolICMPv6:
			if dataLen < offset+6 {
				return ErrIPv6PacketTooShort
			}
			fp.Protocol = uint8(proto)
			fp.LocalPort = 0 //incoming vs outgoing doesn't matter for icmpv6
			icmptype := data[offset+1]
			switch icmptype {
			case layers.ICMPv6TypeEchoRequest, layers.ICMPv6TypeEchoReply:
				fp.RemotePort = binary.BigEndian.Uint16(data[offset+4 : offset+6]) //identifier
			default:
				fp.RemotePort = 0
			}
			fp.Fragment = false
			return nil

		case layers.IPProtocolTCP, layers.IPProtocolUDP:
			if dataLen < offset+4 {
				return ErrIPv6PacketTooShort
			}

			fp.Protocol = uint8(proto)
			if incoming {
				fp.RemotePort = binary.BigEndian.Uint16(data[offset : offset+2])
				fp.LocalPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			} else {
				fp.LocalPort = binary.BigEndian.Uint16(data[offset : offset+2])
				fp.RemotePort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			}

			fp.Fragment = false
			return nil

		case layers.IPProtocolIPv6Fragment:
			// Fragment header is 8 bytes, need at least offset+4 to read the offset field
			if dataLen < offset+8 {
				return ErrIPv6PacketTooShort
			}

			// Check if this is the first fragment
			fragmentOffset := binary.BigEndian.Uint16(data[offset+2:offset+4]) &^ uint16(0x7) // Remove the reserved and M flag bits
			if fragmentOffset != 0 {
				// Non-first fragment, use what we have now and stop processing
				fp.Protocol = data[offset]
				fp.Fragment = true
				fp.RemotePort = 0
				fp.LocalPort = 0
				return nil
			}

			// The next loop should be the transport layer since we are the first fragment
			next = 8 // Fragment headers are always 8 bytes

		case layers.IPProtocolAH:
			// Auth headers, used by IPSec, have a different meaning for header length
			if dataLen <= offset+1 {
				break
			}
			next = (int(data[offset+1]) + 2) << 2

		default:
			// Normal ipv6 header length processing
			if dataLen <= offset+1 {
				break
			}
			next = (int(data[offset+1]) + 1) << 3
		}

		if next <= 0 {
			// Safety check, each ipv6 header has to be at least 8 bytes
			next = 8
		}

		protoAt = offset
		offset = offset + next
	}

	return ErrIPv6CouldNotFindPayload
}

func parseV4(data []byte, incoming bool, fp *firewall.Packet) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return ErrIPv4PacketTooShort
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well-formed ip header length?
	if ihl < ipv4.HeaderLen {
		return ErrIPv4InvalidHeaderLength
	}

	// Check if this is the second or further fragment of a fragmented packet.
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	fp.Fragment = (flagsfrags & 0x1FFF) != 0

	// Firewall handles protocol checks
	fp.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !fp.Fragment {
		if fp.Protocol == firewall.ProtoICMP {
			minLen += minFwPacketLen + 2
		} else {
			minLen += minFwPacketLen
		}
	}

	if len(data) < minLen {
		return ErrIPv4InvalidHeaderLength
	}

	if incoming { // Firewall packets are locally oriented
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.LocalAddr, _ = netip.AddrFromSlice(data[16:20])
	} else {
		fp.LocalAddr, _ = netip.AddrFromSlice(data[12:16])
		fp.RemoteAddr, _ = netip.AddrFromSlice(data[16:20])
	}

	if fp.Fragment {
		fp.RemotePort = 0
		fp.LocalPort = 0
	} else if fp.Protocol == firewall.ProtoICMP { //note that orientation doesn't matter on ICMP
		fp.RemotePort = binary.BigEndian.Uint16(data[ihl+4 : ihl+6]) //identifier
		fp.LocalPort = 0                                             //code would be uint16(data[ihl+1])
	} else if incoming {
		fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])  //src port
		fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4]) //dst port
	} else {
		fp.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])    //src port
		fp.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4]) //dst port
	}

	return nil
}

func (f *Interface) decrypt(hostinfo *HostInfo, mc uint64, out []byte, packet []byte, h *header.H, nb []byte) ([]byte, error) {
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:header.Len], packet[header.Len:], mc, nb)
	if err != nil {
		return nil, err
	}

	if !hostinfo.ConnectionState.window.Update(f.l, mc) {
		return nil, ErrOutOfWindow
	}

	return out, nil
}

func (f *Interface) handleOutsideMessagePacket(hostinfo *HostInfo, out []byte, packet []byte, fwPacket *firewall.Packet, nb []byte, q int, localCache firewall.ConntrackCache) {
	err := newPacket(out, true, fwPacket)
	if err != nil {
		hostinfo.logger(f.l).Warn("Error while validating inbound packet",
			"error", err,
			"packet", out,
		)
		return
	}

	dropReason := f.firewall.Drop(*fwPacket, true, hostinfo, f.pki.GetCAPool(), localCache)
	if dropReason != nil {
		// NOTE: We give `packet` as the `out` here since we already decrypted from it and we don't need it anymore
		// This gives us a buffer to build the reject packet in
		f.rejectOutside(out, hostinfo.ConnectionState, hostinfo, nb, packet, q)
		if f.l.Enabled(context.Background(), slog.LevelDebug) {
			hostinfo.logger(f.l).Debug("dropping inbound packet",
				"fwPacket", fwPacket,
				"reason", dropReason,
			)
		}
		return
	}

	_, err = f.readers[q].Write(out)
	if err != nil {
		f.l.Error("Failed to write to tun", "error", err)
	}
}

func (f *Interface) maybeSendRecvError(endpoint netip.AddrPort, index uint32) {
	if f.sendRecvErrorConfig.ShouldRecvError(endpoint) {
		f.sendRecvError(endpoint, index)
	}
}

func (f *Interface) sendRecvError(endpoint netip.AddrPort, index uint32) {
	f.messageMetrics.Tx(header.RecvError, 0, 1)

	b := header.Encode(make([]byte, header.Len), header.Version, header.RecvError, 0, index, 0)
	_ = f.outside.WriteTo(b, endpoint)
	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		f.l.Debug("Recv error sent",
			"index", index,
			"udpAddr", endpoint,
		)
	}
}

func (f *Interface) handleRecvError(addr netip.AddrPort, h *header.H) {
	if !f.acceptRecvErrorConfig.ShouldRecvError(addr) {
		f.l.Debug("Recv error received, ignoring",
			"index", h.RemoteIndex,
			"udpAddr", addr,
		)
		return
	}

	if f.l.Enabled(context.Background(), slog.LevelDebug) {
		f.l.Debug("Recv error received",
			"index", h.RemoteIndex,
			"udpAddr", addr,
		)
	}

	hostinfo := f.hostMap.QueryReverseIndex(h.RemoteIndex)
	if hostinfo == nil {
		f.l.Debug("Did not find remote index in main hostmap", "remoteIndex", h.RemoteIndex)
		return
	}

	hr := hostinfo.GetRemote()
	if hr.IsValid() && hr != addr {
		f.l.Info("Someone spoofing recv_errors?",
			"addr", addr,
			"hostinfoRemote", hr,
		)
		return
	}

	f.closeTunnel(hostinfo)
	// We also delete it from pending hostmap to allow for fast reconnect.
	f.handshakeManager.DeleteHostInfo(hostinfo)
}
