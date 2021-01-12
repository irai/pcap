// Package pcap implement a basic module to capture packet traffic
//
// see: http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
//
// DNS spooffing: https://github.com/razc411/DNSMangler
//
package pcap

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"

	"sync"
	"time"
)

// Traffic record TCP statistics for the IP address
//
// There may be a large number of this at any one time. The system creates one per minute per peer IP,
// which generates 1,440 instances for a single day for a single peer IP (43k for a month)
type Traffic struct {
	IP             net.IP `json:"ip"`
	OutPacketBytes uint64 `json:"out_bytes"`
	OutPacketCount uint16 `json:"out_packet_count"`
	InPacketBytes  uint64 `json:"in_bytes"`
	InPacketCount  uint16 `json:"in_packet_count"`
	OutConnCount   uint16 `json:"out_conn_count"`
}

// TimeSlice represents traffic for a particular minute
type TimeSlice struct {
	Time    time.Time
	Traffic map[string]*Traffic
}

// Host record recent network statistics for each host
type Host struct {
	MAC            net.HardwareAddr `json:"mac"`
	IP             net.IP           `json:"ip"`
	LastPacketTime time.Time        `json:"last_packet_time"`
	History        []TimeSlice      `json:"history"`
}

func (hs *Host) findOrCreatePeer(ip net.IP, t time.Time, inBytes uint16, outBytes uint16) (entry *Traffic) {

	// Truncate time to minute
	t = t.Truncate(time.Minute)

	// Time is always incrementing, so this is a new time if it is not the same as the last entry in History
	if len(hs.History) == 0 || hs.History[len(hs.History)-1].Time != t {
		hs.History = append(hs.History, TimeSlice{Time: t, Traffic: map[string]*Traffic{}})
	}
	i := len(hs.History) - 1

	entry = hs.History[i].Traffic[string(ip)]
	if entry == nil {
		entry = &Traffic{IP: dupIP(ip)}
		hs.History[i].Traffic[string(entry.IP)] = entry
	}

	if inBytes > 0 {
		entry.InPacketCount++
		entry.InPacketBytes = entry.InPacketBytes + uint64(inBytes)
	}
	if outBytes > 0 {
		entry.OutPacketCount++
		entry.OutPacketBytes = entry.OutPacketBytes + uint64(outBytes)
	}
	return entry
}

var trafficTable = map[string]*Host{}
var mutex sync.Mutex

func findMAC(mac net.HardwareAddr) *Host {
	return trafficTable[string(mac)]
}

func findOrAddHostIP(mac net.HardwareAddr, ip net.IP) (host *Host) {
	host = findMAC(mac)
	if host == nil {
		host = &Host{MAC: dupMAC(mac), IP: dupIP(ip), LastPacketTime: time.Now()}
		trafficTable[string(mac)] = host
	}
	return host
}

// FindHost find a host in the hostStatsTable; return nil if not found
func (h *TCPHandler) FindHost(mac net.HardwareAddr) *Host {
	mutex.Lock()
	defer mutex.Unlock()

	return findMAC(mac)
}

// PrintTable print the hostStatsTable to standard out
func PrintTable() {
	if len(trafficTable) <= 0 {
		return
	}

	fmt.Printf("Traffic table len %d", len(trafficTable))

	for _, host := range trafficTable {
		for i := range host.History {
			for _, t := range host.History[i].Traffic {
				fmt.Printf("time=%s host=%16s peer=%16s inCount=%v inBytes=%10d outCount=%6d outBytes=%10d\n",
					host.History[i].Time.Format("2006-01-02 15:04"), host.MAC, t.IP,
					t.InPacketCount, t.InPacketBytes, t.OutPacketCount, t.OutPacketBytes)
			}
		}
	}
}

// HasTrafficSince return Host if the host has sent packets since the deadline
// otherwise it returns nil
func (h *TCPHandler) HasTrafficSince(mac net.HardwareAddr, deadline time.Time) *Host {
	mutex.Lock()
	defer mutex.Unlock()

	if host := findMAC(mac); host != nil {
		if host.LastPacketTime.After(deadline) {
			return host
		}
	}
	return nil
}

// TCPHandler store a packet listener handler
type TCPHandler struct {
	handle       *pcap.Handle
	notification chan<- Host
	nic          string
	localNet     net.IPNet
	hostMAC      net.HardwareAddr
}

// NewTCPHandler creates a new handler to listen to TCP packets
func NewTCPHandler(nic string, localNetwork net.IPNet, hostMAC net.HardwareAddr) (h *TCPHandler, err error) {
	const snapshotLen int32 = 1024
	const promiscuous bool = true
	const timeout time.Duration = 0

	h = &TCPHandler{localNet: localNetwork, hostMAC: hostMAC}

	h.handle, err = pcap.OpenLive(nic, snapshotLen, promiscuous, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open nic=%s: %w", nic, err)
	}

	log.Info("Started AllTraffic() goroutine")
	// Set filter
	// var filter string = "tcp and (port 80 or port 443)"
	// filter := "tcp or udp"
	filter := "ip"
	if err = h.handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set bpf filter: %w", err)
	}

	return h, nil

	/****
	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Load EtherType value from Ethernet header
		bpf.LoadAbsolute{
			Off:  14 + 9, // IP Protocol field - 14 Eth bytes + 9 IP header
			Size: 1,
		},
		// If IP Protocol is equal ICMP, jump to allow
		// packet to be accepted
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      1, // ICMP protocol
			SkipTrue: 1,
		},
		// not ICMP
		bpf.RetConstant{
			Val: 0,
		},
		// IP Protocl matches ICMP, accept up to 1500
		// bytes of packet
		bpf.RetConstant{
			Val: 1500,
		},
	})

	h.handle.SetBPFInstructionFilter(bpf)
	****/
}

// Close release the underlying handle
func (h *TCPHandler) Close() {
	h.handle.Close()
}

// Notify adds a channel for event notification
func (h *TCPHandler) Notify(c chan<- Host) {
	h.notification = c
}

// ListenAndServe main listening loop
func (h *TCPHandler) ListenAndServe(ctx context.Context) error {

	var eth layers.Ethernet
	var ip4 layers.IPv4
	// var tcp layers.TCP
	// var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4)
	decoded := []gopacket.LayerType{}
	for {
		packetPayload, _, err := h.handle.ZeroCopyReadPacketData()
		if err != nil {
			return fmt.Errorf("pcap error reading tcp packet: %w", err)
		}

		err = parser.DecodeLayers(packetPayload, &decoded)
		if err != nil && len(decoded) != 2 {
			log.Error("pcap error decoding tcp packet ", decoded, err, len(decoded))
			continue
		}

		now := time.Now()

		// Don't capture netfilter traffic
		// if ip.SrcIP.Equal(config.HostIP) || ip.DstIP.Equal(config.HostIP) {
		// return
		// }

		packetLen := uint16(ip4.Length - uint16(ip4.IHL*4))

		// Skip forwarding sent by us
		if bytes.Compare(eth.SrcMAC, h.hostMAC) == 0 {
			continue
		}

		mutex.Lock()

		// add to table if this is a local host sending data
		if h.localNet.Contains(ip4.SrcIP) {
			host := findOrAddHostIP(eth.SrcMAC, ip4.SrcIP)
			host.LastPacketTime = now
			host.findOrCreatePeer(ip4.DstIP, now, 0, packetLen)
		}

		// Record in destination host; if it exist
		if h.localNet.Contains(ip4.DstIP) {
			host := findOrAddHostIP(eth.DstMAC, ip4.DstIP)
			host.LastPacketTime = now
			host.findOrCreatePeer(ip4.SrcIP, now, packetLen, 0)
		}

		mutex.Unlock()
	}
}
