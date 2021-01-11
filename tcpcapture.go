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

// Host record recent network statistics for each host
type Host struct {
	MAC            net.HardwareAddr `json:"mac"`
	IP             net.IP           `json:"ip"`
	LastPacketTime time.Time        `json:"last_packet_time"`
	Traffic        map[time.Time]map[string]*Traffic
}

func (hs *Host) findOrCreatePeer(ip net.IP, t time.Time, inBytes uint16, outBytes uint16, conn bool) (entry *Traffic) {

	// Truncate time to minute
	t = t.Truncate(time.Minute)

	tt := hs.Traffic[t]
	if tt == nil {
		tt = map[string]*Traffic{}
		hs.Traffic[t] = tt
	}

	entry = tt[string(ip)]
	if entry == nil {
		entry = &Traffic{IP: dupIP(ip), InPacketBytes: uint64(inBytes), OutPacketBytes: uint64(outBytes)}
		tt[string(entry.IP)] = entry
	}

	if inBytes > 0 {
		entry.InPacketBytes++
	}
	if outBytes > 9 {
		entry.OutPacketCount++
	}
	if conn {
		entry.OutConnCount++
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
		host = &Host{MAC: dupMAC(mac), IP: dupIP(ip), LastPacketTime: time.Now(), Traffic: map[time.Time]map[string]*Traffic{}}
		trafficTable[string(mac)] = host
	}
	return host
}

// FindHost find a host in the hostStatsTable; return nil if not found
func (h *TCPHandler) FindHost(mac net.HardwareAddr) *Host {
	defer mutex.Unlock()
	mutex.Lock()
	return findMAC(mac)
}

// PrintTable print the hostStatsTable to standard out
func PrintTable() {
	if len(trafficTable) <= 0 {
		return
	}

	fmt.Printf("Traffic table len %d", len(trafficTable))

	for _, host := range trafficTable {
		for minute, i := range host.Traffic {
			for _, t := range i {
				fmt.Printf("time=%s host=%16s peer=%16s connCount=%6d inCount=%v inBytes=%10d outCount=%6d outBytes=%10d", minute.Format("2006-01-02 15:04:05"), host.MAC, t.IP,
					t.OutConnCount, t.InPacketCount, t.InPacketBytes, t.OutPacketCount, t.OutPacketBytes)
			}
		}
	}
}

// HasTrafficSince return true if the host has sent packets since the deadline
func (h *TCPHandler) HasTrafficSince(mac net.HardwareAddr, deadline time.Time) bool {
	if host := h.FindHost(mac); host != nil {
		if host.LastPacketTime.After(deadline) {
			return true
		}
	}
	return false
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
	defer h.handle.Close()

	log.Info("Started AllTraffic() goroutine")
	// Set filter
	// var filter string = "tcp and (port 80 or port 443)"
	filter := "tcp or udp"
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

// Notify adds a channel for event notification
func (h *TCPHandler) Notify(c chan<- Host) {
	h.notification = c
}

// ListenAndServe main listening loop
func (h *TCPHandler) ListenAndServe(ctx context.Context) error {

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	decoded := []gopacket.LayerType{}
	for {
		packetPayload, _, err := h.handle.ZeroCopyReadPacketData()
		if err != nil {
			return fmt.Errorf("pcap error reading tcp packet: %w", err)
		}

		err = parser.DecodeLayers(packetPayload, &decoded)
		if err != nil || len(decoded) != 3 {
			log.Error("pcap error decoding tcp packet ", decoded, err, len(decoded))
			continue
		}

		now := time.Now()

		// Don't capture netfilter traffic
		// if ip.SrcIP.Equal(config.HostIP) || ip.DstIP.Equal(config.HostIP) {
		// return
		// }

		tcpLen := uint16(ip4.Length - uint16(ip4.IHL*4))

		// Skip forwarding sent by us
		if bytes.Compare(eth.SrcMAC, h.hostMAC) == 0 {
			continue
		}

		mutex.Lock()
		defer mutex.Unlock()

		// add to table if this is a local host sending data
		if h.localNet.Contains(ip4.SrcIP) {
			host := findOrAddHostIP(eth.SrcMAC, ip4.SrcIP)
			host.LastPacketTime = now
			conn := false
			if tcp.SYN {
				conn = true
			}
			entry := host.findOrCreatePeer(ip4.DstIP, now, 0, tcpLen, conn)
			if tcp.SYN {
				entry.OutConnCount = entry.OutConnCount + 1
			}
		}

		// Record in destination host; if it exist
		if h.localNet.Contains(ip4.DstIP) {
			host := findOrAddHostIP(eth.DstMAC, ip4.DstIP)
			host.LastPacketTime = now
			host.findOrCreatePeer(ip4.SrcIP, now, tcpLen, 0, false)
		}
	}
}
