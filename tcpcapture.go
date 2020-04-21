// Package pcap implement a basic module to capture packet traffic
//
// see: http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
//
// DNS spooffing: https://github.com/razc411/DNSMangler
//
package pcap

import (
	"bytes"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"

	"sync"
	"time"
)

var (
	hostStatsTable = map[string]*HostStats{}
	mutex          sync.Mutex
)

// TCPStats record TCP statistics for the IP address
type TCPStats struct {
	IP             net.IP    `json:"ip"`
	LastPacketTime time.Time `json:"last_packet_time"`
	OutPacketBytes uint      `json:"out_bytes"`
	OutPacketCount uint      `json:"out_packet_count"`
	InPacketBytes  uint      `json:"in_bytes"`
	InPacketCount  uint      `json:"in_packet_count"`
	OutConnCount   uint      `json:"out_conn_count"`
}

// HostStats record recent network statistics for each host
type HostStats struct {
	MAC            net.HardwareAddr `json:"mac"`
	IP             net.IP           `json:"ip"`
	Blocked        bool             `json:"client_blocked" `
	LastPacketTime time.Time        `json:"last_packet_time"`
	Traffic        []*TCPStats
}

func (h *HostStats) findOrAddIP(ip net.IP) (entry *TCPStats) {
	defer mutex.Unlock()

	mutex.Lock()
	for _, entry = range h.Traffic {
		if entry.IP.Equal(ip) {
			return entry
		}
	}
	entry = &TCPStats{IP: dupIP(ip)}
	h.Traffic = append(h.Traffic, entry)
	return entry
}

// HasTrafficSince return true if the host has sent packets since the deadline
func HasTrafficSince(ip net.IP, deadline time.Time) bool {
	if host := FindHostByIP(ip); host != nil {
		if host.LastPacketTime.After(deadline) {
			return true
		}
	}
	return false
}

func findOrAddHostIP(ip net.IP, mac net.HardwareAddr) (entry *HostStats) {
	defer mutex.Unlock()
	mutex.Lock()

	entry, ok := hostStatsTable[ip.String()]
	if !ok {
		entry = &HostStats{MAC: dupMAC(mac), IP: dupIP(ip), LastPacketTime: time.Now(), Traffic: []*TCPStats{}}
		hostStatsTable[ip.String()] = entry
	}
	return entry
}

// FindHostByIP find a host in the hostStatsTable; return nil if not found
func FindHostByIP(ip net.IP) *HostStats {
	defer mutex.Unlock()
	mutex.Lock()

	return hostStatsTable[ip.String()]
}

// PrintTable print the hostStatsTable to standard out
// TODO: Should use http://info.io to lookup names and geo
func PrintTable() {
	if len(hostStatsTable) <= 0 {
		return
	}

	log.Printf("Traffic hostStatsTable len %d", len(hostStatsTable))
	log.Println("MAC                 IP              lastPacket outconn  inpkt     inbytes outpkt   outbytes")

	now := time.Now()
	for _, host := range hostStatsTable {
		for _, t := range host.Traffic {
			log.Printf("%16s %15s %6s %7d %6d %10d %6d %10d", host.IP, DNSLookupByIP(t.IP), now.Sub(host.LastPacketTime),
				t.OutConnCount, t.InPacketCount, t.InPacketBytes, t.OutPacketCount, t.OutPacketBytes)
		}
	}
}

// ListenAndServe main listening loop
func ListenAndServe(nic string, localNetwork net.IPNet, hostMAC net.HardwareAddr) error {
	const snapshotLen int32 = 1024
	const promiscuous bool = true
	const timeout time.Duration = 0
	// handle  *pcap.Handle

	handle, err := pcap.OpenLive(nic, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Error("Cannot pcap nic", nic, err)
		return err
	}
	defer handle.Close()

	log.Info("Started AllTraffic() goroutine")
	// Set filter
	// var filter string = "tcp and (port 80 or port 443)"
	// var filter string = "tcp and port 80"
	filter := "tcp"
	if err = handle.SetBPFFilter(filter); err != nil {
		log.Error("cannot bpfilter", err)
		return err
	}
	go captureTCPLoopNew(handle, localNetwork, hostMAC)

	dnsListenAndServe(nic)

	return nil
}

// captureTcpLoopNew avoid packet allocations saving garbage collection time
func captureTCPLoopNew(handle *pcap.Handle, localNetwork net.IPNet, hostMAC net.HardwareAddr) {

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
	decoded := []gopacket.LayerType{}
	for {
		packetPayload, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Error("Error reading packet data", err)
			return
		}

		parser.DecodeLayers(packetPayload, &decoded)
		if len(decoded) != 3 {
			log.Error("Error decoding packet data", decoded, err)
			continue
		}

		now := time.Now()

		// Don't capture netfilter traffic
		// if ip.SrcIP.Equal(config.HostIP) || ip.DstIP.Equal(config.HostIP) {
		// return
		// }

		tcpLen := uint(ip4.Length - uint16(ip4.IHL*4))

		// Skip forwarding sent by us
		if bytes.Compare(eth.SrcMAC, hostMAC) == 0 {
			continue
		}

		// add to table if this is a local host sending data
		if localNetwork.Contains(ip4.SrcIP) {
			host := findOrAddHostIP(ip4.SrcIP, eth.SrcMAC)
			host.LastPacketTime = now
			entry := host.findOrAddIP(ip4.DstIP)
			entry.LastPacketTime = now
			entry.OutPacketBytes = entry.OutPacketBytes + tcpLen
			entry.OutPacketCount = entry.OutPacketCount + 1
			if tcp.SYN {
				entry.OutConnCount = entry.OutConnCount + 1
			}
		}

		// Record in destination host; if it exist
		if localNetwork.Contains(ip4.DstIP) {
			if host := FindHostByIP(ip4.DstIP); host != nil {
				entry := host.findOrAddIP(ip4.SrcIP)
				entry.InPacketBytes = entry.InPacketBytes + tcpLen
				entry.InPacketCount = entry.InPacketCount + 1
			}
		}
	}
}

func captureTCPLoop(handle *pcap.Handle, localNetwork *net.IPNet, hostMAC net.HardwareAddr) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// PrintPacketInfo(packet)
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ethLayer == nil || ipLayer == nil || tcpLayer == nil {
			log.Error("Invalid packet ", ethLayer, ipLayer, tcpLayer)
			return
		}

		if tcpLayer != nil {

			eth, _ := ethLayer.(*layers.Ethernet)
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)

			now := time.Now()

			// Don't capture netfilter traffic
			// if ip.SrcIP.Equal(config.HostIP) || ip.DstIP.Equal(config.HostIP) {
			// return
			// }

			tcpLen := uint(ip.Length - uint16(ip.IHL*4))

			// Skip forwarding sent by us
			// if bytes.Compare(eth.SrcMAC, hostMAC) == 0 {
			// continue
			// }

			// add to table if this is a local host sending data
			if localNetwork.Contains(ip.SrcIP) {
				host := findOrAddHostIP(ip.SrcIP, eth.SrcMAC)
				host.LastPacketTime = now
				entry := host.findOrAddIP(ip.DstIP)
				entry.LastPacketTime = now
				entry.OutPacketBytes = entry.OutPacketBytes + tcpLen
				entry.OutPacketCount = entry.OutPacketCount + 1
				if tcp.SYN {
					entry.OutConnCount = entry.OutConnCount + 1
				}
			}

			// Record in destination host; if it exist
			if localNetwork.Contains(ip.DstIP) {
				if host := FindHostByIP(ip.DstIP); host != nil {
					entry := host.findOrAddIP(ip.SrcIP)
					entry.InPacketBytes = entry.InPacketBytes + tcpLen
					entry.InPacketCount = entry.InPacketCount + 1
				}
			}
		}
	}
}
