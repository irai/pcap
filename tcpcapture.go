// Package pcap implement a basic module to capture packet traffic
//
// see: http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
//
// DNS spooffing: https://github.com/razc411/DNSMangler
//
package pcap

import (
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
	MAC     net.HardwareAddr `json:"mac"`
	Blocked bool             `json:"client_blocked" `
	Traffic []*TCPStats
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

// FindMAC find a host in the hostStatsTable; return nil if not found
func FindMAC(mac net.HardwareAddr) *HostStats {
	defer mutex.Unlock()
	mutex.Lock()

	return hostStatsTable[mac.String()]
}

func findOrAddMAC(mac net.HardwareAddr) (entry *HostStats) {
	defer mutex.Unlock()

	mutex.Lock()
	entry, ok := hostStatsTable[mac.String()]
	if !ok {
		entry = &HostStats{MAC: dupMAC(mac), Traffic: []*TCPStats{}}
		hostStatsTable[mac.String()] = entry
	}
	return entry
}

// PrintTable print the hostStatsTable to standard out
// TODO: Should use http://info.io to lookup names and geo
func PrintTable() {
	if len(hostStatsTable) <= 0 {
		return
	}

	log.Printf("Traffic hostStatsTable len %d", len(hostStatsTable))
	log.Println("MAC                 IP              outconn  inpkt     inbytes outpkt   outbytes")

	for _, host := range hostStatsTable {
		for _, t := range host.Traffic {
			log.Printf("%16s %15s %7d %6d %10d %6d %10d", host.MAC, DNSLookupByIP(t.IP),
				t.OutConnCount, t.InPacketCount, t.InPacketBytes, t.OutPacketCount, t.OutPacketBytes)
		}
	}
}

// ListenAndServe main listening loop
func ListenAndServe(nic string, hostMAC net.HardwareAddr) error {
	const snapshotLen int32 = 1024
	const promiscuous bool = true
	const timeout time.Duration = 10 * time.Second
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
	go captureTCPLoop(handle, hostMAC)

	dnsListenAndServe(nic)

	return nil
}

func captureTCPLoop(handle *pcap.Handle, hostMAC net.HardwareAddr) {
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

			host := findOrAddMAC(eth.SrcMAC)
			entry := host.findOrAddIP(ip.SrcIP)

			// Skip forwarding packets
			if eth.SrcMAC.String() != hostMAC.String() {
				entry.LastPacketTime = now
				entry.OutPacketBytes = entry.OutPacketBytes + tcpLen
				entry.OutPacketCount = entry.OutPacketCount + 1
				if tcp.SYN {
					entry.OutConnCount = entry.OutConnCount + 1
				}

				entry = host.findOrAddIP(ip.DstIP)
				entry.InPacketBytes = entry.InPacketBytes + tcpLen
				entry.InPacketCount = entry.InPacketCount + 1
			}

			// Record in destination
			//
			host = findOrAddMAC(eth.DstMAC)
			entry = host.findOrAddIP(ip.SrcIP)
			entry.InPacketBytes = entry.InPacketBytes + tcpLen
			entry.InPacketCount = entry.InPacketCount + 1
		}
	}
}
