// start this with sudo -E go run capture.go
//
// see: http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
//
// DNS spooffing: https://github.com/razc411/DNSMangler
//
package filters

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"

	// "github.com/irai/base"
	"sync"
	"time"

	"github.com/irai/netfilter/network"
)

type HostTraffic struct {
	MAC     net.HardwareAddr `json:"mac" bson:"mac"`
	Blocked bool             `json:"client_blocked" bson:"client_blocked"`
	Traffic []*TCPTraffic
}

func (h *HostTraffic) findOrAddIP(ip net.IP) (entry *TCPTraffic) {
	defer mutex.Unlock()

	mutex.Lock()
	for _, entry = range h.Traffic {
		if entry.IP.Equal(ip) {
			return entry
		}
	}
	entry = &TCPTraffic{IP: network.DupIP(ip)}
	h.Traffic = append(h.Traffic, entry)
	return entry
}

type TCPTraffic struct {
	IP             net.IP    `json:"client_ip" bson:"client_ip"`
	LastPacketTime time.Time `json:"last_packet_time" bson:"last_packet_time"`
	OutPacketBytes uint      `json:"out_bytes" bson:"out_bytes"`
	OutPacketCount uint      `json:"out_packet_count" bson:"out_packet_count"`
	InPacketBytes  uint      `json:"in_bytes" bson:"in_bytes"`
	InPacketCount  uint      `json:"in_packet_count" bson:"in_packet_count"`
	OutConnCount   uint      `json:"out_conn_count" bson:"out_conn_count"`
}

var (
	table map[string]*HostTraffic = map[string]*HostTraffic{}
	mutex sync.Mutex
)

func FindMAC(mac net.HardwareAddr) *HostTraffic {
	defer mutex.Unlock()

	mutex.Lock()
	return table[mac.String()]
}

func findOrAddMAC(mac net.HardwareAddr) (entry *HostTraffic) {
	defer mutex.Unlock()

	mutex.Lock()
	entry, ok := table[mac.String()]
	if !ok {
		entry = &HostTraffic{MAC: network.DupMAC(mac), Traffic: []*TCPTraffic{}}
		table[mac.String()] = entry
	}
	return entry
}

// PrintTable prints the table to standard out
// TODO: Should use http://info.io to lookup names and geo
func PrintTable() {
	if len(table) <= 0 {
		return
	}

	log.Printf("Traffic Table len %d", len(table))
	log.Println("MAC                 IP              outconn  inpkt     inbytes outpkt   outbytes")

	for _, host := range table {
		for _, t := range host.Traffic {
			log.Printf("%16s %15s %7d %6d %10d %6d %10d", host.MAC.String(), t.IP,
				t.OutConnCount, t.InPacketCount, t.InPacketBytes, t.OutPacketCount, t.OutPacketBytes)
		}
	}
}

/****
func TrafficProxyLoop(gwHostName string, deviceId string) {
	ticker := time.NewTicker(time.Second * 60)
	for range ticker.C {

		if len(trafficTable) > 0 {

			// Replace the table with an empty one and with plenty of capacity
			// Send the previos table
			//
			tableMutex.Lock()
			table := trafficTable
			trafficTable = make([]model.IPTraffic, 0, 1024)
			tableMutex.Unlock()

			for i := range table {
				table[i].ServerIP = DnsLookupByIP(table[i].ServerIP)
			}
			log.Infof("Posting %d entries", len(table))
			PrintTable(table)
			// traffic.PostIPTraffic(gwHostName, deviceId, table)
		}
	}
}
***/

func ListenAndServe(nic string) {
	const snapshot_len int32 = 1024
	const promiscuous bool = true
	const timeout time.Duration = 10 * time.Second
	// handle  *pcap.Handle

	handle, err := pcap.OpenLive(nic, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	log.Info("Started AllTraffic() goroutine")
	// Set filter
	// var filter string = "tcp and (port 80 or port 443)"
	// var filter string = "tcp and port 80"
	var filter string = "tcp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// PrintPacketInfo(packet)
		captureTcpTraffic(packet)
	}
}

func captureTcpTraffic(packet gopacket.Packet) {
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

		entry.LastPacketTime = now
		entry.OutPacketBytes = entry.OutPacketBytes + tcpLen
		entry.OutPacketCount = entry.OutPacketCount + 1
		if tcp.SYN {
			entry.OutConnCount = entry.OutConnCount + 1
		}

		entry = host.findOrAddIP(ip.DstIP)
		entry.InPacketBytes = entry.InPacketBytes + tcpLen
		entry.InPacketCount = entry.InPacketCount + 1

		// Record in destination
		//
		host = findOrAddMAC(eth.DstMAC)
		entry = host.findOrAddIP(ip.SrcIP)
		entry.InPacketBytes = entry.InPacketBytes + tcpLen
		entry.InPacketCount = entry.InPacketCount + 1
	}
}
