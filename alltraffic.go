// start this with sudo -E go run capture.go
//
// see: http://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
//
// DNS spooffing: https://github.com/razc411/DNSMangler
//
package filters

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	// "github.com/irai/base"
	"github.com/irai/netfilter/netfilter/config"
	"github.com/irai/netfilter/netfilter/model"
	"sync"
	"time"
)

var (
	deviceId string

	trafficTable []model.IPTraffic = make([]model.IPTraffic, 0, 1024)
	blockTable   []model.IPTraffic
	tableMutex   sync.Mutex
)

/***
func PostIPTraffic(hostname string, deviceId string, IPTable []model.IPTraffic) (err error) {

	aurl := fmt.Sprintf("http://%s:8080/traffic/v1/device/%s/traffic", hostname, deviceId)
	fields := url.Values{}

	fields.Set("device_id", deviceId)
	for i, _ := range IPTable {
		fields.Add("client_mac", IPTable[i].ClientMAC)
		fields.Add("client_ip", IPTable[i].ClientIP)
		fields.Add("client_port", strconv.FormatUint(uint64(IPTable[i].ClientPort), 10))
		fields.Add("server_ip", IPTable[i].ServerIP)
		fields.Add("server_port", strconv.FormatUint(uint64(IPTable[i].ServerPort), 10))
		fields.Add("start_time", IPTable[i].StartTime.String())
		fields.Add("end_time", IPTable[i].LastTime.String())
		fields.Add("out_bytes", strconv.FormatUint(uint64(IPTable[i].OutPacketBytes), 10))
		fields.Add("out_packet_count", strconv.FormatUint(uint64(IPTable[i].OutPacketCount), 10))
		fields.Add("in_bytes", strconv.FormatUint(uint64(IPTable[i].InPacketBytes), 10))
		fields.Add("in_packet_count", strconv.FormatUint(uint64(IPTable[i].InPacketCount), 10))
		fields.Add("out_conn_count", strconv.FormatUint(uint64(IPTable[i].OutConnCount), 10))
	}

	resp, err := post(nil, aurl, fields)
	if err != nil {
		log.Error("TrafficProxy error posting ", aurl, err)
		return err
	}
	defer resp.Body.Close()

	return nil

}
***/

// Should use http://info.io to lookup names and geo
func PrintTable(t []model.IPTraffic) {
	if len(t) <= 0 {
		return
	}

	log.Printf("Traffic Table len %d", len(t))
	log.Println("MAC                server         port  ccount  inpkt     inbytes outpkt   outbytes")

	for i, _ := range t {
		log.Printf("%16s %15s %4d %5d %6d %10d %6d %10d", t[i].ClientMAC, t[i].ServerIP, t[i].ServerPort,
			t[i].OutConnCount, t[i].InPacketCount, t[i].InPacketBytes, t[i].OutPacketCount, t[i].OutPacketBytes)
	}
}

func AllTraffic(config *config.Config) {
	const snapshot_len int32 = 1024
	const promiscuous bool = true
	const timeout time.Duration = 10 * time.Second
	// handle  *pcap.Handle

	handle, err := pcap.OpenLive(config.NIC, snapshot_len, promiscuous, timeout)
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
		//filters.PrintPacketInfo(packet)
		captureTcpTraffic(config, packet)
	}
}

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

func findMACEntry(entry model.IPTraffic) (ret *model.IPTraffic) {
	// get a copy of the slice in case it concurrently reset by the sending goroutine
	tableMutex.Lock()
	t := trafficTable
	tableMutex.Unlock()

	for i, _ := range t {
		if t[i].ClientMAC == entry.ClientMAC &&
			t[i].ServerIP == entry.ServerIP && t[i].ServerPort == entry.ServerPort {
			return &t[i]
		}
	}

	tableMutex.Lock()
	trafficTable = append(trafficTable, entry)
	ret = &trafficTable[len(trafficTable)-1]
	tableMutex.Unlock()

	// log.WithFields(log.Fields{"src": base.FunctionName(2), "MAC": entry.ClientMAC, "Server": entry.ServerIP, "Port": entry.ServerPort}).Debug("filter added")
	return ret
}

func captureTcpTraffic(config *config.Config, packet gopacket.Packet) {
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
		entry := model.IPTraffic{ClientMAC: eth.SrcMAC.String(), StartTime: now, LastTime: now}

		tcpLen := uint(ip.Length - uint16(ip.IHL*4))

		// Don't capture netfilter traffic
		if ip.SrcIP.Equal(config.HostIP) || ip.DstIP.Equal(config.HostIP) {
			return
		}

		// Clients are always on the LAN
		if config.NetfilterLAN.Contains(ip.SrcIP) {
			entry.ClientIP = ip.SrcIP.String()
			entry.ClientPort = uint16(tcp.SrcPort)
			entry.ServerIP = ip.DstIP.String()
			entry.ServerPort = uint16(tcp.DstPort)
			e := findMACEntry(entry)
			// e.LastTime = time.Now()
			e.OutPacketBytes = e.OutPacketBytes + tcpLen
			e.OutPacketCount = e.OutPacketCount + 1
			if tcp.SYN {
				e.OutConnCount = e.OutConnCount + 1
			}
		} else if config.NetfilterLAN.Contains(ip.DstIP) {
			entry.ClientMAC = eth.DstMAC.String()
			entry.ClientIP = ip.DstIP.String()
			entry.ClientPort = uint16(tcp.DstPort)
			entry.ServerIP = ip.SrcIP.String()
			entry.ServerPort = uint16(tcp.SrcPort)
			e := findMACEntry(entry)
			// e.LastTime = time.Now()
			e.InPacketBytes = e.InPacketBytes + tcpLen
			e.InPacketCount = e.InPacketCount + 1
		}
	}
}
