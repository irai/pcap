package pcap

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	icmpTable = []ICMPStats{}
)

// ICMPStats capture DNS statistics for host
type ICMPStats struct {
	Timestamp     string
	SourceIP      string
	DestinationIP string
}

// ICMPListenAndServe listen to ICMP packets
func ICMPListenAndServe(ifName string) {
	const snapshotLen int32 = 1600
	const promiscuous bool = true
	const timeout time.Duration = 5 * time.Second

	// Open device
	handle, err := pcap.OpenLive(ifName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Error(err)
		return
	}
	defer handle.Close()

	// Set filter
	// var filter string = "udp and port 53 and src host " + InetAddr
	filter := "icmp"
	// fmt.Println("    Filter: ", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Error("ICMP error cannot set BPF", err)
		return
	}
	captureICMPLoop(handle)
}

func captureICMPLoop(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		// tcpLayer := packet.Layer(layers.LayerTypeTCP)
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)

		if icmpLayer != nil {
			// eth, _ := ethLayer.(*layers.Ethernet)
			ip, _ := ipLayer.(*layers.IPv4)
			// tcp, _ := tcpLayer.(*layers.TCP)
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			log.Info("new ICMP packet ", ip.SrcIP, icmp)
		}
	}
}
