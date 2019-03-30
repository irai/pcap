package filters

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

type IPEndPoint struct {
	Protocol string
	IP       string
	Port     uint16
}

var interfaceNetwork *net.IPNet

//
// BlockTCPTraffic will loop waiting for TCP packets to intercept.
// Call it from a goroutine.
//
// It will then send a TCP RST packet to close the socket.
//
func BlockTCPTraffic(ifName string, localInterface *net.IPNet) {
	interfaceNetwork = localInterface

	const snapshot_len int32 = 1024
	const promiscuous bool = true
	const timeout time.Duration = 1
	// handle  *pcap.Handle

	handle, err := pcap.OpenLive(ifName, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	log.Info("Started BlockeTraffic() goroutine")
	// Set filter
	// var filter string = "tcp and (port 80 or port 443)"
	// var filter string = "tcp"
	var filter string = "tcp and port 22"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		log.Info("blocked packet")
		killTcpTraffic(handle, packet)
	}
}

func killTcpTraffic(handle *pcap.Handle, packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	// Clients are always on the LAN
	if interfaceNetwork.Contains(ip.SrcIP) {
		// match the sender sequence as per RFC, when connection is already closed

		// FIXME: RST local connection is not working yet
		// tcpLen := ip.Length - uint16(ip.IHL) - (uint16(tcp.DataOffset) * 4)
		// sendTCPReset(packet, true, ip, tcp, 0, tcp.Seq+uint32(tcpLen))

		// RST remote connection
		PrintPacketInfo(packet)
		SendTCPReset(handle, packet, false, ip, tcp)
		// mytcp.SendTCPReset(handle, packet, true, ip, tcp)
	} else if interfaceNetwork.Contains(ip.DstIP) {
		// Seq must match Ack field
		// FIXME: this is not working yet for localtraffic
		// mytcp.PrintPacketInfo(packet)
		// mytcp.SendTCPReset(handle, packet, false, ip, tcp)
	}
}

func SendTCPReset(handle *pcap.Handle, packet gopacket.Packet, reply bool,
	ip *layers.IPv4, tcp *layers.TCP) {

	var buffer gopacket.SerializeBuffer

	if tcp.FIN || tcp.RST || tcp.SYN {
		// Tcp kill ignore these packets. So, do the same here.
		return
	}

	// Get current ethernet packet
	ethernet := packet.Layer(layers.LayerTypeEthernet)
	ethernetPacket, _ := ethernet.(*layers.Ethernet)

	// This time lets fill out some information
	ipLayer := &layers.IPv4{
		SrcIP:    ip.SrcIP,
		DstIP:    ip.DstIP,
		Version:  4,
		TTL:      64,
		Id:       0x0, // Use 0 for a RST packet
		Protocol: layers.IPProtocolTCP,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       ethernetPacket.SrcMAC,
		DstMAC:       ethernetPacket.DstMAC,
		EthernetType: layers.EthernetTypeIPv4,
		// Length:       1, // Will be overwritten by FixLengths option
	}
	tcpLayer := &layers.TCP{
		SrcPort: tcp.SrcPort,
		DstPort: tcp.DstPort,
		RST:     true,
		Seq:     tcp.Seq,
		Window:  tcp.Window,
		ACK:     tcp.ACK,
		Ack:     tcp.Ack,
	}

	if reply == true {
		// FIXME: Ethernet mac is not being set correctly.
		ethernetLayer.SrcMAC = ethernetPacket.DstMAC
		ethernetLayer.DstMAC = ethernetPacket.SrcMAC
		ipLayer.SrcIP = ip.DstIP
		ipLayer.DstIP = ip.SrcIP
		tcpLayer.SrcPort = tcp.DstPort
		tcpLayer.DstPort = tcp.SrcPort
		tcpLayer.Seq = tcp.Ack

		tcpLen := ip.Length - uint16(ip.IHL*4) - (uint16(tcp.DataOffset) * 4)
		tcpLayer.Ack = tcp.Seq + uint32(tcpLen)
		tcpLayer.ACK = true
	}

	// if tcp.ACK {
	// tcpLayer.ACK = true
	// tcpLayer.Ack = tcp.Ack
	// }

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	for i := 0; i < 3; i++ {
		// log.Printf("In reset packet tcpseq=%x newseq=%x tcpack=%x newack=%x tcplen=%d\n", tcp.Seq, tcpLayer.Seq, tcp.Ack, tcpLayer.Ack, tcpLen)
		// And create the packet with the layers
		buffer = gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, options,
			ethernetLayer,
			ipLayer,
			tcpLayer,
			// gopacket.Payload(rawBytes),
		)
		outgoingPacket := buffer.Bytes()
		err := handle.WritePacketData(outgoingPacket)
		if err != nil {
			log.Fatal(err)
		}
		tcpLayer.Seq = tcpLayer.Seq + uint32(tcpLayer.Window)
	}
}