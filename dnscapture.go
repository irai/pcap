package filters

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	dnsTable []DnsMsg = []DnsMsg{}
)

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

func DNSListen(ifName string) {
	const snapshot_len int32 = 1600
	const promiscuous bool = true
	const timeout time.Duration = 5 * time.Second

	// Open device
	handle, err := pcap.OpenLive(ifName, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Error(err)
		return
	}
	defer handle.Close()

	// Set filter
	// var filter string = "udp and port 53 and src host " + InetAddr
	var filter string = "udp and port 53"
	// fmt.Println("    Filter: ", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Error("DNS error cannot set BPF", err)
		return
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		captureDNSTraffic(packet)
	}
}

func captureDNSTraffic(packet gopacket.Packet) {
	// ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// tcpLayer := packet.Layer(layers.LayerTypeTCP)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer != nil {
		// eth, _ := ethLayer.(*layers.Ethernet)
		ip, _ := ipLayer.(*layers.IPv4)
		// tcp, _ := tcpLayer.(*layers.TCP)
		dns, _ := dnsLayer.(*layers.DNS)

		dnsOpCode := int(dns.OpCode)
		dnsResponseCode := int(dns.ResponseCode)
		dnsANCount := int(dns.ANCount)

		if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {

			for _, dnsQuestion := range dns.Questions {

				t := time.Now()
				timestamp := t.Format(time.RFC3339)

				d := dnsLookupByQuestionName(string(dnsQuestion.Name))
				if d != nil {
					continue
				}

				// Add a new entry
				d = &DnsMsg{Timestamp: timestamp, SourceIP: ip.SrcIP.String(),
					DestinationIP:   ip.DstIP.String(),
					DnsQuery:        string(dnsQuestion.Name),
					DnsOpCode:       strconv.Itoa(dnsOpCode),
					DnsResponseCode: strconv.Itoa(dnsResponseCode),
					NumberOfAnswers: strconv.Itoa(dnsANCount)}

				log.WithFields(log.Fields{"opcode": d.DnsOpCode, "response": d.DnsResponseCode,
					"#answers": d.NumberOfAnswers, "question": d.DnsQuery}).
					Debug("DNS Response record")

				// fmt.Println("    DNS OpCode: ", d.DnsOpCode)
				// fmt.Println("    DNS ResponseCode: ", d.DnsResponseCode)
				// fmt.Println("    DNS # Answers: ", d.NumberOfAnswers)
				// fmt.Println("    DNS Question: ", d.DnsQuery)
				// fmt.Println("    DNS Endpoints: ", d.SourceIP, d.DestinationIP)

				if dnsANCount > 0 {

					for _, dnsAnswer := range dns.Answers {
						d.DnsAnswerTTL = append(d.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
						if dnsAnswer.IP.String() != "<nil>" {
							log.WithFields(log.Fields{"DNSAnswer": dnsAnswer.IP.String(), "question": d.DnsQuery}).Info("DNS new entry")
							d.DnsAnswer = append(d.DnsAnswer, dnsAnswer.IP.String())
						}
					}

				}

				// Append to main dns cache
				dnsTable = append(dnsTable, *d)

			}
		}
	}
}

func dnsLookupByQuestionName(query string) *DnsMsg {
	for i := range dnsTable {
		if dnsTable[i].DnsQuery == query {
			return &dnsTable[i]
		}
	}
	return nil
}

func DnsLookupByIP(ip string) string {
	for i := range dnsTable {
		for x := range dnsTable[i].DnsAnswer {
			if ip == dnsTable[i].DnsAnswer[x] {
				return dnsTable[i].DnsQuery
			}
		}
	}
	return ip
}
