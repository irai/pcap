package pcap

import (
	"fmt"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	dnsTable = []DNSStats{}
)

// DNSStats capture DNS statistics for host
type DNSStats struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DNSQuery        string
	DNSAnswer       []net.IP
	DNSAnswerTTL    []string
	NumberOfAnswers string
	DNSResponseCode string
	DNSOpsCode      string
}

func dnsListenAndServe(ifName string) {
	const snapshotLen int32 = 1600
	const promiscuous bool = true
	const timeout time.Duration = 0

	// Open device
	handle, err := pcap.OpenLive(ifName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Error(err)
		return
	}
	defer handle.Close()

	// Set filter
	// var filter string = "udp and port 53 and src host " + InetAddr
	filter := "udp and port 53"
	// fmt.Println("    Filter: ", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Error("DNS error cannot set BPF", err)
		return
	}
	captureDNSLoop(handle)
}

func captureDNSLoop(handle *pcap.Handle) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var udp layers.UDP
	var dns layers.DNS
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &udp, &dns)
	decoded := []gopacket.LayerType{}
	for {
		packetPayload, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			log.Error("pcap error reading packet data", err)
			return
		}

		err = parser.DecodeLayers(packetPayload, &decoded)
		if err != nil || len(decoded) != 4 {
			log.Error("pcap decoding packet data", decoded, err, len(decoded))
			continue
		}

		DNSOpsCode := int(dns.OpCode)
		DNSResponseCode := int(dns.ResponseCode)
		dnsANCount := int(dns.ANCount)

		if (dnsANCount == 0 && DNSResponseCode > 0) || (dnsANCount > 0) {

			for _, dnsQuestion := range dns.Questions {

				t := time.Now()
				timestamp := t.Format(time.RFC3339)

				d := dnsLookupByQuestionName(string(dnsQuestion.Name))
				if d != nil {
					continue
				}

				// Add a new entry
				d = &DNSStats{Timestamp: timestamp, SourceIP: ip4.SrcIP.String(),
					DestinationIP:   ip4.DstIP.String(),
					DNSQuery:        string(dnsQuestion.Name),
					DNSOpsCode:      strconv.Itoa(DNSOpsCode),
					DNSResponseCode: strconv.Itoa(DNSResponseCode),
					NumberOfAnswers: strconv.Itoa(dnsANCount)}

				log.WithFields(log.Fields{"opcode": d.DNSOpsCode, "response": d.DNSResponseCode,
					"#answers": d.NumberOfAnswers, "question": d.DNSQuery}).
					Debug("DNS Response record")

				// fmt.Println("    DNS OpCode: ", d.DNSOpsCode)
				// fmt.Println("    DNS ResponseCode: ", d.DNSResponseCode)
				// fmt.Println("    DNS # Answers: ", d.NumberOfAnswers)
				// fmt.Println("    DNS Question: ", d.DNSQuery)
				// fmt.Println("    DNS Endpoints: ", d.SourceIP, d.DestinationIP)

				if dnsANCount > 0 {

					for _, dnsAnswer := range dns.Answers {
						d.DNSAnswerTTL = append(d.DNSAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
						if dnsAnswer.IP != nil {
							log.WithFields(log.Fields{"DNSAnswer": dnsAnswer.IP.String(), "question": d.DNSQuery}).Debug("DNS new entry")
							d.DNSAnswer = append(d.DNSAnswer, dnsAnswer.IP)
						}
					}

				}

				// Append to main dns cache
				dnsTable = append(dnsTable, *d)

			}
		}
	}
}

func dnsLookupByQuestionName(query string) *DNSStats {
	for i := range dnsTable {
		if dnsTable[i].DNSQuery == query {
			return &dnsTable[i]
		}
	}
	return nil
}

// DNSLookupByIP find DNS entry by IP address; return ip if not found
func DNSLookupByIP(ip net.IP) string {
	for i := range dnsTable {
		for x := range dnsTable[i].DNSAnswer {
			if ip.Equal(dnsTable[i].DNSAnswer[x]) {
				return dnsTable[i].DNSQuery
			}
		}
	}
	return ip.String()
}
