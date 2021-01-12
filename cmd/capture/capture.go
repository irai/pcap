package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/irai/pcap"
	log "github.com/sirupsen/logrus"

	"net/http"
	_ "net/http/pprof"
)

/***
using pprof:

go tool pprof -alloc_objects http://localhost:6061/debug/pprof/heap

inuse_space — amount of memory allocated and not released yet
inuse_objects— amount of objects allocated and not released yet
alloc_space — total amount of memory allocated (regardless of released)
alloc_objects — total amount of objects allocated (regardless of released
**/

var (
	nic = flag.String("i", "eth0", "network interface to listen to")
)

func main() {
	flag.Parse()

	setLogLevel("info")

	_, localNetwork, hostMAC, err := nicGetInfo(*nic)
	if err != nil {
		log.Fatal("error cannot get host ip and mac ", err)
	}

	fmt.Println("host config: ", localNetwork, hostMAC)

	listener, err := pcap.NewTCPHandler(*nic, *localNetwork, hostMAC)
	if err != nil {
		log.Fatal("error cannot create listener: %s", err)
	}

	ctxt, cancel := context.WithCancel(context.Background())
	go listener.ListenAndServe(ctxt)

	// go pcap.ICMPListenAndServe(*nic)

	// http listener for pprof
	go func() {
		log.Println(http.ListenAndServe("localhost:6061", nil))
	}()

	cmd()

	cancel()

}

func cmd() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (l)ist | (g) loG <level>")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(text[:len(text)-1])
		// fmt.Println(text)

		if text == "" || len(text) < 1 {
			continue
		}

		switch text[0] {
		case 'q':
			return
		case 'g':
			if len(text) < 3 {
				text = text + "   "
			}
			err := setLogLevel(text[2:])
			if err != nil {
				log.Error("invalid level. valid levels (error, warn, info, debug) ", err)
				break
			}
		case 'l':
			pcap.PrintTable()
		}
	}
}

func nicGetInfo(nic string) (ip net.IP, localNetwork *net.IPNet, mac net.HardwareAddr, err error) {
	all, err := net.Interfaces()
	for _, v := range all {
		log.Debug("interface name ", v.Name, v.HardwareAddr.String())
	}
	ifi, err := net.InterfaceByName(nic)
	if err != nil {
		log.WithFields(log.Fields{"nic": nic}).Errorf("NIC cannot open nic %s error %s ", nic, err)
		return ip, localNetwork, mac, err
	}

	mac = ifi.HardwareAddr

	addrs, err := ifi.Addrs()
	if err != nil {
		log.WithFields(log.Fields{"nic": nic}).Errorf("NIC cannot get addresses nic %s error %s ", nic, err)
		return ip, localNetwork, mac, err
	}

	for i := range addrs {
		ip, localNetwork, err = net.ParseCIDR(addrs[i].String())
		if err != nil {
			log.WithFields(log.Fields{"nic": nic}).Errorf("NIC cannot parse IP %s error %s ", addrs[i].String(), err)
		}
		log.Info("IP=", ip)
		ip = ip.To4()
		if ip != nil && !ip.Equal(net.IPv4zero) {
			break
		}
	}

	if ip == nil || ip.Equal(net.IPv4zero) {
		err = fmt.Errorf("NIC cannot find IPv4 address list - is %s up?", nic)
		log.Error(err)
		return ip, localNetwork, mac, err
	}

	log.WithFields(log.Fields{"nic": nic, "ip": ip, "mac": mac}).Info("NIC successfull acquired host nic information")
	return ip, localNetwork, mac, err
}

func setLogLevel(level string) (err error) {

	if level != "" {
		l, err := log.ParseLevel(level)
		if err != nil {
			return err
		}
		log.SetLevel(l)
	}

	return nil
}

const (
	file  = "/proc/net/route"
	line  = 1    // line containing the gateway addr. (first line: 0)
	sep   = "\t" // field separator
	field = 2    // field containing hex gateway address (first field: 0)
)

// NICDefaultGateway read the default gateway from linux route file
//
// file: /proc/net/route file:
//   Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask
//   eth0    00000000    C900A8C0    0003    0   0   100 00000000    0   00
//   eth0    0000A8C0    00000000    0001    0   0   100 00FFFFFF    0   00
//
func getLinuxDefaultGateway() (gw net.IP, err error) {

	file, err := os.Open(file)
	if err != nil {
		log.Error("NIC cannot open route file ", err)
		return net.IPv4zero, err
	}
	defer file.Close()

	ipd32 := net.IP{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		// jump to line containing the gateway address
		for i := 0; i < line; i++ {
			scanner.Scan()
		}

		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), sep)
		gatewayHex := "0x" + tokens[field]

		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 = make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		fmt.Printf("NIC default gateway is %T --> %[1]v\n", ipd32)

		// format net.IP to dotted ipV4 string
		//ip := net.IP(ipd32).String()
		//fmt.Printf("%T --> %[1]v\n", ip)

		// exit scanner
		break
	}
	return ipd32, nil
}
