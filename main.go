package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

var resourceRecordsID = map[uint16]string{
	1:  "A",
	2:  "NS",
	5:  "CNAME",
	6:  "SOA",
	12: "PTR",
	15: "MX",
	16: "TXT",
	28: "AAAA",
}

type Records struct {
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
	Domain string `json:"domain,omitempty"`
}

func (r *Records) IPv4Hex() string {
	if r.IPv4 == "" {
		return ""
	}
	parts := strings.Split(r.IPv4, ".")
	bytes := make([]byte, len(parts))
	for i, p := range parts {
		fmt.Sscanf(p, "%d", &bytes[i])
	}
	return hex.EncodeToString(bytes)
}

func (r *Records) IPv6Hex() string {
	return strings.ReplaceAll(r.IPv6, ":", "")
}

var domains map[string]Records

func loadDomains(path string) (map[string]Records, error) {
	var d map[string]Records

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &d)
	if err != nil {
		return nil, err
	}

	return d, nil
}

func parseDomain(msg []byte) (string, int) {
	var labels []string
	i := 12
	for {
		length := int(msg[i])
		if length == 0 {
			break
		}
		i++
		labels = append(labels, string(msg[i:i+length]))
		i += length
	}
	return strings.ToLower(strings.Join(labels, ".")), i + 1
}

func handleDNS(conn *net.UDPConn, addr *net.UDPAddr, msg []byte) {
	fmt.Printf("Received %x from %s\n", msg, addr.String())

	domain, offset := parseDomain(msg)

	qtype := uint16(msg[offset])<<8 | uint16(msg[offset+1])
	rtype := resourceRecordsID[qtype]

	fmt.Printf("[DNS] Query: %s type %s\n", domain, rtype)

	transactionID := msg[:2]
	flags := []byte{0x81, 0x80}
	if _, ok := domains[domain]; !ok {
		flags = []byte{0x81, 0x83}
	}

	response := make([]byte, 0)
	response = append(response, transactionID...)
	response = append(response, flags...)
	response = append(response, 0x00, 0x01) // QDCOUNT
	response = append(response, 0x00, 0x01) // ANCOUNT
	response = append(response, 0x00, 0x00) // NSCOUNT
	response = append(response, 0x00, 0x00) // ARCOUNT

	// Question section
	questionEnd := offset + 4
	response = append(response, msg[12:questionEnd]...)

	record, _ := domains[domain]
	var rdata string
	shouldProxy := false

	switch rtype {
	case "A":
		rdata = record.IPv4Hex()
		if rdata == "" {
			shouldProxy = true
		}
	case "AAAA":
		rdata = record.IPv6Hex()
		if rdata == "" {
			shouldProxy = true
		}
	default:
		shouldProxy = true
	}

	if shouldProxy {
		proxy(addr, msg, conn)
		return
	}

	// Answer section
	response = append(response, 0xc0, 0x0c)                  // pointer to name
	response = append(response, byte(qtype>>8), byte(qtype)) // TYPE
	response = append(response, 0x00, 0x01)                  // CLASS IN
	response = append(response, 0x00, 0x00, 0x00, 0x3c)      // TTL
	rdataBytes, _ := hex.DecodeString(rdata)
	response = append(response, 0x00, byte(len(rdataBytes))) // RDLENGTH
	response = append(response, rdataBytes...)               // RDATA

	conn.WriteToUDP(response, addr)
}

func proxy(clientAddr *net.UDPAddr, msg []byte, serverConn *net.UDPConn) {
	proxyAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	conn, _ := net.DialUDP("udp", nil, proxyAddr)
	defer conn.Close()

	conn.Write(msg)

	buf := make([]byte, 512)
	n, _, _ := conn.ReadFromUDP(buf)

	serverConn.WriteToUDP(buf[:n], clientAddr)
}

func main() {
	var err error
	domains, err = loadDomains("domains.json")
	if err != nil {
		panic(err)
	}

	go startDNS()

	go startAPI()

	fmt.Println("DNS und TLS Server laufen")

	select {}
}

func startDNS() {
	addr, _ := net.ResolveUDPAddr("udp", ":53")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("DNS server running on port 53")

	for {
		buf := make([]byte, 512)
		n, clientAddr, _ := conn.ReadFromUDP(buf)
		go handleDNS(conn, clientAddr, buf[:n])
	}
}
