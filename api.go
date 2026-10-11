package main

import (
	"os"
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"strings"
	"encoding/json"
)

func startAPI() {
	cert, err := tls.LoadX509KeyPair(
		"server-cert.pem",
		"server-key.pem",
	)
	if err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":7002", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("TLS-Server läuft auf Port 7002")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept:", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		log.Println("TLS-Handshake:", err)
		return
	}

	log.Println("Con",
		tlsConn.RemoteAddr())

	scanner := bufio.NewScanner(tlsConn)
	writer := bufio.NewWriter(tlsConn)

	for scanner.Scan() {
		message := scanner.Text()
		log.Println("Nachricht:", message)

		if _, err := writer.WriteString(
			strings.ToUpper(message) + "\n",
		); err != nil {
			return
		}

		if err := writer.Flush(); err != nil {
			return
		}

		var data map[string]string
		if err := json.Unmarshal([]byte(message), &data); err != nil {
			continue
		}

		token, exists1 := data["token"]

		if !exists1 || token == ""{
			continue
		}

		if token != "password" {
			continue
		}

		record, exists := domains[data["domain"]]
		if exists {
			if data["ipv4"] != "" {
				record.IPv4 = data["ipv4"]
			}
			if data["ipv6"] != "" {
				record.IPv6 = data["ipv6"]
			}
		} else {
			if data["ipv4"] != "" && data["ipv6"] == ""{
		   		record = Records{
		       		IPv4: data["ipv4"],
				}
			}

			if data["ipv4"] == "" && data["ipv6"] != "" {
				record = Records{
					IPv6: data["ipv6"],
				}
			}

			if data["ipv4"] != "" && data["ipv6"] != "" {
				record = Records{
					IPv4: data["ipv4"],
					IPv6: data["ipv6"],
				}
			}
		}

		domains[data["domain"]] = record

		jsonBytes, err := json.Marshal(domains)
		if err != nil {
			continue
		}

		os.WriteFile("domains.json",jsonBytes,0644)

	}

	if err := scanner.Err(); err != nil {
		log.Println("Lesefehler:", err)
	}
}
