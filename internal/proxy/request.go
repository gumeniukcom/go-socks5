package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// request is the parsed CONNECT/BIND/UDP ASSOCIATE request from a client.
type request struct {
	version  byte
	command  byte
	reserved byte
	addrType byte

	addr []byte
	port uint16
}

var (
	errBadVersion       = errors.New("request: bad SOCKS version")
	errBadReserved      = errors.New("request: reserved byte must be 0x00")
	errAddrTypeNotSupp  = errors.New("request: address type not supported")
	errEmptyDomain      = errors.New("request: domain length must be > 0")
)

// fqdn returns "host:port" suitable for net.Dial.
func (r *request) fqdn() string {
	var host string
	switch r.addrType {
	case addrTypeIPv4:
		host = net.IPv4(r.addr[0], r.addr[1], r.addr[2], r.addr[3]).String()
	case addrTypeDomain:
		host = string(r.addr)
	case addrTypeIPv6:
		host = net.IP(r.addr).String()
	default:
		host = ""
	}
	return net.JoinHostPort(host, strconv.Itoa(int(r.port)))
}

// readRequest decodes a SOCKS5 request from src per RFC 1928 §4.
func readRequest(src io.Reader) (*request, error) {
	r := &request{}

	if err := binary.Read(src, binary.BigEndian, &r.version); err != nil {
		return nil, fmt.Errorf("request: read version: %w", err)
	}
	if r.version != socks5Version {
		return nil, fmt.Errorf("%w: 0x%02x", errBadVersion, r.version)
	}
	if err := binary.Read(src, binary.BigEndian, &r.command); err != nil {
		return nil, fmt.Errorf("request: read command: %w", err)
	}
	if err := binary.Read(src, binary.BigEndian, &r.reserved); err != nil {
		return nil, fmt.Errorf("request: read reserved: %w", err)
	}
	if r.reserved != reservedByte {
		return nil, errBadReserved
	}
	if err := binary.Read(src, binary.BigEndian, &r.addrType); err != nil {
		return nil, fmt.Errorf("request: read addr type: %w", err)
	}

	var addrLen int
	switch r.addrType {
	case addrTypeIPv4:
		addrLen = net.IPv4len
	case addrTypeIPv6:
		addrLen = net.IPv6len
	case addrTypeDomain:
		var b byte
		if err := binary.Read(src, binary.BigEndian, &b); err != nil {
			return nil, fmt.Errorf("request: read domain length: %w", err)
		}
		if b == 0 {
			return nil, errEmptyDomain
		}
		addrLen = int(b)
	default:
		return nil, fmt.Errorf("%w: 0x%02x", errAddrTypeNotSupp, r.addrType)
	}

	r.addr = make([]byte, addrLen)
	if _, err := io.ReadFull(src, r.addr); err != nil {
		return nil, fmt.Errorf("request: read addr: %w", err)
	}
	if err := binary.Read(src, binary.BigEndian, &r.port); err != nil {
		return nil, fmt.Errorf("request: read port: %w", err)
	}
	return r, nil
}
