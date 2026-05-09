package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// response is the SOCKS5 reply structure per RFC 1928 §6.
type response struct {
	reply    byte
	addrType byte
	addr     []byte
	port     uint16
}

var (
	errAddrTooShort = errors.New("response: address too short")
	errAddrTooLong  = errors.New("response: address too long")
	errEmptyIP      = errors.New("response: empty IP")
)

// marshal serializes the response to wire bytes.
func (r *response) marshal() ([]byte, error) {
	buf := make([]byte, 0, 4+net.IPv6len+2)
	buf = append(buf, socks5Version, r.reply, reservedByte, r.addrType)

	switch r.addrType {
	case addrTypeIPv4:
		if len(r.addr) < net.IPv4len {
			return nil, errAddrTooShort
		}
		buf = append(buf, r.addr[:net.IPv4len]...)
	case addrTypeIPv6:
		if len(r.addr) < net.IPv6len {
			return nil, errAddrTooShort
		}
		buf = append(buf, r.addr[:net.IPv6len]...)
	case addrTypeDomain:
		if len(r.addr) > 255 {
			return nil, errAddrTooLong
		}
		buf = append(buf, byte(len(r.addr)))
		buf = append(buf, r.addr...)
	default:
		return nil, errAddrTooShort
	}

	buf = append(buf, 0, 0)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], r.port)
	return buf, nil
}

// errorResponse returns a minimal IPv4 0.0.0.0:0 reply with the given code.
// Useful when the server cannot or chose not to provide a bound address.
func errorResponse(code byte) []byte {
	return []byte{
		socks5Version, code, reservedByte, addrTypeIPv4,
		0, 0, 0, 0, // addr
		0, 0, // port
	}
}

// fillFromLocalAddr populates addrType/addr/port from a net.Conn local
// address string (e.g. "1.2.3.4:5678" or "[::1]:5678").
func (r *response) fillFromLocalAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errEmptyIP
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		r.addrType = addrTypeIPv4
		r.addr = ipv4
	} else {
		r.addrType = addrTypeIPv6
		r.addr = ip.To16()
	}
	prt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("response: invalid port %q: %w", port, err)
	}
	if prt < 0 || prt > 0xFFFF {
		return fmt.Errorf("response: port %d out of range", prt)
	}
	r.port = uint16(prt) //nolint:gosec // bounded by check above
	return nil
}
