package proxy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRequestFQDN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  request
		want string
	}{
		{
			name: "ipv4",
			req:  request{addrType: addrTypeIPv4, addr: []byte{8, 8, 8, 8}, port: 53},
			want: "8.8.8.8:53",
		},
		{
			name: "ipv6",
			req: request{
				addrType: addrTypeIPv6,
				addr:     []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
				port:     443,
			},
			want: "[2001:db8::1]:443",
		},
		{
			name: "domain",
			req:  request{addrType: addrTypeDomain, addr: []byte("example.com"), port: 80},
			want: "example.com:80",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.fqdn(); got != tt.want {
				t.Errorf("fqdn = %q want %q", got, tt.want)
			}
		})
	}
}

func TestReadRequest(t *testing.T) {
	t.Parallel()
	t.Run("ipv4 connect", func(t *testing.T) {
		raw := bytes.NewReader([]byte{
			0x05, 0x01, 0x00, 0x01,
			192, 168, 1, 1,
			0x00, 0x50, // port 80
		})
		r, err := readRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if r.command != cmdConnect || r.addrType != addrTypeIPv4 || r.port != 80 {
			t.Fatalf("bad parse: %+v", r)
		}
	})

	t.Run("rejects bad version", func(t *testing.T) {
		raw := bytes.NewReader([]byte{0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
		_, err := readRequest(raw)
		if !errors.Is(err, errBadVersion) {
			t.Fatalf("want errBadVersion, got %v", err)
		}
	})

	t.Run("rejects bad reserved", func(t *testing.T) {
		raw := bytes.NewReader([]byte{0x05, 0x01, 0x42, 0x01, 1, 2, 3, 4, 0, 80})
		_, err := readRequest(raw)
		if !errors.Is(err, errBadReserved) {
			t.Fatalf("want errBadReserved, got %v", err)
		}
	})

	t.Run("rejects empty domain", func(t *testing.T) {
		raw := bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x03, 0x00, 0, 80})
		_, err := readRequest(raw)
		if !errors.Is(err, errEmptyDomain) {
			t.Fatalf("want errEmptyDomain, got %v", err)
		}
	})

	t.Run("rejects unknown addr type", func(t *testing.T) {
		raw := bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x09, 0, 0, 0, 0})
		_, err := readRequest(raw)
		if !errors.Is(err, errAddrTypeNotSupp) {
			t.Fatalf("want errAddrTypeNotSupp, got %v", err)
		}
	})

	t.Run("truncated", func(t *testing.T) {
		raw := bytes.NewReader([]byte{0x05, 0x01, 0x00, 0x01, 1})
		_, err := readRequest(raw)
		if err == nil || !strings.Contains(err.Error(), "addr") {
			t.Fatalf("want addr-read error, got %v", err)
		}
	})
}

func FuzzReadRequest(f *testing.F) {
	seeds := [][]byte{
		{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80},
		{0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0, 80},
		{0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readRequest(bytes.NewReader(data))
	})
}
