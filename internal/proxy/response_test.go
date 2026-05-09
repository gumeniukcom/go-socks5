package proxy

import (
	"bytes"
	"errors"
	"testing"
)

func TestResponseMarshal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		r    response
		want []byte
		err  error
	}{
		{
			name: "ipv4 success",
			r:    response{reply: repSuccess, addrType: addrTypeIPv4, addr: []byte{1, 2, 3, 4}, port: 80},
			want: []byte{0x05, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0, 80},
		},
		{
			name: "ipv6 success",
			r: response{
				reply:    repSuccess,
				addrType: addrTypeIPv6,
				addr:     bytes.Repeat([]byte{0}, 16),
				port:     443,
			},
			want: append(
				[]byte{0x05, 0x00, 0x00, 0x04},
				append(bytes.Repeat([]byte{0}, 16), 0x01, 0xbb)...,
			),
		},
		{
			name: "domain ok",
			r:    response{reply: repSuccess, addrType: addrTypeDomain, addr: []byte("ab"), port: 1},
			want: []byte{0x05, 0x00, 0x00, 0x03, 2, 'a', 'b', 0, 1},
		},
		{
			name: "ipv4 too short",
			r:    response{reply: repSuccess, addrType: addrTypeIPv4, addr: []byte{1, 2}},
			err:  errAddrTooShort,
		},
		{
			name: "domain too long",
			r:    response{reply: repSuccess, addrType: addrTypeDomain, addr: bytes.Repeat([]byte("a"), 300)},
			err:  errAddrTooLong,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.r.marshal()
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("want %v got %v", tt.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("got %x want %x", got, tt.want)
			}
		})
	}
}

func TestFillFromLocalAddr(t *testing.T) {
	t.Parallel()
	t.Run("ipv4", func(t *testing.T) {
		var r response
		if err := r.fillFromLocalAddr("10.0.0.1:1234"); err != nil {
			t.Fatal(err)
		}
		if r.addrType != addrTypeIPv4 || r.port != 1234 {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("ipv6", func(t *testing.T) {
		var r response
		if err := r.fillFromLocalAddr("[2001:db8::1]:1234"); err != nil {
			t.Fatal(err)
		}
		if r.addrType != addrTypeIPv6 || r.port != 1234 {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("error", func(t *testing.T) {
		var r response
		if err := r.fillFromLocalAddr("not-an-addr"); err == nil {
			t.Fatal("expected error")
		}
	})
}
