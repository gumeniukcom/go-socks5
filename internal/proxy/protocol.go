package proxy

// SOCKS5 protocol constants per RFC 1928 and RFC 1929. Kept in one place to
// avoid magic numbers scattered across the package.
const (
	socks5Version byte = 0x05
	authSubVersion byte = 0x01

	authMethodNoAuth        byte = 0x00
	authMethodUserPassword  byte = 0x02
	authMethodNoneAcceptable byte = 0xFF

	authStatusSuccess byte = 0x00
	authStatusFailure byte = 0x01

	cmdConnect      byte = 0x01
	cmdBind         byte = 0x02
	cmdUDPAssociate byte = 0x03

	addrTypeIPv4   byte = 0x01
	addrTypeDomain byte = 0x03
	addrTypeIPv6   byte = 0x04

	reservedByte byte = 0x00

	repSuccess              byte = 0x00
	repServerFailure        byte = 0x01
	repConnNotAllowed       byte = 0x02
	repNetworkUnreachable   byte = 0x03
	repHostUnreachable      byte = 0x04
	repConnRefused          byte = 0x05
	repTTLExpired           byte = 0x06
	repCommandNotSupported  byte = 0x07
	repAddrTypeNotSupported byte = 0x08
)
