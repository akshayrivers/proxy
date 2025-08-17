use std::io;

// proxy client :
// 1.Negotiation 2. TCP requests and responses 3. udp support(later)

//Negotiation:
//  Procedure for TCP-based clients

//    When a TCP-based client wishes to establish a connection to an object
//    that is reachable only via a firewall (such determination is left up
//    to the implementation), it must open a TCP connection to the
//    appropriate SOCKS port on the SOCKS server system.  The SOCKS service
//    is conventionally located on TCP port 1080.  If the connection
//    request succeeds, the client enters a negotiation for the
//    authentication method to be used, authenticates with the chosen
//    method, then sends a relay request.  The SOCKS server evaluates the
//    request, and either establishes the appropriate connection or denies
//    it.

//    Unless otherwise noted, the decimal numbers appearing in packet-
//    format diagrams represent the length of the corresponding field, in
//    octets.  Where a given octet must take on a specific value, the
//    syntax X'hh' is used to denote the value of the single octet in that
//    field. When the word 'Variable' is used, it indicates that the
//    corresponding field has a variable length defined either by an
//    associated (one or two octet) length field, or by a data type field.

//    The client connects to the server, and sends a version
//    identifier/method selection message:

//                    +----+----------+----------+
//                    |VER | NMETHODS | METHODS  |
//                    +----+----------+----------+
//                    | 1  |    1     | 1 to 255 |
//                    +----+----------+----------+

//    The VER field is set to X'05' for this version of the protocol.  The
//    NMETHODS field contains the number of method identifier octets that
//    appear in the METHODS field.

//    The server selects from one of the methods given in METHODS, and
//    sends a METHOD selection message:

//                          +----+--------+
//                          |VER | METHOD |
//                          +----+--------+
//                          | 1  |   1    |
//                          +----+--------+

//    If the selected METHOD is X'FF', none of the methods listed by the
//    client are acceptable, and the client MUST close the connection.

//    The values currently defined for METHOD are:

//           o  X'00' NO AUTHENTICATION REQUIRED
//           o  X'01' GSSAPI
//           o  X'02' USERNAME/PASSWORD
//           o  X'03' to X'7F' IANA ASSIGNED
//           o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//           o  X'FF' NO ACCEPTABLE METHODS

//    The client and server then enter a method-specific sub-negotiation.

// Leech, et al                Standards Track                     [Page 3]

// RFC 1928                SOCKS Protocol Version 5              March 1996

//    Descriptions of the method-dependent sub-negotiations appear in
//    separate memos.

//    Developers of new METHOD support for this protocol should contact
//    IANA for a METHOD number.  The ASSIGNED NUMBERS document should be
//    referred to for a current list of METHOD numbers and their
//    corresponding protocols.

//    Compliant implementations MUST support GSSAPI and SHOULD support
//    USERNAME/PASSWORD authentication methods.
// Request format
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

enum Address {
    IPv4([u8; 4]),
    Domain(String),
    IPv6([u8; 16]),
}

struct Request {
    ver: u8,
    cmd: u8,
    rsv: u8,
    atyp: u8,
    dst_addr: Address,
    dst_port: u16,
}

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

struct Response {
    ver: u8,
    rep: u8,
    rsv: u8,
    atyp: u8,
    bnd_addr: Address,
    bnd_port: u16,
}
