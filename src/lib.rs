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

pub enum Address {
    IPv4([u8; 4]),
    Domain(String),
    IPv6([u8; 16]),
}

pub struct Request {
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

pub struct Response {
    ver: u8,
    rep: u8,
    rsv: u8,
    atyp: u8,
    bnd_addr: Address,
    bnd_port: u16,
}

impl Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Address::IPv4(addr) => {
                let mut bytes = vec![0x01]; // IPV4
                bytes.extend_from_slice(addr);
                bytes
            }
            Address::Domain(domain) => {
                let mut bytes = vec![0x03]; //Domain
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                bytes
            }
            Address::IPv6(addr) => {
                let mut bytes = vec![0x04]; //IPV6
                bytes.extend_from_slice(addr);
                bytes
            }
        }
    }
}
impl Request {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.ver);
        buf.push(self.cmd);
        buf.push(self.rsv);

        let mut addr_bytes = self.dst_addr.to_bytes();
        buf.append(&mut addr_bytes);
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf
    }
}
impl Response {
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        let ver = buf[0];
        let rep = buf[1];
        let rsv = buf[2];
        let atyp = buf[3];
        let (bnd_addr, offset) = match atyp {
            0x01 => {
                if buf.len() < 10 {
                    return None;
                }
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(&buf[4..8]);
                (Address::IPv4(ipv4), 8)
            }
            0x03 => {
                let len = buf[4] as usize;
                if buf.len() < 5 + len + 2 {
                    return None;
                }
                let domain = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
                (Address::Domain(domain), 5 + len)
            }
            0x04 => {
                if buf.len() < 22 {
                    return None;
                }
                let mut ipv6 = [0u8; 16];
                ipv6.copy_from_slice(&buf[4..20]);
                (Address::IPv6(ipv6), 20)
            }
            _ => return None,
        };
        let bnd_port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        Some(Response {
            ver,
            rep,
            rsv,
            atyp,
            bnd_addr,
            bnd_port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_address_to_bytes() {
        let addr = Address::IPv4([127, 0, 0, 1]);
        let bytes = addr.to_bytes();
        assert_eq!(bytes, vec![0x01, 127, 0, 0, 1]);
    }

    #[test]
    fn test_domain_address_to_bytes() {
        let addr = Address::Domain("example.com".to_string());
        let bytes = addr.to_bytes();
        let mut expected = vec![0x03, 11]; // type + length
        expected.extend_from_slice(b"example.com");
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_ipv6_address_to_bytes() {
        let addr = Address::IPv6([0u8; 16]);
        let bytes = addr.to_bytes();
        let mut expected = vec![0x04];
        expected.extend_from_slice(&[0u8; 16]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_request_to_bytes_ipv4() {
        let req = Request {
            ver: 5,
            cmd: 1,
            rsv: 0,
            atyp: 0x01,
            dst_addr: Address::IPv4([127, 0, 0, 1]),
            dst_port: 8080,
        };

        let bytes = req.to_bytes();
        // Expected: VER, CMD, RSV, ATYP + ADDR + PORT
        let mut expected = vec![5, 1, 0, 0x01, 127, 0, 0, 1];
        expected.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_request_to_bytes_domain() {
        let req = Request {
            ver: 5,
            cmd: 1,
            rsv: 0,
            atyp: 0x03,
            dst_addr: Address::Domain("example.com".to_string()),
            dst_port: 80,
        };

        let bytes = req.to_bytes();
        // Expected: VER, CMD, RSV, ATYP + LEN + "example.com" + PORT
        let mut expected = vec![5, 1, 0, 0x03, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_response_from_bytes_ipv4() {
        let buf = vec![
            0x05, 0x00, 0x00, 0x01, // VER, REP, RSV, ATYP (IPv4)
            127, 0, 0, 1, // BND.ADDR
            0x1F, 0x90, // BND.PORT = 8080
        ];

        let resp = Response::from_bytes(&buf).unwrap();
        assert_eq!(resp.ver, 5);
        assert_eq!(resp.rep, 0);
        assert_eq!(resp.rsv, 0);
        assert_eq!(resp.atyp, 1);
        match resp.bnd_addr {
            Address::IPv4(addr) => assert_eq!(addr, [127, 0, 0, 1]),
            _ => panic!("Expected IPv4"),
        }
        assert_eq!(resp.bnd_port, 8080);
    }

    #[test]
    fn test_response_from_bytes_domain() {
        let mut buf = vec![0x05, 0x00, 0x00, 0x03, 11]; // VER, REP, RSV, ATYP, LEN
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&80u16.to_be_bytes());

        let resp = Response::from_bytes(&buf).unwrap();
        assert_eq!(resp.ver, 5);
        assert_eq!(resp.rep, 0);
        assert_eq!(resp.atyp, 3);
        match resp.bnd_addr {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("Expected Domain"),
        }
        assert_eq!(resp.bnd_port, 80);
    }

    #[test]
    fn test_response_from_bytes_ipv6() {
        let mut buf = vec![0x05, 0x00, 0x00, 0x04]; // VER, REP, RSV, ATYP (IPv6)
        buf.extend_from_slice(&[0u8; 16]); // BND.ADDR
        buf.extend_from_slice(&443u16.to_be_bytes());

        let resp = Response::from_bytes(&buf).unwrap();
        assert_eq!(resp.ver, 5);
        assert_eq!(resp.rep, 0);
        assert_eq!(resp.atyp, 4);
        match resp.bnd_addr {
            Address::IPv6(addr) => assert_eq!(addr, [0u8; 16]),
            _ => panic!("Expected IPv6"),
        }
        assert_eq!(resp.bnd_port, 443);
    }
}
