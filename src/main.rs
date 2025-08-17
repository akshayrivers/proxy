use native_tls::TlsConnector;
use proxy::{Address, Request, Response};
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;

pub fn socks5_handshake(mut stream: &TcpStream) -> std::io::Result<()> {
    let greeting = [0x05u8, 0x01, 0x00];
    stream.write_all(&greeting)?;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf)?;

    if buf[0] != 0x05 || buf[1] == 0xFF {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "SOCKS5: no acceptable auth method",
        ));
    }
    Ok(())
}

pub fn socks5_connect(mut stream: &TcpStream, target: Address, port: u16) -> std::io::Result<()> {
    let req = Request {
        ver: 5,
        cmd: 1,
        rsv: 0,
        atyp: match &target {
            Address::IPv4(_) => 0x01,
            Address::Domain(_) => 0x03,
            Address::IPv6(_) => 0x04,
        },
        dst_addr: target,
        dst_port: port,
    };
    let req_bytes = req.to_bytes();
    stream.write_all(&req_bytes)?;

    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf)?;
    let resp = Response::from_bytes(&buf[..n])
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Invalid SOCKS5 response"))?;

    if resp.rep != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 connect failed, REP={}", resp.rep),
        ));
    }

    println!("SOCKS5 connected: {:?}", resp);
    Ok(())
}

fn main() -> std::io::Result<()> {
    let proxy_addr = "127.0.0.1:9050";
    let target_host = "kali.org";
    let target_addr = Address::Domain(target_host.to_string());
    let target_port = 443;

    let stream = TcpStream::connect(proxy_addr)?;
    socks5_handshake(&stream)?;
    socks5_connect(&stream, target_addr, target_port)?;

    // Wraping TCP stream in TLS to support https because http throws 301 status code
    let connector = TlsConnector::new().unwrap();
    let mut tls_stream = connector
        .connect(target_host, stream)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Sending HTTPS request
    let request = format!(
    "GET / HTTP/1.1\r\n\
     Host:www.kali.org\r\n\
     User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36\r\n\
     Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
     Accept-Language: en-US,en;q=0.9\r\n\
     Connection: close\r\n\r\n"
);
    tls_stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    tls_stream.read_to_string(&mut response)?;
    let mut file = File::create("response.html")?;
    file.write_all(response.as_bytes())?;
    println!("HTTPS response saved to response.html ✅");

    Ok(())
}
