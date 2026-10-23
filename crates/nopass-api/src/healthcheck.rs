//! `nopass-api healthcheck`: probes the API's own health endpoint and exits 0
//! or 1. Kubernetes runs it as an exec probe, so health checks never depend on
//! a network path from the kubelet into the pod, which the namespace's
//! default-deny NetworkPolicy would otherwise have to allow.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_secs(2);

/// True when `GET /v1/health` on `addr` answers with a 2xx status.
pub fn check(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    let request = "GET /v1/health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = [0u8; 16];
    if stream.read_exact(&mut head).is_err() {
        return false;
    }
    // "HTTP/1.1 200 ..." — the status code starts at byte 9
    head.starts_with(b"HTTP/1.") && head[9] == b'2'
}

/// Entry point for the subcommand; the port comes from NOPASS_PORT like the server's.
pub fn run() -> i32 {
    let port: u16 = std::env::var("NOPASS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);
    if check(SocketAddr::from(([127, 0, 0, 1], port))) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve_once(response: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                let _ = s.write_all(response.as_bytes());
            }
        });
        addr
    }

    #[test]
    fn healthy_only_when_the_endpoint_answers_2xx() {
        assert!(check(serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")));
        assert!(!check(serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n")));
        assert!(!check(serve_once("HTTP/1.1 500 Internal Server Error\r\n\r\n")));
    }

    #[test]
    fn unhealthy_when_nothing_listens() {
        let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(!check(addr));
    }
}
