//! WASI 构建（wasm32-wasip2）连服务器的 TCP 入口：websocket 与 HTTP 共用。
//!
//! tokio 在 WASI 上没有后台线程，按主机名连接（`TcpStream::connect("host:port")`）要用阻塞线程查地址，用不了；
//! 这里先查出地址（IP 写法直接用，主机名走标准库的解析，WASI 下由宿主答），再按地址逐个连。

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};

use tokio::net::TcpStream;

/// 连上 `host:port`：IP 直接连；主机名查出全部地址，按顺序连，第一个连上的为准。
pub(crate) async fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in resolve(host, port)? {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("查不到 {host} 的地址"))))
}

fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    Ok((bare, port).to_socket_addrs()?.collect())
}

/// 地址里的主机与端口（`ws`/`http` 缺省 80，`wss`/`https` 缺省 443）。
pub(crate) fn host_port(uri: &http::Uri) -> io::Result<(String, u16, bool)> {
    let host = uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "地址里没有主机"))?.to_owned();
    let tls = matches!(uri.scheme_str(), Some("https" | "wss"));
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    Ok((host, port, tls))
}
