//! WASI 构建（wasm32-wasip2）的 HTTP 客户端：reqwest 在 wasm32 上只有浏览器版本（靠 JS 的 fetch），WASI 里用不了，
//! 这里只实现 Cindy IM 用到的那一小部分 reqwest 接口，名字与用法相同，调用处不分平台：
//! `GET` / `PUT` / `HEAD`、请求头、请求体、连接超时与整体超时、不跟随跳转、读状态与响应头、按块读或一次读完响应体。
//!
//! 底层是 hyper（HTTP/1.1）跑在 tokio 网络上，https 用 rustls（ring，webpki 根证书），和 websocket 共用同一个事件循环。
//! 连接按“协议 + 主机 + 端口”留着复用（至多 [`IDLE_MAX`] 条）；不跟随跳转（与原生构建里 `Policy::none()` 的用法一致，
//! 文件接口本来也不跳转）。

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

pub use http::StatusCode;
pub use http::header;

/// 同一个地址至多留几条空闲连接。
const IDLE_MAX: usize = 4;

/// 跳转政策。本实现从不跟随跳转，`none()` 只为与 reqwest 的写法一致。
pub mod redirect {
    /// 不跟随跳转。
    #[derive(Debug, Clone, Copy)]
    pub struct Policy(());

    impl Policy {
        /// 不跟随跳转。
        pub fn none() -> Self {
            Self(())
        }
    }
}

/// 请求失败：连不上、超时、TLS、读写中断或地址不对。
#[derive(Debug)]
pub struct Error(String);

impl Error {
    fn new(what: impl fmt::Display) -> Self {
        Self(what.to_string())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Sender = SendRequest<Full<Bytes>>;

struct Inner {
    connect_timeout: Option<Duration>,
    timeout: Option<Duration>,
    tls: tokio_rustls::TlsConnector,
    idle: Mutex<HashMap<String, Vec<Sender>>>,
}

/// HTTP 客户端，克隆共用同一个连接池。
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

/// [`Client`] 的设置。
#[derive(Default)]
pub struct ClientBuilder {
    connect_timeout: Option<Duration>,
    timeout: Option<Duration>,
}

impl ClientBuilder {
    /// 建连（TCP + TLS）至多等多久。
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// 一次请求（含读完响应体）至多多久；单个请求可用 [`RequestBuilder::timeout`] 另设。
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// 跳转政策（本实现总是不跟随）。
    pub fn redirect(self, _policy: redirect::Policy) -> Self {
        self
    }

    /// 建客户端。
    ///
    /// # Errors
    /// TLS 设置建不起来时。
    pub fn build(self) -> Result<Client, Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(Error::new)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Client {
            inner: Arc::new(Inner {
                connect_timeout: self.connect_timeout,
                timeout: self.timeout,
                tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
                idle: Mutex::new(HashMap::new()),
            }),
        })
    }
}

/// 缺省设置的客户端（与 reqwest 一样，TLS 建不起来时 panic；用的是内置根证书，实际总能建起来）。
impl Default for Client {
    fn default() -> Self {
        ClientBuilder::default().build().expect("内置根证书的 TLS 设置总能建起来")
    }
}

impl Client {
    /// 设置客户端。
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// `GET` 请求。
    pub fn get(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::GET, url.as_ref())
    }

    /// `PUT` 请求。
    pub fn put(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::PUT, url.as_ref())
    }

    /// `HEAD` 请求。
    pub fn head(&self, url: impl AsRef<str>) -> RequestBuilder {
        self.request(Method::HEAD, url.as_ref())
    }

    fn request(&self, method: Method, url: &str) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            method,
            url: url.to_owned(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            timeout: self.inner.timeout,
            error: None,
        }
    }

    fn take_idle(&self, key: &str) -> Option<Sender> {
        let mut idle = self.inner.idle.lock().unwrap_or_else(|p| p.into_inner());
        let list = idle.get_mut(key)?;
        list.retain(|sender| !sender.is_closed());
        let at = list.iter().position(Sender::is_ready)?;
        Some(list.swap_remove(at))
    }

    fn keep(&self, key: String, sender: Sender) {
        let mut idle = self.inner.idle.lock().unwrap_or_else(|p| p.into_inner());
        let list = idle.entry(key).or_default();
        list.retain(|sender| !sender.is_closed());
        if list.len() < IDLE_MAX {
            list.push(sender);
        }
    }

    async fn connect(&self, host: &str, port: u16, tls: bool) -> Result<Sender, Error> {
        let open = async {
            let tcp = crate::wasi_net::connect_tcp(host, port).await.map_err(Error::new)?;
            let io: Box<dyn Io> = if tls {
                let name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(Error::new)?;
                Box::new(self.inner.tls.connect(name, tcp).await.map_err(Error::new)?)
            } else {
                Box::new(tcp)
            };
            let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await.map_err(Error::new)?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::debug!(%error, "HTTP 连接断了");
                }
            });
            Ok(sender)
        };
        match self.inner.connect_timeout {
            Some(limit) => tokio::time::timeout(limit, open).await.map_err(|_| Error::new("连接超时"))?,
            None => open.await,
        }
    }
}

/// 一个待发的请求。
pub struct RequestBuilder {
    client: Client,
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Bytes,
    timeout: Option<Duration>,
    error: Option<Error>,
}

impl RequestBuilder {
    /// 加一个请求头。
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        match (HeaderName::try_from(key), HeaderValue::try_from(value)) {
            (Ok(key), Ok(value)) => {
                self.headers.append(key, value);
            }
            (Err(error), _) => self.error = Some(Error::new(Into::<http::Error>::into(error))),
            (_, Err(error)) => self.error = Some(Error::new(Into::<http::Error>::into(error))),
        }
        self
    }

    /// 请求体。
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// 这个请求（含读完响应体）至多多久。
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// 发出去，等到响应头。
    ///
    /// # Errors
    /// 地址不对、连不上、超时或连接中断时。
    pub async fn send(self) -> Result<Response, Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let deadline = self.timeout.map(|limit| Instant::now() + limit);
        let uri: http::Uri = self.url.parse().map_err(Error::new)?;
        let (host, port, tls) = crate::wasi_net::host_port(&uri).map_err(Error::new)?;
        let authority = uri.authority().map(|a| a.as_str().to_owned()).unwrap_or_else(|| host.clone());
        let key = format!("{}://{authority}", if tls { "https" } else { "http" });
        let path = uri.path_and_query().map_or("/", |p| p.as_str());

        let mut request = Request::builder().method(self.method).uri(path).body(Full::new(self.body)).map_err(Error::new)?;
        *request.headers_mut() = self.headers;
        request.headers_mut().insert(HOST, HeaderValue::from_str(&authority).map_err(Error::new)?);

        let exchange = async {
            let mut sender = match self.client.take_idle(&key) {
                Some(sender) => sender,
                None => self.client.connect(&host, port, tls).await?,
            };
            let response = sender.send_request(request).await.map_err(Error::new)?;
            self.client.keep(key, sender);
            Ok::<_, Error>(response)
        };
        let response = match deadline {
            Some(at) => tokio::time::timeout_at(at, exchange).await.map_err(|_| Error::new("请求超时"))??,
            None => exchange.await?,
        };
        let (parts, body) = response.into_parts();
        Ok(Response { status: parts.status, headers: parts.headers, body, deadline })
    }
}

/// 收到的响应：状态、响应头，响应体按需读。
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Incoming,
    deadline: Option<Instant>,
}

impl Response {
    /// 状态码。
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// 响应头。
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// 读下一块响应体；读完为 `None`。
    ///
    /// # Errors
    /// 超时或连接中断时。
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, Error> {
        loop {
            let frame = match self.deadline {
                Some(at) => tokio::time::timeout_at(at, self.body.frame()).await.map_err(|_| Error::new("读响应超时"))?,
                None => self.body.frame().await,
            };
            match frame {
                None => return Ok(None),
                Some(Err(error)) => return Err(Error::new(error)),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }

    /// 读完整个响应体。
    ///
    /// # Errors
    /// 超时或连接中断时。
    pub async fn bytes(mut self) -> Result<Bytes, Error> {
        let mut all = Vec::new();
        while let Some(data) = self.chunk().await? {
            all.extend_from_slice(&data);
        }
        Ok(Bytes::from(all))
    }
}
