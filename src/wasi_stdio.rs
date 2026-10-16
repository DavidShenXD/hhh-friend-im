//! WASI 构建（wasm32-wasip2）的标准输入输出：协议照旧一行一条走标准输入输出，只是 tokio 在 WASI 上没有后台线程，
//! 它自带的 `stdin()` / `stdout()` 用不了。
//!
//! - 输入：WASI 的非阻塞读，读到就交出。tokio 的事件循环只等网络与计时、不等标准输入（tokio 在 WASI 上没有
//!   `AsyncFd`），所以暂时没内容时只能靠计时把自己叫醒：刚读到过（[`HOT`] 以内，大块内容正分段进来）就让一下马上再看；
//!   之后从 [`NAP_MIN`] 起每次加倍、至多 [`NAP_MAX`]，空闲时一秒只醒几十次。代价是空闲后第一条请求至多晚 [`NAP_MAX`]。
//! - 输出：直接同步写进标准输出（每次一行协议消息，写进宿主的管道很快）。

use std::future::Future as _;
use std::io::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wasip2::io::streams::{InputStream, StreamError};

/// 刚读到过内容多久之内，没内容时不睡、让一下马上再看。
const HOT: Duration = Duration::from_millis(2);
/// 空闲时第一次睡多久。
const NAP_MIN: Duration = Duration::from_millis(1);
/// 空闲时至多睡多久。
const NAP_MAX: Duration = Duration::from_millis(16);

/// 标准输入。
pub(crate) struct Stdin {
    stream: InputStream,
    nap: Option<Pin<Box<tokio::time::Sleep>>>,
    last_data: Instant,
    next_nap: Duration,
}

impl Stdin {
    pub(crate) fn new() -> Self {
        Self { stream: wasip2::cli::stdin::get_stdin(), nap: None, last_data: Instant::now(), next_nap: NAP_MIN }
    }
}

impl AsyncRead for Stdin {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            if let Some(nap) = self.nap.as_mut() {
                if nap.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.nap = None;
            }
            match self.stream.read(buf.remaining() as u64) {
                Ok(bytes) if !bytes.is_empty() => {
                    self.last_data = Instant::now();
                    self.next_nap = NAP_MIN;
                    buf.put_slice(&bytes);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) if self.last_data.elapsed() < HOT => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Ok(_) => {
                    let nap = self.next_nap;
                    self.next_nap = (nap * 2).min(NAP_MAX);
                    self.nap = Some(Box::pin(tokio::time::sleep(nap)));
                }
                // 宿主关了标准输入：读完了。
                Err(StreamError::Closed) => return Poll::Ready(Ok(())),
                Err(StreamError::LastOperationFailed(error)) => {
                    return Poll::Ready(Err(std::io::Error::other(error.to_debug_string())));
                }
            }
        }
    }
}

/// 标准输出。
pub(crate) struct Stdout;

impl AsyncWrite for Stdout {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(std::io::stdout().write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(std::io::stdout().flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(std::io::stdout().flush())
    }
}
