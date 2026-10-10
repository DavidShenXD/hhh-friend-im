//! 文件、图片的上传下载（方案 §3：每个文件一把随机钥匙，按 64 KiB 分段加密）。
//!
//! - 上传：边读边加密，攒够一段请求（≤ 8 MiB）就 `PUT /v1/files/{编号}`；断了先 `HEAD` 问服务器收到哪里，从那里续传。
//! - 下载：`GET` 边收边解，每收齐一段密文就解开写出去；断了带 `Range` 从收到的位置续下。
//! - 内存里最多同时有一段请求的数据，大文件不会整份进内存；文件内容不占客户端的状态锁，传文件时照常收消息。
//!
//! 服务器只拿到密文；文件钥匙、文件名和类型都在 [`FileRef`] 里，随加了密的消息正文发给对方。

use std::io::{Read, Write};
use std::time::Duration;

use friend_im_core::bytes::{self, Fixed};
use friend_im_core::file::{self, CHUNK_PLAIN, CHUNK_SEALED, Decryptor, Encryptor, FileRef};
use friend_im_core::ids::{ConvId, FileId};
use friend_im_core::limits;
use friend_im_core::wire::{Request, Response};
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, RANGE};

use crate::client::Client;
use crate::error::{ClientError, Result};

/// 一次请求最多带几段密文：不超过服务器的单次上限。
const CHUNKS_PER_PART: usize = limits::UPLOAD_PART_MAX / CHUNK_SEALED;
/// 一段请求（或一次续下）失败后最多重试几次。
const RETRIES: u32 = 3;
/// 一段请求的超时：8 MiB 在 1 Mbps 下约 70 秒，留出余量。
const PART_TIMEOUT: Duration = Duration::from_secs(180);

fn transfer(message: impl Into<String>) -> ClientError {
    ClientError::Transfer(message.into())
}

/// 文件请求要带的登录凭证与地址。
struct Endpoint {
    url: String,
    bearer: String,
}

async fn endpoint(client: &Client, file: &FileId) -> Result<Endpoint> {
    let session = client.inner.state.lock().await.creds.session.clone().ok_or_else(|| ClientError::state("没有登录凭证"))?;
    Ok(Endpoint {
        url: format!("{}/v1/files/{}", client.inner.base, file),
        bearer: format!("Bearer {}", bytes::encode(&session.0)),
    })
}

fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf).map_err(|error| {
        tracing::info!(%error, "读要上传的文件失败");
        transfer("读不出要上传的文件，或文件比说的小")
    })
}

/// 上传：返回放进消息正文的 [`FileRef`]。`size` 是明文字节数，`reader` 必须正好给出这么多字节。
pub(crate) async fn upload(client: &Client, conv: &ConvId, mut reader: impl Read, size: u64, name: &str, mime: &str) -> Result<FileRef> {
    if size > limits::FILE_PLAIN_MAX {
        return Err(ClientError::state("文件超过 100 MiB"));
    }
    let key = file::generate_key();
    let reference = FileRef {
        // 编号由服务器分配，下面拿到后替换；这里先用一个占位校验文件名与类型。
        id: FileId::random(),
        key: Fixed(*key),
        size,
        name: name.to_owned(),
        mime: mime.to_owned(),
    };
    reference.check()?;
    let sealed_size = file::sealed_len(size);
    let conn = client.inner_conn()?;
    let Response::FileCreated { file: id } = conn.request(Request::FileCreate { conv: conv.clone(), size: sealed_size }).await? else {
        return Err(ClientError::protocol("回执不对"));
    };
    let end = endpoint(client, &id).await?;

    let chunks = size.div_ceil(CHUNK_PLAIN as u64).max(1);
    let mut encryptor = Encryptor::new(&key);
    let mut plain = vec![0u8; CHUNK_PLAIN];
    let mut part = Vec::with_capacity(CHUNKS_PER_PART * CHUNK_SEALED);
    let mut offset = 0u64;
    for index in 0..chunks {
        let last = index + 1 == chunks;
        let len = if last { (size - index * CHUNK_PLAIN as u64) as usize } else { CHUNK_PLAIN };
        read_full(&mut reader, &mut plain[..len])?;
        part.extend_from_slice(&encryptor.seal_chunk(&plain[..len], last)?);
        if last || part.len() + CHUNK_SEALED > limits::UPLOAD_PART_MAX {
            offset = put_part(client, &end, offset, &part).await?;
            part.clear();
        }
    }
    // 文件比说的大：服务器那边的大小已经定了，只能作废重来。
    let mut probe = [0u8; 1];
    if !matches!(reader.read(&mut probe), Ok(0)) {
        return Err(transfer("文件比说的大"));
    }
    if offset != sealed_size {
        return Err(transfer("上传的字节数不对"));
    }
    tracing::info!(file = %id, size, "文件已上传");
    Ok(FileRef { id, ..reference })
}

/// 传一段（从 `offset` 开始的 `data`），返回服务器收到的位置。失败时问服务器收到哪里，从那里续传。
async fn put_part(client: &Client, end: &Endpoint, offset: u64, data: &[u8]) -> Result<u64> {
    let target = offset + data.len() as u64;
    let mut at = offset;
    let mut failures = 0;
    loop {
        let body = data[(at - offset) as usize..].to_vec();
        let result = client
            .inner
            .http
            .put(&end.url)
            .header(AUTHORIZATION, &end.bearer)
            .header("Upload-Offset", at)
            .header(CONTENT_TYPE, "application/octet-stream")
            .timeout(PART_TIMEOUT)
            .body(body)
            .send()
            .await;
        match result {
            Ok(response) if response.status() == StatusCode::NO_CONTENT => {
                let received = upload_offset(&response).ok_or_else(|| ClientError::protocol("上传回执缺少位置"))?;
                if received != target {
                    return Err(ClientError::protocol("服务器收到的位置不对"));
                }
                return Ok(received);
            }
            Ok(response) if response.status() == StatusCode::UNAUTHORIZED => return Err(transfer("登录凭证无效")),
            Ok(response) if response.status() == StatusCode::PAYLOAD_TOO_LARGE => return Err(transfer("超过服务器的文件上限")),
            Ok(response) if response.status() != StatusCode::CONFLICT && response.status().is_client_error() => {
                return Err(transfer(format!("服务器拒绝：HTTP {}", response.status())));
            }
            Ok(response) => tracing::info!(status = %response.status(), "上传一段没成，问服务器收到哪里"),
            Err(error) => tracing::info!(%error, "上传一段断了，问服务器收到哪里"),
        }
        failures += 1;
        if failures > RETRIES {
            return Err(transfer("上传多次失败"));
        }
        tokio::time::sleep(Duration::from_millis(500 * u64::from(failures))).await;
        let received = match progress(client, end).await {
            Ok(received) => received,
            // 还没恢复（比如仍在断网）：算一次失败，下一轮从原来的位置再传，服务器收得比它多时会回“位置不对”再问。
            Err(error) => {
                tracing::info!(%error, "问上传进度没成，稍后再试");
                continue;
            }
        };
        if received < offset || received > target {
            return Err(transfer("服务器收到的位置不在这一段里"));
        }
        if received == target {
            return Ok(received);
        }
        at = received;
    }
}

fn upload_offset(response: &reqwest::Response) -> Option<u64> {
    response.headers().get("Upload-Offset")?.to_str().ok()?.parse().ok()
}

async fn progress(client: &Client, end: &Endpoint) -> Result<u64> {
    let response = client
        .inner
        .http
        .head(&end.url)
        .header(AUTHORIZATION, &end.bearer)
        .timeout(PART_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            tracing::info!(%error, "问上传进度失败");
            transfer("连不上服务器")
        })?;
    if !response.status().is_success() {
        return Err(transfer(format!("问上传进度失败：HTTP {}", response.status())));
    }
    upload_offset(&response).ok_or_else(|| ClientError::protocol("进度回执缺少位置"))
}

/// 下载并解密到 `out`：每收齐一段密文就解开写出去，被改过、截短、调换的文件在这里报错。
pub(crate) async fn download(client: &Client, file: &FileRef, out: &mut impl Write) -> Result<()> {
    file.check()?;
    let end = endpoint(client, &file.id).await?;
    let total = file::sealed_len(file.size);
    let chunks = file.size.div_ceil(CHUNK_PLAIN as u64).max(1);
    let mut decryptor = Decryptor::new(&file.key.0);
    let mut pending: Vec<u8> = Vec::with_capacity(CHUNK_SEALED * 2);
    let mut received = 0u64;
    let mut opened = 0u64;
    let mut failures = 0;
    while received < total {
        let mut request = client.inner.http.get(&end.url).header(AUTHORIZATION, &end.bearer).timeout(PART_TIMEOUT);
        if received > 0 {
            request = request.header(RANGE, format!("bytes={received}-"));
        }
        let outcome = async {
            let mut response = request.send().await.map_err(|error| {
                tracing::info!(%error, "下载请求失败");
                None
            })?;
            let expected = if received > 0 { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK };
            if response.status() != expected {
                tracing::info!(status = %response.status(), "下载被拒");
                let fatal = response.status().is_client_error();
                return Err(fatal.then(|| transfer(format!("服务器拒绝：HTTP {}", response.status()))));
            }
            while let Some(data) = response.chunk().await.map_err(|error| {
                tracing::info!(%error, "下载中途断了");
                None
            })? {
                received += data.len() as u64;
                if received > total {
                    return Err(Some(transfer("服务器给的文件比说的大")));
                }
                pending.extend_from_slice(&data);
                // 不是最后一段时必须攒满一整段；最后一段等全部收完。
                while opened + 1 < chunks && pending.len() >= CHUNK_SEALED {
                    let plain = decryptor.open_chunk(&pending[..CHUNK_SEALED], false).map_err(|e| Some(e.into()))?;
                    out.write_all(&plain).map_err(|_| Some(transfer("写不进下载的文件")))?;
                    pending.drain(..CHUNK_SEALED);
                    opened += 1;
                }
            }
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) if received == total => break,
            Ok(()) => tracing::info!(received, total, "下载提前结束，续下"),
            Err(Some(error)) => return Err(error),
            Err(None) => {}
        }
        failures += 1;
        if failures > RETRIES {
            return Err(transfer("下载多次失败"));
        }
        tokio::time::sleep(Duration::from_millis(500 * u64::from(failures))).await;
    }
    let plain = decryptor.open_chunk(&pending, true)?;
    out.write_all(&plain).map_err(|_| transfer("写不进下载的文件"))?;
    out.flush().map_err(|_| transfer("写不进下载的文件"))?;
    if !decryptor.finished() || opened + 1 != chunks {
        return Err(ClientError::Core(friend_im_core::CoreError::Decrypt));
    }
    tracing::info!(file = %file.id, size = file.size, "文件已下载");
    Ok(())
}
