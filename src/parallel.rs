//! Parallel download with non-blocking pipeline.
//!
//! Architecture:
//! - Downloaders (parallel): fetch chunks, don't block on processing
//! - Processor (single): decrypt, write, update MAC
//! - Uses ParallelMacProcessor for out-of-order MAC computation

use std::fs::File as StdFile;
use std::io;
use std::io::SeekFrom;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use aes::Aes128;
use async_trait::async_trait;
use bytes::BytesMut;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use futures::io::Cursor;
use futures::TryStreamExt;
use tokio::io::{AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::fingerprint::{
    compute_condensed_mac, compute_mega_chunk_mac, mega_chunk_boundaries, MegaChunk, MegaChunkMac,
    ParallelMacProcessor,
};
use crate::http::HttpClient;
use crate::Node;

/// Maximum number of workers we will spawn to keep RAM bounded.
const MAX_PARALLEL_WORKERS: usize = 16;

#[async_trait]
pub trait ParallelDownloadWriter: AsyncWrite + AsyncSeek + Unpin + Send {
    async fn sync_data(&mut self) -> std::io::Result<()>;

    async fn write_chunk(&mut self, offset: u64, data: Vec<u8>) -> std::io::Result<Vec<u8>> {
        self.seek(SeekFrom::Start(offset)).await?;
        self.write_all(&data).await?;
        Ok(data)
    }
}

#[cfg(feature = "reqwest")]
#[async_trait]
impl ParallelDownloadWriter for tokio::fs::File {
    async fn sync_data(&mut self) -> std::io::Result<()> {
        tokio::fs::File::sync_data(self).await
    }

    async fn write_chunk(&mut self, offset: u64, data: Vec<u8>) -> std::io::Result<Vec<u8>> {
        let std_file = self.try_clone().await?.into_std().await;
        tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
            write_all_at_blocking(&std_file, offset, &data)?;
            Ok(data)
        })
        .await
        .map_err(|e| std::io::Error::other(format!("positioned write task failed: {e}")))?
    }
}

struct NoSyncWriter<W>(W);

impl<W> NoSyncWriter<W> {
    fn new(writer: W) -> Self {
        Self(writer)
    }
}

impl<W> AsyncWrite for NoSyncWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl<W> AsyncSeek for NoSyncWriter<W>
where
    W: AsyncSeek + Unpin,
{
    fn start_seek(self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.get_mut().0).start_seek(pos)
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.get_mut().0).poll_complete(cx)
    }
}

#[async_trait]
impl<W> ParallelDownloadWriter for NoSyncWriter<W>
where
    W: AsyncWrite + AsyncSeek + Unpin + Send,
{
    async fn sync_data(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ============================================================================
// Message type
// ============================================================================

/// Downloaded chunk (encrypted, mutable for in-place decryption).
struct DownloadedChunk {
    index: u32,
    offset: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct ChunkBufferPool {
    buffers: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl ChunkBufferPool {
    fn acquire(&self) -> Vec<u8> {
        match self.buffers.lock() {
            Ok(mut guard) => guard.pop().unwrap_or_default(),
            Err(poisoned) => poisoned.into_inner().pop().unwrap_or_default(),
        }
    }

    fn release(&self, buffer: Vec<u8>) {
        match self.buffers.lock() {
            Ok(mut guard) => guard.push(buffer),
            Err(poisoned) => poisoned.into_inner().push(buffer),
        }
    }
}

// ============================================================================
// Chunk calculation
// ============================================================================

impl MegaChunk {
    fn end(&self) -> u64 {
        self.offset + self.length
    }

    fn url(&self, base_url: &str) -> String {
        format!(
            "{base_url}/{}-{}",
            self.offset,
            self.end().saturating_sub(1)
        )
    }
}

// ============================================================================
// Decryption
// ============================================================================

fn decrypt(key: &[u8; 16], iv: &[u8; 16], offset: u64, data: &mut [u8]) {
    let mut cipher = ctr::Ctr128BE::<Aes128>::new(key.into(), iv.into());
    cipher.seek(offset);
    cipher.apply_keystream(data);
}

#[cfg(unix)]
fn write_all_at_blocking(file: &StdFile, mut offset: u64, mut data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::FileExt;

    while !data.is_empty() {
        let written = file.write_at(data, offset)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write download chunk",
            ));
        }
        offset = offset.saturating_add(written as u64);
        data = &data[written..];
    }

    Ok(())
}

#[cfg(windows)]
fn write_all_at_blocking(file: &StdFile, mut offset: u64, mut data: &[u8]) -> io::Result<()> {
    use std::os::windows::fs::FileExt;

    while !data.is_empty() {
        let written = file.seek_write(data, offset)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write download chunk",
            ));
        }
        offset = offset.saturating_add(written as u64);
        data = &data[written..];
    }

    Ok(())
}

// ============================================================================
// Download worker
// ============================================================================

struct DownloadContext {
    base_url: String,
    next_chunk: Arc<AtomicU64>,
    chunks: Arc<[MegaChunk]>,
    trusted_chunks: Arc<[Option<[u8; 16]>]>,
    buffer_pool: Arc<ChunkBufferPool>,
    tx: mpsc::Sender<DownloadedChunk>,
}

async fn download_worker(client: &dyn HttpClient, ctx: DownloadContext) -> Result<()> {
    loop {
        let idx = ctx.next_chunk.fetch_add(1, Ordering::Relaxed);
        let Some(range) = ctx.chunks.get(idx as usize).copied() else {
            break;
        };
        if ctx
            .trusted_chunks
            .get(idx as usize)
            .is_some_and(Option::is_some)
        {
            continue;
        }

        let target_size = range.length as usize;
        let mut buffer = ctx.buffer_pool.acquire();
        if buffer.capacity() < target_size {
            buffer.reserve(target_size - buffer.capacity());
        }
        if buffer.len() < target_size {
            buffer.resize(target_size, 0);
        } else {
            buffer.truncate(target_size);
        }

        let url = range.url(&ctx.base_url).parse()?;
        let mut response = client.get(url).await?;
        let mut bytes_read = 0;

        while let Some(chunk) = response.try_next().await? {
            let chunk = chunk.as_ref();
            let end = bytes_read + chunk.len();
            if end > target_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "HTTP chunk exceeded expected MEGA range: expected {} bytes, got at least {} bytes",
                        range.length, end
                    ),
                )
                .into());
            }
            buffer[bytes_read..end].copy_from_slice(chunk);
            bytes_read = end;
            if bytes_read == target_size {
                break;
            }
        }

        if bytes_read < target_size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "unexpected EOF while reading HTTP chunk: expected {} bytes, got {} bytes",
                    range.length, bytes_read
                ),
            )
            .into());
        }

        let chunk = DownloadedChunk {
            index: range.index,
            offset: range.offset,
            data: buffer,
        };

        if ctx.tx.send(chunk).await.is_err() {
            break;
        }
    }
    Ok(())
}

// ============================================================================
// Processor
// ============================================================================

async fn process_chunks<W>(
    mut rx: mpsc::Receiver<DownloadedChunk>,
    mut writer: W,
    mac: Arc<ParallelMacProcessor>,
    aes_key: [u8; 16],
    aes_iv: [u8; 16],
    aes_iv_8: [u8; 8],
    buffer_pool: Arc<ChunkBufferPool>,
    chunk_verified: Option<Arc<dyn Fn(u32, [u8; 16]) + Send + Sync>>,
    progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    progress_total: Option<Arc<AtomicU64>>,
    progress_reported: Option<Arc<AtomicU64>>,
) -> Result<()>
where
    W: ParallelDownloadWriter,
{
    while let Some(chunk) = rx.recv().await {
        let offset = chunk.offset;

        // Decrypt + MAC in single blocking task (data stays hot in cache)
        let decrypted = tokio::task::spawn_blocking({
            let mut data = chunk.data;
            move || -> Result<([u8; 16], Vec<u8>)> {
                decrypt(&aes_key, &aes_iv, offset, &mut data);
                let chunk_mac = compute_mega_chunk_mac(&data, &aes_key, &aes_iv_8);
                Ok((chunk_mac, data))
            }
        })
        .await
        .map_err(|e| {
            Error::from(std::io::Error::other(format!(
                "spawn_blocking task failed: {e}"
            )))
        })??;

        let chunk_index = chunk.index;
        let chunk_mac = decrypted.0;
        let mut data = decrypted.1;
        mac.set_chunk_mac(chunk_index as usize, chunk_mac);

        // File-backed writers can bypass Tokio's buffered async file adapter here.
        data = writer.write_chunk(offset, data).await?;
        writer.flush().await?;
        if let Some(ref cb) = chunk_verified {
            cb(chunk_index, chunk_mac);
        }
        if let Some(ref total) = progress_total {
            let new_total =
                total.fetch_add(data.len() as u64, Ordering::Relaxed) + data.len() as u64;
            if let Some(ref reported) = progress_reported {
                let prev = reported.fetch_max(new_total, Ordering::Relaxed);
                if new_total > prev {
                    if let Some(ref cb) = progress {
                        cb(new_total);
                    }
                }
            }
        }
        buffer_pool.release(std::mem::take(&mut data));
    }

    writer.flush().await?;

    Ok(())
}

struct StreamingFileDownloadContext {
    base_url: String,
    next_chunk: Arc<AtomicU64>,
    chunks: Arc<[MegaChunk]>,
    trusted_chunks: Arc<[Option<[u8; 16]>]>,
    std_file: Arc<StdFile>,
    progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    progress_total: Option<Arc<AtomicU64>>,
    progress_reported: Option<Arc<AtomicU64>>,
    mac: Arc<ParallelMacProcessor>,
    aes_key: [u8; 16],
    aes_iv: [u8; 16],
    aes_iv_8: [u8; 8],
    chunk_verified: Option<Arc<dyn Fn(u32, [u8; 16]) + Send + Sync>>,
}

async fn stream_download_worker_to_file(
    client: &dyn HttpClient,
    ctx: StreamingFileDownloadContext,
) -> Result<()> {
    loop {
        let idx = ctx.next_chunk.fetch_add(1, Ordering::Relaxed);
        let Some(range) = ctx.chunks.get(idx as usize).copied() else {
            break;
        };
        if ctx
            .trusted_chunks
            .get(idx as usize)
            .is_some_and(Option::is_some)
        {
            continue;
        }

        let url = range.url(&ctx.base_url).parse()?;
        let mut response = client.get(url).await?;
        let mut remaining = range.length as usize;
        let mut file_offset = range.offset;
        let mut chunk_mac = MegaChunkMac::new(&ctx.aes_key, &ctx.aes_iv_8);

        while let Some(bytes) = response.try_next().await? {
            let read_len = bytes.len();
            if read_len > remaining {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "HTTP chunk exceeded expected MEGA range: expected {} bytes remaining, got {} bytes",
                        remaining, read_len
                    ),
                )
                .into());
            }

            let mut chunk = match bytes.try_into_mut() {
                Ok(bytes) => bytes,
                Err(bytes) => {
                    let mut buf = BytesMut::with_capacity(bytes.len());
                    buf.extend_from_slice(&bytes);
                    buf
                }
            };
            decrypt(&ctx.aes_key, &ctx.aes_iv, file_offset, &mut chunk);
            chunk_mac.update(&chunk);

            tokio::task::block_in_place(|| {
                write_all_at_blocking(&ctx.std_file, file_offset, &chunk)
            })?;

            file_offset += read_len as u64;
            remaining -= read_len;

            if remaining == 0 {
                break;
            }
        }

        if remaining != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!(
                    "unexpected EOF while reading HTTP chunk: expected {} trailing bytes",
                    remaining
                ),
            )
            .into());
        }

        let chunk_index = range.index;
        let chunk_mac = chunk_mac.finalize();
        ctx.mac.set_chunk_mac(chunk_index as usize, chunk_mac);

        if let Some(ref cb) = ctx.chunk_verified {
            cb(chunk_index, chunk_mac);
        }
        if let Some(ref total) = ctx.progress_total {
            let new_total = total.fetch_add(range.length, Ordering::Relaxed) + range.length;
            if let Some(ref reported) = ctx.progress_reported {
                let prev = reported.fetch_max(new_total, Ordering::Relaxed);
                if new_total > prev {
                    if let Some(ref cb) = ctx.progress {
                        cb(new_total);
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Main entry point
// ============================================================================

/// Downloads a file using parallel connections.
///
/// Downloads run in parallel and don't block on processing.
pub(crate) async fn download_parallel<W>(
    client: &dyn HttpClient,
    node: &Node,
    base_url: String,
    server_size: u64,
    writer: W,
    num_connections: usize,
    progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    aes_iv: [u8; 8],
    expected_mac: [u8; 8],
) -> Result<()>
where
    W: AsyncWrite + AsyncSeek + Unpin + Send + 'static,
{
    download_parallel_resumable(
        client,
        node,
        base_url,
        server_size,
        NoSyncWriter::new(writer),
        num_connections,
        progress_callback,
        None,
        None,
        aes_iv,
        expected_mac,
    )
    .await
}

/// Downloads a file using parallel connections, skipping preverified plaintext chunks.
pub(crate) async fn download_parallel_resumable<W>(
    client: &dyn HttpClient,
    node: &Node,
    base_url: String,
    server_size: u64,
    writer: W,
    num_connections: usize,
    progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    trusted_chunks: Option<Arc<[Option<[u8; 16]>]>>,
    chunk_verified: Option<Arc<dyn Fn(u32, [u8; 16]) + Send + Sync>>,
    aes_iv: [u8; 8],
    expected_mac: [u8; 8],
) -> Result<()>
where
    W: ParallelDownloadWriter + 'static,
{
    if !node.kind.is_file() {
        return Err(Error::NotAFileNode);
    }

    let file_size = server_size;
    let aes_key = node.aes_key;
    let aes_iv_8 = aes_iv;

    if file_size == 0 {
        if let Some(cb) = progress_callback {
            cb(0);
        }

        let empty_mac =
            compute_condensed_mac(Cursor::new(Vec::new()), 0, &aes_key, &aes_iv_8).await?;

        return if empty_mac == expected_mac {
            Ok(())
        } else {
            Err(Error::CondensedMacMismatch)
        };
    }

    // CTR IV: [aes_iv, zeros] - NOT repeated!
    let mut aes_iv_16 = [0u8; 16];
    aes_iv_16[..8].copy_from_slice(&aes_iv_8);

    let chunks = Arc::<[MegaChunk]>::from(mega_chunk_boundaries(file_size));
    let num_chunks = chunks.len() as u64;
    let trusted_chunks = trusted_chunks.unwrap_or_else(|| {
        std::iter::repeat_with(|| None)
            .take(num_chunks as usize)
            .collect::<Vec<_>>()
            .into()
    });
    let trusted_bytes = chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| {
            trusted_chunks
                .get(index)
                .and_then(Option::as_ref)
                .map(|_| chunk.length)
        })
        .sum::<u64>();
    let requested_workers = num_connections.max(1);
    if requested_workers > MAX_PARALLEL_WORKERS {
        return Err(Error::ParallelismTooHigh);
    }
    let untrusted_chunks = num_chunks as usize
        - trusted_chunks
            .iter()
            .take(num_chunks as usize)
            .filter(|entry| entry.is_some())
            .count();

    // MAC processor (handles out-of-order chunks)
    let mac = Arc::new(ParallelMacProcessor::new(file_size, &aes_key, &aes_iv_8));
    for (index, entry) in trusted_chunks.iter().take(num_chunks as usize).enumerate() {
        if let Some(chunk_mac) = entry {
            mac.set_chunk_mac(index, *chunk_mac);
        }
    }

    let progress: Option<Arc<dyn Fn(u64) + Send + Sync>> = progress_callback;
    if trusted_bytes > 0 {
        if let Some(ref cb) = progress {
            cb(trusted_bytes);
        }
    }
    if untrusted_chunks == 0 {
        let computed_mac = mac.finalize().ok_or(Error::CondensedMacMismatch)?;
        return if computed_mac == expected_mac {
            Ok(())
        } else {
            Err(Error::CondensedMacMismatch)
        };
    }

    // Cap workers so we never exceed the number of chunks or the configured maximum
    let num_workers = requested_workers.min(untrusted_chunks);
    let next_chunk = Arc::new(AtomicU64::new(0));

    // Channel: downloaders → processor
    // Bounded to num_workers so each worker can have at most one queued chunk while
    // downloading the next. Peak memory: ~num_workers * CHUNK_SIZE queued + num_workers
    // in-flight downloads, i.e. ~2 * num_workers * CHUNK_SIZE total.
    let (tx, rx) = mpsc::channel::<DownloadedChunk>(num_workers);

    // Progress callback with cumulative tracking and monotonic reporting
    let progress_total = progress
        .as_ref()
        .map(|_| Arc::new(AtomicU64::new(trusted_bytes)));
    let progress_reported = progress
        .as_ref()
        .map(|_| Arc::new(AtomicU64::new(trusted_bytes)));
    let buffer_pool = Arc::new(ChunkBufferPool::default());

    // Processor task: decrypt, write, MAC
    let processor_mac = Arc::clone(&mac);
    let processor_pool = Arc::clone(&buffer_pool);
    let processor_handle = tokio::spawn(async move {
        process_chunks(
            rx,
            writer,
            processor_mac,
            aes_key,
            aes_iv_16,
            aes_iv_8,
            processor_pool,
            chunk_verified,
            progress.clone(),
            progress_total.clone(),
            progress_reported.clone(),
        )
        .await
    });

    // Download workers
    let download_workers: Vec<_> = (0..num_workers)
        .map(|_| {
            let ctx = DownloadContext {
                base_url: base_url.clone(),
                next_chunk: Arc::clone(&next_chunk),
                chunks: Arc::clone(&chunks),
                trusted_chunks: Arc::clone(&trusted_chunks),
                buffer_pool: Arc::clone(&buffer_pool),
                tx: tx.clone(),
            };
            download_worker(client, ctx)
        })
        .collect();

    drop(tx); // Close channel when all workers done

    // Run downloaders; try_join_all returns on first error and stops polling remaining futures
    let download_error = futures::future::try_join_all(download_workers).await.err();

    // If any downloader failed, abort the processor immediately
    if download_error.is_some() {
        processor_handle.abort();
    }

    // Wait for processor to finish
    let processor_result: Result<_> = processor_handle
        .await
        .map_err(|e| Error::from(std::io::Error::other(format!("processor task failed: {e}"))));

    // Propagate downloader error if any, otherwise propagate processor error
    if let Some(err) = download_error {
        return Err(err);
    }

    processor_result??;

    // Finalize MAC
    let computed_mac = mac.finalize().ok_or(Error::CondensedMacMismatch)?;

    if computed_mac == expected_mac {
        Ok(())
    } else {
        Err(Error::CondensedMacMismatch)
    }
}

pub(crate) async fn download_parallel_resumable_to_file(
    client: &dyn HttpClient,
    node: &Node,
    base_url: String,
    server_size: u64,
    writer: tokio::fs::File,
    num_connections: usize,
    progress_callback: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    trusted_chunks: Option<Arc<[Option<[u8; 16]>]>>,
    chunk_verified: Option<Arc<dyn Fn(u32, [u8; 16]) + Send + Sync>>,
    aes_iv: [u8; 8],
    expected_mac: [u8; 8],
) -> Result<()> {
    if !node.kind.is_file() {
        return Err(Error::NotAFileNode);
    }

    let file_size = server_size;
    let aes_key = node.aes_key;
    let aes_iv_8 = aes_iv;

    if file_size == 0 {
        if let Some(cb) = progress_callback {
            cb(0);
        }

        let empty_mac =
            compute_condensed_mac(Cursor::new(Vec::new()), 0, &aes_key, &aes_iv_8).await?;

        return if empty_mac == expected_mac {
            Ok(())
        } else {
            Err(Error::CondensedMacMismatch)
        };
    }

    let mut aes_iv_16 = [0u8; 16];
    aes_iv_16[..8].copy_from_slice(&aes_iv_8);

    let chunks = Arc::<[MegaChunk]>::from(mega_chunk_boundaries(file_size));
    let num_chunks = chunks.len() as u64;
    let trusted_chunks = trusted_chunks.unwrap_or_else(|| {
        std::iter::repeat_with(|| None)
            .take(num_chunks as usize)
            .collect::<Vec<_>>()
            .into()
    });
    let trusted_bytes = chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| {
            trusted_chunks
                .get(index)
                .and_then(Option::as_ref)
                .map(|_| chunk.length)
        })
        .sum::<u64>();
    let requested_workers = num_connections.max(1);
    if requested_workers > MAX_PARALLEL_WORKERS {
        return Err(Error::ParallelismTooHigh);
    }
    let untrusted_chunks = num_chunks as usize
        - trusted_chunks
            .iter()
            .take(num_chunks as usize)
            .filter(|entry| entry.is_some())
            .count();

    let mac = Arc::new(ParallelMacProcessor::new(file_size, &aes_key, &aes_iv_8));
    for (index, entry) in trusted_chunks.iter().take(num_chunks as usize).enumerate() {
        if let Some(chunk_mac) = entry {
            mac.set_chunk_mac(index, *chunk_mac);
        }
    }

    let progress: Option<Arc<dyn Fn(u64) + Send + Sync>> = progress_callback;
    if trusted_bytes > 0 {
        if let Some(ref cb) = progress {
            cb(trusted_bytes);
        }
    }
    if untrusted_chunks == 0 {
        let computed_mac = mac.finalize().ok_or(Error::CondensedMacMismatch)?;
        return if computed_mac == expected_mac {
            Ok(())
        } else {
            Err(Error::CondensedMacMismatch)
        };
    }

    let num_workers = requested_workers.min(untrusted_chunks);
    let next_chunk = Arc::new(AtomicU64::new(0));
    let progress_total = progress
        .as_ref()
        .map(|_| Arc::new(AtomicU64::new(trusted_bytes)));
    let progress_reported = progress
        .as_ref()
        .map(|_| Arc::new(AtomicU64::new(trusted_bytes)));
    let std_file = Arc::new(writer.into_std().await);

    let mut workers = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let ctx = StreamingFileDownloadContext {
            base_url: base_url.clone(),
            next_chunk: Arc::clone(&next_chunk),
            chunks: Arc::clone(&chunks),
            trusted_chunks: Arc::clone(&trusted_chunks),
            std_file: Arc::clone(&std_file),
            progress: progress.clone(),
            progress_total: progress_total.clone(),
            progress_reported: progress_reported.clone(),
            mac: Arc::clone(&mac),
            aes_key,
            aes_iv: aes_iv_16,
            aes_iv_8,
            chunk_verified: chunk_verified.clone(),
        };
        workers.push(stream_download_worker_to_file(client, ctx));
    }

    let result = futures::future::try_join_all(workers).await;
    result?;

    let computed_mac = mac.finalize().ok_or(Error::CondensedMacMismatch)?;
    if computed_mac == expected_mac {
        Ok(())
    } else {
        Err(Error::CondensedMacMismatch)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use bytes::Bytes;
    use futures::io::AsyncRead;
    use futures::stream;
    use futures::stream::StreamExt;
    use tokio::time::{timeout, Duration};
    use url::Url;

    use crate::http::{ClientState, HttpClient, HttpGetStream};
    use crate::protocol::commands::{Request, Response};

    #[test]
    fn chunk_range_basic() {
        let chunks = mega_chunk_boundaries(500);
        let r = chunks[0];
        assert_eq!(r.offset, 0);
        assert_eq!(r.length, 500);
    }

    #[test]
    fn chunk_range_large_file() {
        let chunks = mega_chunk_boundaries(1280 * 1024);
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].length, 128 * 1024);
        assert_eq!(chunks[1].length, 256 * 1024);
        assert_eq!(chunks[2].length, 384 * 1024);
        assert_eq!(chunks[3].length, 512 * 1024);
    }

    #[test]
    fn chunk_range_past_end() {
        assert!(mega_chunk_boundaries(500).get(10).is_none());
    }

    #[test]
    fn chunk_count_cases() {
        assert_eq!(mega_chunk_boundaries(0).len(), 0);
        assert_eq!(mega_chunk_boundaries(1).len(), 1);
        assert_eq!(mega_chunk_boundaries(128 * 1024).len(), 1);
        assert_eq!(mega_chunk_boundaries(128 * 1024 + 1).len(), 2);
    }

    #[test]
    fn decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x13u8; 16];
        let original = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut data = original;

        decrypt(&key, &iv, 0, &mut data);
        decrypt(&key, &iv, 0, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn decrypt_continuous() {
        let key = [0x42u8; 16];
        let iv = [0x13u8; 16];

        let mut part1 = vec![0u8; 32];
        let mut part2 = vec![0u8; 32];
        decrypt(&key, &iv, 0, &mut part1);
        decrypt(&key, &iv, 32, &mut part2);

        let mut whole = vec![0u8; 64];
        decrypt(&key, &iv, 0, &mut whole);

        assert_eq!(&whole[..32], &part1[..]);
        assert_eq!(&whole[32..], &part2[..]);
    }

    #[derive(Clone, Default)]
    struct SharedWriter {
        inner: Arc<Mutex<SharedWriterInner>>,
    }

    #[derive(Default)]
    struct SharedWriterInner {
        data: Vec<u8>,
        pos: u64,
        fail_sync: bool,
        sync_calls: usize,
        journal: Vec<&'static str>,
    }

    impl SharedWriter {
        fn with_data(data: Vec<u8>) -> Self {
            Self {
                inner: Arc::new(Mutex::new(SharedWriterInner {
                    data,
                    pos: 0,
                    ..SharedWriterInner::default()
                })),
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.inner.lock().unwrap().data.clone()
        }

        fn set_fail_sync(&self, fail_sync: bool) {
            self.inner.lock().unwrap().fail_sync = fail_sync;
        }

        fn sync_calls(&self) -> usize {
            self.inner.lock().unwrap().sync_calls
        }

        fn journal(&self) -> Vec<&'static str> {
            self.inner.lock().unwrap().journal.clone()
        }
    }

    impl AsyncWrite for SharedWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let mut inner = self.inner.lock().unwrap();
            let pos = usize::try_from(inner.pos).map_err(std::io::Error::other)?;
            let end = pos
                .checked_add(buf.len())
                .ok_or_else(|| std::io::Error::other("write position overflow"))?;
            if inner.data.len() < end {
                inner.data.resize(end, 0);
            }
            inner.data[pos..end].copy_from_slice(buf);
            inner.pos = end as u64;
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.get_mut().inner.lock().unwrap().journal.push("flush");
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncSeek for SharedWriter {
        fn start_seek(self: Pin<&mut Self>, pos: SeekFrom) -> std::io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            let len = inner.data.len() as i128;
            let current = i128::from(inner.pos);
            let next = match pos {
                SeekFrom::Start(pos) => i128::from(pos),
                SeekFrom::End(offset) => len + i128::from(offset),
                SeekFrom::Current(offset) => current + i128::from(offset),
            };
            if next < 0 || next > i128::from(u64::MAX) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid seek",
                ));
            }
            inner.pos = next as u64;
            Ok(())
        }

        fn poll_complete(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<u64>> {
            let inner = self.inner.lock().unwrap();
            Poll::Ready(Ok(inner.pos))
        }
    }

    #[async_trait]
    impl ParallelDownloadWriter for SharedWriter {
        async fn sync_data(&mut self) -> std::io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.journal.push("sync");
            inner.sync_calls += 1;
            if inner.fail_sync {
                return Err(std::io::Error::other("simulated sync failure"));
            }
            Ok(())
        }
    }

    struct MockHttpClient {
        encrypted: Vec<u8>,
        requests: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl MockHttpClient {
        fn new(encrypted: Vec<u8>) -> Self {
            Self {
                encrypted,
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn requests(&self) -> Vec<(u64, u64)> {
            self.requests.lock().unwrap().clone()
        }
    }

    struct HangingTailHttpClient {
        encrypted: Vec<u8>,
    }

    impl HangingTailHttpClient {
        fn new(encrypted: Vec<u8>) -> Self {
            Self { encrypted }
        }
    }

    #[async_trait]
    impl HttpClient for MockHttpClient {
        async fn send_requests(
            &self,
            _state: &ClientState,
            _requests: &[Request],
            _query_params: &[(&str, &str)],
        ) -> Result<Vec<Response>> {
            unreachable!("resumable tests call the lower-level downloader directly")
        }

        async fn get(&self, url: Url) -> Result<HttpGetStream> {
            let range = url
                .path_segments()
                .and_then(Iterator::last)
                .ok_or_else(|| std::io::Error::other("missing range"))?;
            let (start, end) = range
                .split_once('-')
                .ok_or_else(|| std::io::Error::other("bad range"))?;
            let start = start.parse::<u64>().map_err(std::io::Error::other)?;
            let end = end.parse::<u64>().map_err(std::io::Error::other)?;
            self.requests.lock().unwrap().push((start, end));
            let start_usize = usize::try_from(start).map_err(std::io::Error::other)?;
            let end_usize = usize::try_from(end).map_err(std::io::Error::other)?;
            let bytes = self.encrypted[start_usize..=end_usize].to_vec();
            Ok(Box::pin(stream::iter([Ok(Bytes::from(bytes))])))
        }

        async fn post(
            &self,
            _url: Url,
            _body: Pin<Box<dyn AsyncRead + Send + Sync>>,
            _content_length: Option<u64>,
        ) -> Result<Pin<Box<dyn AsyncRead + Send>>> {
            unreachable!("resumable tests do not upload data")
        }
    }

    #[async_trait]
    impl HttpClient for HangingTailHttpClient {
        async fn send_requests(
            &self,
            _state: &ClientState,
            _requests: &[Request],
            _query_params: &[(&str, &str)],
        ) -> Result<Vec<Response>> {
            unreachable!("resumable tests call the lower-level downloader directly")
        }

        async fn get(&self, url: Url) -> Result<HttpGetStream> {
            let range = url
                .path_segments()
                .and_then(Iterator::last)
                .ok_or_else(|| std::io::Error::other("missing range"))?;
            let (start, end) = range
                .split_once('-')
                .ok_or_else(|| std::io::Error::other("bad range"))?;
            let start = start.parse::<u64>().map_err(std::io::Error::other)?;
            let end = end.parse::<u64>().map_err(std::io::Error::other)?;
            let start_usize = usize::try_from(start).map_err(std::io::Error::other)?;
            let end_usize = usize::try_from(end).map_err(std::io::Error::other)?;
            let bytes = self.encrypted[start_usize..=end_usize].to_vec();
            let stream = stream::iter([Ok::<Bytes, std::io::Error>(Bytes::from(bytes))])
                .chain(stream::pending::<std::io::Result<Bytes>>());
            Ok(Box::pin(stream))
        }

        async fn post(
            &self,
            _url: Url,
            _body: Pin<Box<dyn AsyncRead + Send + Sync>>,
            _content_length: Option<u64>,
        ) -> Result<Pin<Box<dyn AsyncRead + Send>>> {
            unreachable!("resumable tests do not upload data")
        }
    }

    fn test_plaintext(size: usize) -> Vec<u8> {
        (0..size)
            .map(|i| u8::try_from((i * 31 + 7) % 251).unwrap())
            .collect()
    }

    fn encrypt_plaintext(plaintext: &[u8], aes_key: &[u8; 16], aes_iv: &[u8; 8]) -> Vec<u8> {
        let mut encrypted = plaintext.to_vec();
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(aes_iv);
        decrypt(aes_key, &iv, 0, &mut encrypted);
        encrypted
    }

    fn test_node(size: u64, aes_key: [u8; 16], aes_iv: [u8; 8], condensed_mac: [u8; 8]) -> Node {
        Node {
            name: "test.bin".to_string(),
            handle: "handle".to_string(),
            owner: "owner".to_string(),
            size,
            kind: crate::NodeKind::File,
            parent: None,
            children: Vec::new(),
            aes_key,
            aes_iv: Some(aes_iv),
            condensed_mac: Some(condensed_mac),
            sparse_checksum: None,
            created_at: None,
            modified_at: None,
            download_id: None,
            thumbnail_handle: None,
            preview_image_handle: None,
        }
    }

    struct ResumableFixture {
        plaintext: Vec<u8>,
        encrypted: Vec<u8>,
        node: Node,
        chunks: Vec<MegaChunk>,
    }

    fn resumable_fixture(size: usize) -> ResumableFixture {
        let aes_key = [0x42; 16];
        let aes_iv = [0x24; 8];
        let plaintext = test_plaintext(size);
        let condensed_mac = crate::fingerprint::compute_condensed_mac_from_buffer(
            &plaintext,
            size as u64,
            &aes_key,
            &aes_iv,
        )
        .unwrap();
        let encrypted = encrypt_plaintext(&plaintext, &aes_key, &aes_iv);
        let node = test_node(size as u64, aes_key, aes_iv, condensed_mac);
        let chunks = mega_chunk_boundaries(size as u64);
        ResumableFixture {
            plaintext,
            encrypted,
            node,
            chunks,
        }
    }

    fn trusted_chunk_macs(
        fixture: &ResumableFixture,
        trusted_indices: &[usize],
    ) -> Vec<Option<[u8; 16]>> {
        let trusted: HashSet<usize> = trusted_indices.iter().copied().collect();
        fixture
            .chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| {
                trusted.contains(&index).then(|| {
                    let start = chunk.offset as usize;
                    let end = (chunk.offset + chunk.length) as usize;
                    compute_mega_chunk_mac(
                        &fixture.plaintext[start..end],
                        &fixture.node.aes_key,
                        fixture.node.aes_iv.as_ref().unwrap(),
                    )
                })
            })
            .collect()
    }

    fn writer_with_trusted_plaintext(
        fixture: &ResumableFixture,
        trusted_chunks: &[Option<[u8; 16]>],
    ) -> SharedWriter {
        let mut data = vec![0; fixture.plaintext.len()];
        for (index, mac) in trusted_chunks.iter().enumerate() {
            if mac.is_some() {
                let chunk = fixture.chunks[index];
                let start = chunk.offset as usize;
                let end = (chunk.offset + chunk.length) as usize;
                data[start..end].copy_from_slice(&fixture.plaintext[start..end]);
            }
        }
        SharedWriter::with_data(data)
    }

    #[tokio::test]
    async fn resumable_skips_trusted_chunks() {
        let fixture = resumable_fixture(800_000);
        let trusted = trusted_chunk_macs(&fixture, &[0, 2]);
        let writer = writer_with_trusted_plaintext(&fixture, &trusted);
        let http = MockHttpClient::new(fixture.encrypted.clone());

        download_parallel_resumable(
            &http,
            &fixture.node,
            "http://example.test/file".to_string(),
            fixture.plaintext.len() as u64,
            writer.clone(),
            4,
            None,
            Some(trusted.into()),
            None,
            *fixture.node.aes_iv.as_ref().unwrap(),
            *fixture.node.condensed_mac.as_ref().unwrap(),
        )
        .await
        .unwrap();

        let requested_starts: HashSet<u64> = http
            .requests()
            .into_iter()
            .map(|(start, _)| start)
            .collect();
        assert!(!requested_starts.contains(&fixture.chunks[0].offset));
        assert!(!requested_starts.contains(&fixture.chunks[2].offset));
        assert_eq!(writer.bytes(), fixture.plaintext);
    }

    #[tokio::test]
    async fn resumable_mixed_chunks_writes_complete_plaintext() {
        let fixture = resumable_fixture(800_000);
        let trusted = trusted_chunk_macs(&fixture, &[1]);
        let writer = writer_with_trusted_plaintext(&fixture, &trusted);
        let http = MockHttpClient::new(fixture.encrypted.clone());

        download_parallel_resumable(
            &http,
            &fixture.node,
            "http://example.test/file".to_string(),
            fixture.plaintext.len() as u64,
            writer.clone(),
            3,
            None,
            Some(trusted.into()),
            None,
            *fixture.node.aes_iv.as_ref().unwrap(),
            *fixture.node.condensed_mac.as_ref().unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(writer.bytes(), fixture.plaintext);
    }

    #[tokio::test]
    async fn resumable_all_chunks_trusted_makes_no_http_requests() {
        let fixture = resumable_fixture(800_000);
        let all_indices: Vec<_> = (0..fixture.chunks.len()).collect();
        let trusted = trusted_chunk_macs(&fixture, &all_indices);
        let writer = writer_with_trusted_plaintext(&fixture, &trusted);
        let http = MockHttpClient::new(fixture.encrypted.clone());

        download_parallel_resumable(
            &http,
            &fixture.node,
            "http://example.test/file".to_string(),
            fixture.plaintext.len() as u64,
            writer,
            4,
            None,
            Some(trusted.into()),
            None,
            *fixture.node.aes_iv.as_ref().unwrap(),
            *fixture.node.condensed_mac.as_ref().unwrap(),
        )
        .await
        .unwrap();

        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn resumable_rejects_bad_trusted_mac() {
        let fixture = resumable_fixture(800_000);
        let all_indices: Vec<_> = (0..fixture.chunks.len()).collect();
        let mut trusted = trusted_chunk_macs(&fixture, &all_indices);
        trusted[0] = Some([0xFF; 16]);
        let writer = writer_with_trusted_plaintext(&fixture, &trusted);
        let http = MockHttpClient::new(fixture.encrypted.clone());

        let err = download_parallel_resumable(
            &http,
            &fixture.node,
            "http://example.test/file".to_string(),
            fixture.plaintext.len() as u64,
            writer,
            4,
            None,
            Some(trusted.into()),
            None,
            *fixture.node.aes_iv.as_ref().unwrap(),
            *fixture.node.condensed_mac.as_ref().unwrap(),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, Error::CondensedMacMismatch));
        assert!(http.requests().is_empty());
    }

    #[tokio::test]
    async fn resumable_progress_includes_trusted_prefix_then_fetched_bytes() {
        let fixture = resumable_fixture(800_000);
        let trusted = trusted_chunk_macs(&fixture, &[0, 1]);
        let trusted_bytes: u64 = fixture.chunks[0].length + fixture.chunks[1].length;
        let writer = writer_with_trusted_plaintext(&fixture, &trusted);
        let http = MockHttpClient::new(fixture.encrypted.clone());
        let progress = Arc::new(Mutex::new(Vec::new()));
        let progress_for_cb = Arc::clone(&progress);

        download_parallel_resumable(
            &http,
            &fixture.node,
            "http://example.test/file".to_string(),
            fixture.plaintext.len() as u64,
            writer,
            1,
            Some(Arc::new(move |bytes| {
                progress_for_cb.lock().unwrap().push(bytes);
            })),
            Some(trusted.into()),
            None,
            *fixture.node.aes_iv.as_ref().unwrap(),
            *fixture.node.condensed_mac.as_ref().unwrap(),
        )
        .await
        .unwrap();

        let progress = progress.lock().unwrap().clone();
        assert_eq!(progress.first().copied(), Some(trusted_bytes));
        assert_eq!(
            progress.last().copied(),
            Some(fixture.plaintext.len() as u64)
        );
        assert!(progress.windows(2).all(|window| window[1] > window[0]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resumable_streaming_file_path_writes_complete_plaintext() {
        let fixture = resumable_fixture(800_000);
        let trusted = trusted_chunk_macs(&fixture, &[1]);
        let http = MockHttpClient::new(fixture.encrypted.clone());
        let path = std::env::temp_dir().join(format!(
            "mega-parallel-test-{}-{}.part",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(fixture.plaintext.len() as u64).await.unwrap();
        let std_file = file.try_clone().await.unwrap().into_std().await;
        for (index, mac) in trusted.iter().enumerate() {
            if mac.is_some() {
                let chunk = fixture.chunks[index];
                let start = chunk.offset as usize;
                let end = (chunk.offset + chunk.length) as usize;
                write_all_at_blocking(&std_file, chunk.offset, &fixture.plaintext[start..end])
                    .unwrap();
            }
        }

        download_parallel_resumable_to_file(
            &http,
            &fixture.node,
            "http://example.test/file".to_string(),
            fixture.plaintext.len() as u64,
            file,
            3,
            None,
            Some(trusted.into()),
            None,
            *fixture.node.aes_iv.as_ref().unwrap(),
            *fixture.node.condensed_mac.as_ref().unwrap(),
        )
        .await
        .unwrap();

        let bytes = tokio::fs::read(&path).await.unwrap();
        let _ = tokio::fs::remove_file(&path).await;
        assert_eq!(bytes, fixture.plaintext);
    }

    #[tokio::test]
    async fn chunk_verified_runs_after_flush_without_sync() {
        let key = [0x42u8; 16];
        let iv = [0x13u8; 16];
        let iv8 = [0x13u8; 8];
        let plaintext = b"persist me".to_vec();
        let mut encrypted = plaintext.clone();
        decrypt(&key, &iv, 0, &mut encrypted);

        let writer = SharedWriter::default();
        let callback_events = Arc::new(Mutex::new(Vec::new()));
        let callback_events_for_cb = Arc::clone(&callback_events);
        let mac = Arc::new(ParallelMacProcessor::new(
            plaintext.len() as u64,
            &key,
            &iv8,
        ));
        let (tx, rx) = mpsc::channel(1);
        tx.send(DownloadedChunk {
            index: 0,
            offset: 0,
            data: encrypted,
        })
        .await
        .unwrap();
        drop(tx);

        process_chunks(
            rx,
            writer.clone(),
            mac,
            key,
            iv,
            iv8,
            Arc::new(ChunkBufferPool::default()),
            Some(Arc::new(move |_index, _mac| {
                callback_events_for_cb.lock().unwrap().push("callback");
            })),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(writer.bytes(), plaintext);
        assert_eq!(writer.sync_calls(), 0);
        let writer_journal = writer.journal();
        assert_eq!(writer_journal.as_slice(), &["flush", "flush"]);
        assert_eq!(callback_events.lock().unwrap().as_slice(), &["callback"]);
    }

    #[tokio::test]
    async fn chunk_verified_is_reported_even_if_sync_would_fail() {
        let key = [0x33u8; 16];
        let iv = [0x19u8; 16];
        let iv8 = [0x19u8; 8];
        let plaintext = b"bad flush".to_vec();
        let mut encrypted = plaintext.clone();
        decrypt(&key, &iv, 0, &mut encrypted);

        let writer = SharedWriter::default();
        writer.set_fail_sync(true);
        let callback_count = Arc::new(Mutex::new(0usize));
        let callback_count_for_cb = Arc::clone(&callback_count);
        let mac = Arc::new(ParallelMacProcessor::new(
            plaintext.len() as u64,
            &key,
            &iv8,
        ));
        let (tx, rx) = mpsc::channel(1);
        tx.send(DownloadedChunk {
            index: 0,
            offset: 0,
            data: encrypted,
        })
        .await
        .unwrap();
        drop(tx);

        process_chunks(
            rx,
            writer.clone(),
            mac,
            key,
            iv,
            iv8,
            Arc::new(ChunkBufferPool::default()),
            Some(Arc::new(move |_index, _mac| {
                *callback_count_for_cb.lock().unwrap() += 1;
            })),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(writer.bytes(), plaintext);
        assert_eq!(*callback_count.lock().unwrap(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resumable_streaming_download_does_not_wait_for_http_eof_after_full_range() {
        let fixture = resumable_fixture(800_000);
        let http = HangingTailHttpClient::new(fixture.encrypted.clone());
        let path = std::env::temp_dir().join(format!(
            "mega-parallel-hanging-tail-{}-{}.part",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)
            .await
            .unwrap();
        file.set_len(fixture.plaintext.len() as u64).await.unwrap();

        timeout(
            Duration::from_secs(2),
            download_parallel_resumable_to_file(
                &http,
                &fixture.node,
                "http://example.test/file".to_string(),
                fixture.plaintext.len() as u64,
                file,
                3,
                None,
                None,
                None,
                *fixture.node.aes_iv.as_ref().unwrap(),
                *fixture.node.condensed_mac.as_ref().unwrap(),
            ),
        )
        .await
        .expect("download should finish without waiting for stream EOF")
        .unwrap();

        let bytes = tokio::fs::read(&path).await.unwrap();
        let _ = tokio::fs::remove_file(&path).await;
        assert_eq!(bytes, fixture.plaintext);
    }
}
