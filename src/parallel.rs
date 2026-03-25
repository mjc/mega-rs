//! Parallel download with non-blocking pipeline.
//!
//! Architecture:
//! - Downloaders (parallel): fetch chunks, don't block on processing
//! - Processor (single): decrypt, write, update MAC
//! - Uses ParallelMacProcessor for out-of-order MAC computation

use std::io::SeekFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aes::Aes128;
use bytes::BytesMut;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use futures::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::fingerprint::ParallelMacProcessor;
use crate::http::HttpClient;
use crate::Node;

/// Download chunk size (32 MB) - larger chunks reduce HTTP overhead.
const CHUNK_SIZE: u64 = 32 * 1024 * 1024;

// ============================================================================
// Message type
// ============================================================================

/// Downloaded chunk (encrypted, mutable for in-place decryption).
struct DownloadedChunk {
    offset: u64,
    data: BytesMut,
}

// ============================================================================
// Chunk calculation
// ============================================================================

#[derive(Debug, Clone, Copy)]
struct ChunkRange {
    offset: u64,
    length: u64,
}

impl ChunkRange {
    fn new(index: u64, file_size: u64) -> Self {
        let offset = index * CHUNK_SIZE;
        let length = CHUNK_SIZE.min(file_size.saturating_sub(offset));
        Self { offset, length }
    }

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

fn chunk_count(file_size: u64) -> u64 {
    file_size.div_ceil(CHUNK_SIZE)
}

// ============================================================================
// Decryption
// ============================================================================

fn decrypt(key: &[u8; 16], iv: &[u8; 16], offset: u64, data: &mut [u8]) {
    let mut cipher = ctr::Ctr128BE::<Aes128>::new(key.into(), iv.into());
    cipher.seek(offset);
    cipher.apply_keystream(data);
}

// ============================================================================
// Download worker
// ============================================================================

struct DownloadContext {
    base_url: String,
    file_size: u64,
    next_chunk: Arc<AtomicU64>,
    num_chunks: u64,
    tx: mpsc::Sender<DownloadedChunk>,
    progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    progress_total: Option<Arc<AtomicU64>>,
    progress_reported: Option<Arc<AtomicU64>>,
}

async fn download_worker(client: &dyn HttpClient, ctx: DownloadContext) -> Result<()> {
    let mut buffer = BytesMut::with_capacity(CHUNK_SIZE as usize);

    loop {
        let idx = ctx.next_chunk.fetch_add(1, Ordering::Relaxed);
        if idx >= ctx.num_chunks {
            break;
        }

        let range = ChunkRange::new(idx, ctx.file_size);
        let target_size = range.length as usize;
        buffer.clear();
        buffer.resize(target_size, 0);

        let url = range.url(&ctx.base_url).parse()?;
        let mut response = client.get(url).await?;
        let mut bytes_read = 0;

        while bytes_read < target_size {
            match response.read(&mut buffer[bytes_read..]).await? {
                0 => {
                    // EOF before reaching expected bytes
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!(
                            "unexpected EOF while reading HTTP chunk: expected {} bytes, got {} bytes",
                            range.length, bytes_read
                        ),
                    )
                    .into());
                }
                n => {
                    bytes_read += n;
                    if let Some(ref total) = ctx.progress_total {
                        let new_total = total.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
                        // Only invoke callback if we advanced the high-water mark,
                        // ensuring monotonic progress reporting across workers.
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
            }
        }

        let chunk = DownloadedChunk {
            offset: range.offset,
            data: buffer.split(),
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
) -> Result<()>
where
    W: futures::io::AsyncWrite + futures::io::AsyncSeek + Unpin,
{
    while let Some(chunk) = rx.recv().await {
        let offset = chunk.offset;

        // Decrypt + MAC in single blocking task (data stays hot in cache)
        let decrypted = tokio::task::spawn_blocking({
            let mut data = chunk.data;
            let mac = Arc::clone(&mac);
            move || {
                decrypt(&aes_key, &aes_iv, offset, &mut data);
                mac.add_chunk(offset, &data);
                data.freeze()
            }
        })
        .await
        .map_err(|e| {
            Error::from(std::io::Error::other(format!(
                "spawn_blocking task failed: {e}"
            )))
        })?;

        // Write to file
        writer.seek(SeekFrom::Start(offset)).await?;
        writer.write_all(&decrypted).await?;
    }

    writer.flush().await?;

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
) -> Result<()>
where
    W: futures::io::AsyncWrite + futures::io::AsyncSeek + Unpin + Send + 'static,
{
    if !node.kind.is_file() {
        return Err(Error::NotAFileNode);
    }

    let file_size = server_size;
    if file_size == 0 {
        if let Some(cb) = progress_callback {
            cb(0);
        }
        return Ok(());
    }

    let aes_key = node.aes_key;
    let aes_iv_8 = node.aes_iv.unwrap_or_default();
    // CTR IV: [aes_iv, zeros] - NOT repeated!
    let mut aes_iv_16 = [0u8; 16];
    aes_iv_16[..8].copy_from_slice(&aes_iv_8);

    let num_chunks = chunk_count(file_size);
    // Cap workers to avoid spawning more than necessary; workers beyond num_chunks will be idle
    let num_workers = num_connections.max(1).min(num_chunks as usize);
    let next_chunk = Arc::new(AtomicU64::new(0));

    // Channel: downloaders → processor
    // Bounded to num_workers so each worker can have at most one queued chunk while
    // downloading the next. Peak memory: ~num_workers * CHUNK_SIZE queued + num_workers
    // in-flight downloads, i.e. ~2 * num_workers * CHUNK_SIZE total.
    let (tx, rx) = mpsc::channel::<DownloadedChunk>(num_workers);

    // MAC processor (handles out-of-order chunks)
    let mac = Arc::new(ParallelMacProcessor::new(file_size, &aes_key, &aes_iv_8));

    // Progress callback with cumulative tracking and monotonic reporting
    let progress: Option<Arc<dyn Fn(u64) + Send + Sync>> = progress_callback;
    let progress_total = progress.as_ref().map(|_| Arc::new(AtomicU64::new(0)));
    let progress_reported = progress.as_ref().map(|_| Arc::new(AtomicU64::new(0)));

    // Processor task: decrypt, write, MAC
    let processor_mac = Arc::clone(&mac);
    let processor_handle =
        tokio::spawn(
            async move { process_chunks(rx, writer, processor_mac, aes_key, aes_iv_16).await },
        );

    // Download workers
    let download_workers: Vec<_> = (0..num_workers)
        .map(|_| {
            let ctx = DownloadContext {
                base_url: base_url.clone(),
                file_size,
                next_chunk: Arc::clone(&next_chunk),
                num_chunks,
                tx: tx.clone(),
                progress: progress.clone(),
                progress_total: progress_total.clone(),
                progress_reported: progress_reported.clone(),
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
    let expected_mac = node.condensed_mac.unwrap_or_default();

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

    #[test]
    fn chunk_range_basic() {
        let r = ChunkRange::new(0, 500);
        assert_eq!(r.offset, 0);
        assert_eq!(r.length, 500);
    }

    #[test]
    fn chunk_range_large_file() {
        let file_size = 100 * 1024 * 1024; // 100 MB
        let num_chunks = chunk_count(file_size);
        assert_eq!(num_chunks, 4); // 32MB + 32MB + 32MB + 4MB
        assert_eq!(ChunkRange::new(0, file_size).length, CHUNK_SIZE);
        assert_eq!(ChunkRange::new(1, file_size).length, CHUNK_SIZE);
        assert_eq!(
            ChunkRange::new(3, file_size).length,
            file_size - 3 * CHUNK_SIZE
        );
    }

    #[test]
    fn chunk_range_past_end() {
        assert_eq!(ChunkRange::new(10, 500).length, 0);
    }

    #[test]
    fn chunk_count_cases() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1), 2);
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
}
