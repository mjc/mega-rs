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
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use futures::io::Cursor;
use futures::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::fingerprint::{
    compute_condensed_mac, compute_mega_chunk_mac, mega_chunk_boundaries, MegaChunk,
    ParallelMacProcessor,
};
use crate::http::HttpClient;
use crate::Node;

/// Maximum number of workers we will spawn to keep RAM bounded.
const MAX_PARALLEL_WORKERS: usize = 16;

// ============================================================================
// Message type
// ============================================================================

/// Downloaded chunk (encrypted, mutable for in-place decryption).
struct DownloadedChunk {
    index: u32,
    offset: u64,
    data: Vec<u8>,
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

// ============================================================================
// Download worker
// ============================================================================

struct DownloadContext {
    base_url: String,
    next_chunk: Arc<AtomicU64>,
    chunks: Arc<[MegaChunk]>,
    trusted_chunks: Arc<[Option<[u8; 16]>]>,
    tx: mpsc::Sender<DownloadedChunk>,
    progress: Option<Arc<dyn Fn(u64) + Send + Sync>>,
    progress_total: Option<Arc<AtomicU64>>,
    progress_reported: Option<Arc<AtomicU64>>,
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
        let mut buffer = vec![0u8; target_size];

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
    chunk_verified: Option<Arc<dyn Fn(u32, [u8; 16]) + Send + Sync>>,
) -> Result<()>
where
    W: futures::io::AsyncWrite + futures::io::AsyncSeek + Unpin,
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
        mac.set_chunk_mac(chunk_index as usize, chunk_mac);

        // Write to file
        writer.seek(SeekFrom::Start(offset)).await?;
        writer.write_all(&decrypted.1).await?;
        if let Some(ref cb) = chunk_verified {
            cb(chunk_index, chunk_mac);
        }
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
    aes_iv: [u8; 8],
    expected_mac: [u8; 8],
) -> Result<()>
where
    W: futures::io::AsyncWrite + futures::io::AsyncSeek + Unpin + Send + 'static,
{
    download_parallel_resumable(
        client,
        node,
        base_url,
        server_size,
        writer,
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
    W: futures::io::AsyncWrite + futures::io::AsyncSeek + Unpin + Send + 'static,
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

    // Processor task: decrypt, write, MAC
    let processor_mac = Arc::clone(&mac);
    let processor_handle = tokio::spawn(async move {
        process_chunks(
            rx,
            writer,
            processor_mac,
            aes_key,
            aes_iv_16,
            aes_iv_8,
            chunk_verified,
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
}
