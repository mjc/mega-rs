#[cfg(feature = "parallel")]
use std::io::{Error as IoError, ErrorKind};
use std::pin::pin;

use aes::Aes128;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use cipher::{BlockEncryptMut, KeyIvInit};
use futures::io::{AsyncRead, AsyncReadExt};

#[cfg(feature = "parallel")]
use crate::Error;
use crate::Result;

/// Represents the node's fingerprint (useful for caching purposes).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NodeFingerprint {
    /// The checksum bytes of the node.
    pub checksum: [u8; 16],
    /// The last modified date of the node.
    pub modified_at: i64,
}

impl NodeFingerprint {
    pub fn new(checksum: [u8; 16], modified_at: i64) -> Self {
        Self {
            checksum,
            modified_at,
        }
    }

    #[allow(unused)]
    pub async fn from_reader<R: AsyncRead>(reader: R, size: u64, modified_at: i64) -> Result<Self> {
        Ok(Self::new(
            compute_sparse_checksum(reader, size).await?,
            modified_at,
        ))
    }

    pub fn deserialize(checksum_str: &str) -> Option<Self> {
        let decoded = BASE64_URL_SAFE_NO_PAD.decode(checksum_str).ok()?;

        let (checksum, mtime) = decoded.split_at(16);
        let checksum = checksum.try_into().ok()?;

        let modified_at = {
            let (byte_count, mtime) = mtime.split_first().map(|(a, b)| (usize::from(*a), b))?;

            if byte_count > 8 || byte_count > mtime.len() {
                // incorrect byte count.
                return None;
            }

            mtime[..byte_count]
                .into_iter()
                .rev()
                .copied()
                .fold(0, |acc, byte| (acc << 8) + i64::from(byte))
        };

        Some(Self::new(checksum, modified_at))
    }

    pub fn serialize(&self) -> String {
        let mut buffer = vec![0u8; 16 + 8];

        buffer[..16].copy_from_slice(&self.checksum);

        let mut value = self.modified_at;
        let mut byte_count: u8 = 0;
        while value > 0 {
            buffer[16 + usize::from(byte_count)] = u8::try_from(value & 0xFF).unwrap();
            value >>= 8;
            byte_count += 1;
        }
        buffer[16] = byte_count;

        let bytes_written = 16 + usize::from(byte_count) + 1;
        BASE64_URL_SAFE_NO_PAD.encode(&buffer[..bytes_written])
    }
}

/// This function computes a sparse CRC32-based checksum, in the exact same way that MEGA does it.
///
/// This allows to compute a checksum for any arbitrary data and compare it to the ones of remote MEGA nodes.
///
/// Please be aware that, due to these checksums being sparse, two identical checksums can be identical to
/// one another despite being generated from very slightly different files.
///
/// Using condensed MACs is more accurate to assess file integrity than the sparse checksum method,
/// but it is both more CPU and disk intensive to do so.
///
/// Here is an example of how to use this function:
/// ```rust,no_run
/// # async fn example() -> mega::Result<()> {
/// # let http_client = reqwest::Client::new();
/// # let mega = mega::Client::builder().build(http_client)?;
/// use tokio_util::compat::TokioAsyncReadCompatExt;
///
/// let nodes = mega.fetch_own_nodes().await?;
///
/// let remote_checksum = {
///     let node = nodes.get_node_by_path("/Root/some-remote-file.txt").unwrap();
///     node.sparse_checksum().unwrap()
/// };
///
/// let local_checksum = {
///     let file = tokio::fs::File::open("some-local-file.txt").await?;
///     let size = file.metadata().await?.len();
///     mega::compute_sparse_checksum(file.compat(), size).await?
/// };
///
/// if local_checksum == *remote_checksum {
///     println!("OK ! (the checksums are identical)");
/// } else {
///     println!("FAILED ! (the checksums differ)");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn compute_sparse_checksum<R: AsyncRead>(reader: R, size: u64) -> Result<[u8; 16]> {
    const MAXFULL: u64 = 8192;

    const CRC_SIZE: u64 = 16;
    const BLOCK_SIZE: u64 = CRC_SIZE * 4;

    match size {
        size if size <= 16 => {
            // tiny file: checksum is simply the file's content verbatim.
            let mut checksum = [0u8; 16];
            pin!(reader).read_exact(&mut checksum).await?;
            Ok(checksum)
        }
        size if size <= MAXFULL => {
            // small file: full coverage, four full CRC32s.
            let size = usize::try_from(size).unwrap();
            let mut buffer = vec![0u8; size];
            pin!(reader).read_exact(&mut buffer).await?;

            let mut checksum = [0u8; 16];
            for i in 0..4 {
                let crc = {
                    let begin = i * size / 4;
                    let end = (i + 1) * size / 4;
                    crc32fast::hash(&buffer[begin..end])
                };

                let begin = i * 4;
                checksum[begin..(begin + 4)].copy_from_slice(&crc.to_be_bytes());
            }

            Ok(checksum)
        }
        size => {
            // large file: sparse coverage, four sparse CRC32s.
            let mut reader = {
                let size = u64::try_from(size).unwrap();
                pin!(reader.take(size))
            };

            let mut block = [0u8; BLOCK_SIZE as usize];
            let blocks = MAXFULL / (BLOCK_SIZE * 4);

            let mut checksum = [0u8; 16];

            let mut cursor = 0;
            for idx in 0..4 {
                let mut hasher = crc32fast::Hasher::new();
                for blk in 0..blocks {
                    let offset = (size - BLOCK_SIZE) * (idx * blocks + blk) / (4 * blocks - 1);
                    let gap = offset - cursor;
                    futures::io::copy((&mut reader).take(gap), &mut futures::io::sink()).await?;
                    (&mut reader).read_exact(&mut block).await?;
                    hasher.update(&block);
                    cursor = offset + BLOCK_SIZE;
                }

                let crc = hasher.finalize();

                let begin = usize::try_from(idx * 4).unwrap();
                checksum[begin..(begin + 4)].copy_from_slice(&crc.to_be_bytes());
            }

            Ok(checksum)
        }
    }
}

/// This function computes a full-coverage condensed MAC, in the exact same way that MEGA does it.
///
/// This allows to compute a condensed MAC for any arbitrary data and compare it to the ones of remote MEGA nodes.
///
/// Using these MACs is more accurate to assess file integrity than the sparse checksum method,
/// but it is both more CPU and disk intensive to do so.
///
/// Here is an example of how to use this function:
/// ```rust,no_run
/// # async fn example() -> mega::Result<()> {
/// # let http_client = reqwest::Client::new();
/// # let mega = mega::Client::builder().build(http_client)?;
/// use tokio_util::compat::TokioAsyncReadCompatExt;
///
/// let nodes = mega.fetch_own_nodes().await?;
///
/// let (remote_condensed_mac, key, iv) = {
///     let node = nodes.get_node_by_path("/Root/some-remote-file.txt").unwrap();
///     let condensed_mac = node.condensed_mac().unwrap();
///     let key = node.aes_key();
///     let iv = node.aes_iv().unwrap();
///     (condensed_mac, key, iv)
/// };
///
/// let local_condensed_mac = {
///     let file = tokio::fs::File::open("some-local-file.txt").await?;
///     let size = file.metadata().await?.len();
///     mega::compute_condensed_mac(file.compat(), size, key, iv).await?
/// };
///
/// if local_condensed_mac == *remote_condensed_mac {
///     println!("OK ! (the MACs are identical)");
/// } else {
///     println!("FAILED ! (the MACs differ)");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn compute_condensed_mac<R: AsyncRead>(
    reader: R,
    size: u64,
    aes_key: &[u8; 16],
    aes_iv: &[u8; 8],
) -> Result<[u8; 8]> {
    let mut chunk_size: u64 = 131_072; // 2^17
    let mut cur_mac = [0u8; 16];

    let mut final_mac_data = [0u8; 16];
    let mut final_mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&final_mac_data).into());

    let mut buffer = {
        let chunk_size = usize::try_from(chunk_size).unwrap();
        Vec::with_capacity(chunk_size)
    };

    let mut reader = pin!(reader.take(size));

    let aes_iv = {
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(aes_iv);
        data[8..].copy_from_slice(aes_iv);
        data
    };

    loop {
        buffer.clear();

        let bytes_read = (&mut reader)
            .take(chunk_size)
            .read_to_end(&mut buffer)
            .await?;

        if bytes_read == 0 {
            break;
        }

        let (chunks, leftover) = buffer.split_at(buffer.len() - buffer.len() % 16);

        let mut mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&aes_iv).into());
        for chunk in chunks.chunks_exact(16) {
            mac.encrypt_block_b2b_mut(chunk.into(), (&mut cur_mac).into());
        }

        if !leftover.is_empty() {
            let mut padded_chunk = [0u8; 16];
            padded_chunk[..leftover.len()].copy_from_slice(leftover);
            mac.encrypt_block_b2b_mut((&padded_chunk).into(), (&mut cur_mac).into());
        }

        final_mac.encrypt_block_b2b_mut((&cur_mac).into(), (&mut final_mac_data).into());

        if chunk_size < 1_048_576 {
            chunk_size += 131_072;
        }
    }

    for i in 0..4 {
        final_mac_data[i] = final_mac_data[i] ^ final_mac_data[i + 4];
        final_mac_data[i + 4] = final_mac_data[i + 8] ^ final_mac_data[i + 12];
    }

    Ok(final_mac_data[..8].try_into().unwrap())
}

/// Pre-computed chunk boundary info for O(1) lookups
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegaChunk {
    pub index: u32,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy)]
struct ChunkInfo {
    start: u64,
    size: u64,
}

fn build_chunk_boundaries(file_size: u64) -> Vec<ChunkInfo> {
    let mut boundaries = Vec::new();
    let mut offset = 0u64;
    let mut size = 131_072u64;
    while offset < file_size {
        let actual_size = size.min(file_size - offset);
        boundaries.push(ChunkInfo {
            start: offset,
            size: actual_size,
        });
        offset += actual_size;
        if size < 1_048_576 {
            size += 131_072;
        }
    }
    boundaries
}

/// Returns the plaintext MAC chunk boundaries MEGA uses for a file size.
#[must_use]
pub fn mega_chunk_boundaries(file_size: u64) -> Vec<MegaChunk> {
    build_chunk_boundaries(file_size)
        .into_iter()
        .enumerate()
        .map(|(index, info)| MegaChunk {
            index: index as u32,
            offset: info.start,
            length: info.size,
        })
        .collect()
}

/// A parallel MAC processor that computes MEGA chunk MACs independently.
///
/// Each MEGA chunk's MAC (`cur_mac`) can be computed independently - only the
/// final combination step is sequential. This processor stores just the 16-byte
/// MAC per MEGA chunk (~160KB for a 5GB file) instead of buffering actual data.
///
/// Uses lock-free atomics (AtomicU64 pairs) for MACs and a Mutex only for partial chunks.
#[cfg(feature = "parallel")]
struct MacEntry {
    lo: std::sync::atomic::AtomicU64,
    hi: std::sync::atomic::AtomicU64,
    computed: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "parallel")]
impl MacEntry {
    fn store(&self, mac: [u8; 16]) {
        let lo = u64::from_le_bytes(mac[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(mac[8..16].try_into().unwrap());
        self.hi.store(hi, std::sync::atomic::Ordering::Relaxed);
        self.lo.store(lo, std::sync::atomic::Ordering::Relaxed);
        // Publish the MAC by setting the computed flag with Release ordering
        self.computed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn load(&self) -> Option<[u8; 16]> {
        // Check the computed flag first with Acquire ordering
        if !self.computed.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let lo = self.lo.load(std::sync::atomic::Ordering::Relaxed);
        let hi = self.hi.load(std::sync::atomic::Ordering::Relaxed);
        let mut mac = [0u8; 16];
        mac[0..8].copy_from_slice(&lo.to_le_bytes());
        mac[8..16].copy_from_slice(&hi.to_le_bytes());
        Some(mac)
    }

    fn is_computed(&self) -> bool {
        self.computed.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[cfg(feature = "parallel")]
pub struct ParallelMacProcessor {
    aes_key: [u8; 16],
    aes_iv_full: [u8; 16],
    file_size: u64,

    // Pre-computed chunk boundaries for O(1)/O(log n) lookups
    chunk_boundaries: Box<[ChunkInfo]>,

    // Computed MACs per MEGA chunk: 16-byte MAC stored as two u64s with computed flag
    chunk_macs: Vec<MacEntry>,

    // Partial chunk state: (data buffer, bytes received)
    chunk_state: std::sync::Mutex<Vec<Option<ChunkState>>>,
}

#[cfg(feature = "parallel")]
struct ChunkState {
    data: Vec<u8>,
    bytes_received: usize,
    coverage: Vec<u8>,
}

#[cfg(feature = "parallel")]
fn parallel_chunk_range_error(start: u64, end: u64, file_size: u64) -> Error {
    Error::Other {
        source: Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!("parallel chunk range [{start}, {end}) is invalid for file size {file_size}"),
        )),
    }
}

#[cfg(feature = "parallel")]
fn parallel_chunk_data_error(start: usize, end: usize, chunk_size: usize) -> Error {
    Error::Other {
        source: Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!("parallel chunk data range [{start}, {end}) exceeds chunk size {chunk_size}"),
        )),
    }
}

#[cfg(feature = "parallel")]
impl ParallelMacProcessor {
    pub fn new(file_size: u64, aes_key: &[u8; 16], aes_iv: &[u8; 8]) -> Self {
        let aes_iv_full = {
            let mut iv = [0u8; 16];
            iv[..8].copy_from_slice(aes_iv);
            iv[8..].copy_from_slice(aes_iv);
            iv
        };

        // Pre-compute all chunk boundaries.
        let chunk_boundaries = build_chunk_boundaries(file_size).into_boxed_slice();

        let num_chunks = chunk_boundaries.len();
        Self {
            aes_key: *aes_key,
            aes_iv_full,
            file_size,
            chunk_boundaries,
            chunk_macs: (0..num_chunks)
                .map(|_| MacEntry {
                    lo: std::sync::atomic::AtomicU64::new(0),
                    hi: std::sync::atomic::AtomicU64::new(0),
                    computed: std::sync::atomic::AtomicBool::new(false),
                })
                .collect(),
            chunk_state: std::sync::Mutex::new((0..num_chunks).map(|_| None).collect()),
        }
    }

    /// Returns (mega_chunk_index, offset_within_chunk) for a file offset
    /// Uses binary search for O(log n) lookup
    fn mega_chunk_for_offset(&self, offset: u64) -> Option<(usize, u64)> {
        // Out-of-bounds offsets are not valid and should not be processed
        if offset >= self.file_size {
            return None;
        }

        let idx = self
            .chunk_boundaries
            .binary_search_by(|info| {
                if offset < info.start {
                    std::cmp::Ordering::Greater
                } else if offset >= info.start + info.size {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()?;

        let chunk_start = self.chunk_boundaries[idx].start;
        Some((idx, offset - chunk_start))
    }

    fn lock_chunk_state(&self) -> std::sync::MutexGuard<'_, Vec<Option<ChunkState>>> {
        match self.chunk_state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Seeds a preverified MEGA chunk MAC for resumable downloads.
    ///
    /// Returns false if `index` is outside the file's MEGA chunk list.
    pub fn set_chunk_mac(&self, index: usize, mac: [u8; 16]) -> bool {
        let Some(entry) = self.chunk_macs.get(index) else {
            return false;
        };
        entry.store(mac);
        true
    }

    /// Returns a computed MEGA chunk MAC, if available.
    #[must_use]
    pub fn chunk_mac(&self, index: usize) -> Option<[u8; 16]> {
        self.chunk_macs.get(index).and_then(MacEntry::load)
    }
}

/// Standalone MAC computation for use with spawn_blocking
#[cfg(feature = "parallel")]
fn compute_chunk_mac_inner(aes_key: &[u8; 16], aes_iv: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut cur_mac = [0u8; 16];
    let (blocks, leftover) = data.split_at(data.len() - data.len() % 16);

    let mut mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), aes_iv.into());
    for block in blocks.chunks_exact(16) {
        mac.encrypt_block_b2b_mut(block.into(), (&mut cur_mac).into());
    }

    if !leftover.is_empty() {
        let mut padded = [0u8; 16];
        padded[..leftover.len()].copy_from_slice(leftover);
        mac.encrypt_block_b2b_mut((&padded).into(), (&mut cur_mac).into());
    }

    cur_mac
}

/// Computes a single MEGA plaintext chunk MAC.
#[cfg(feature = "parallel")]
#[must_use]
pub fn compute_mega_chunk_mac(data: &[u8], aes_key: &[u8; 16], aes_iv: &[u8; 8]) -> [u8; 16] {
    let aes_iv_full = {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(aes_iv);
        iv[8..].copy_from_slice(aes_iv);
        iv
    };
    compute_chunk_mac_inner(aes_key, &aes_iv_full, data)
}

#[cfg(feature = "parallel")]
impl ParallelMacProcessor {
    /// Add data at the given file offset. Can be called from multiple threads.
    ///
    /// Processes data linearly through MEGA chunks:
    /// - One initial binary search to find the starting chunk
    /// - Then linear iteration through successive chunks (no per-iteration searches)
    /// - Complete chunks compute MACs directly; partial chunks are buffered
    pub fn add_chunk(&self, offset: u64, data: &[u8]) -> Result<()> {
        let data_len = data.len();
        let end_offset = offset.checked_add(data_len as u64).ok_or_else(|| {
            parallel_chunk_range_error(
                offset,
                offset.saturating_add(data_len as u64),
                self.file_size,
            )
        })?;

        if end_offset > self.file_size {
            return Err(parallel_chunk_range_error(
                offset,
                end_offset,
                self.file_size,
            ));
        }

        let (mut chunk_idx, _) = self
            .mega_chunk_for_offset(offset)
            .ok_or_else(|| parallel_chunk_range_error(offset, end_offset, self.file_size))?;

        let mut pos = offset;
        let mut remaining = data;

        while !remaining.is_empty() && chunk_idx < self.chunk_boundaries.len() {
            let info = self.chunk_boundaries[chunk_idx];
            let chunk_end = info.start + info.size;
            let offset_in_chunk = (pos - info.start) as usize;
            let bytes_until_end = (chunk_end - pos) as usize;
            let to_take = remaining.len().min(bytes_until_end);
            let (for_this_chunk, rest) = remaining.split_at(to_take);

            // Fast path: complete, aligned chunk - compute MAC directly
            if offset_in_chunk == 0 && to_take == info.size as usize {
                if !self.chunk_macs[chunk_idx].is_computed() {
                    let mac =
                        compute_chunk_mac_inner(&self.aes_key, &self.aes_iv_full, for_this_chunk);
                    self.chunk_macs[chunk_idx].store(mac);
                }
            } else {
                // Slow path: partial chunk at boundary - use buffering
                if let Some(data) = self.buffer_partial_chunk(
                    chunk_idx,
                    offset_in_chunk,
                    for_this_chunk,
                    info.size as usize,
                )? {
                    let mac = compute_chunk_mac_inner(&self.aes_key, &self.aes_iv_full, &data);
                    self.chunk_macs[chunk_idx].store(mac);
                    self.lock_chunk_state()[chunk_idx] = None;
                }
            }

            pos += to_take as u64;
            remaining = rest;
            chunk_idx += 1; // Linear advance — no per-iteration binary search
        }

        Ok(())
    }

    /// Buffer partial chunk data, computing MAC when complete.
    /// Safe to call concurrently: skips chunks whose MAC was already computed.
    fn buffer_partial_chunk(
        &self,
        chunk_idx: usize,
        offset_in_chunk: usize,
        data: &[u8],
        actual_chunk_size: usize,
    ) -> Result<Option<Vec<u8>>> {
        if offset_in_chunk
            .checked_add(data.len())
            .map_or(true, |end| end > actual_chunk_size)
        {
            return Err(parallel_chunk_data_error(
                offset_in_chunk,
                offset_in_chunk + data.len(),
                actual_chunk_size,
            ));
        }

        let mut completed_data = None;

        {
            let mut states = self.lock_chunk_state();

            if self.chunk_macs[chunk_idx].is_computed() {
                states[chunk_idx] = None;
                return Ok(None);
            }

            if let Some(state) = &mut states[chunk_idx] {
                if state.bytes_received == actual_chunk_size {
                    states[chunk_idx] = None;
                    return Ok(None);
                }

                let mut new_bytes = 0;
                for idx in offset_in_chunk..offset_in_chunk + data.len() {
                    if state.coverage[idx] == 0 {
                        state.coverage[idx] = 1;
                        new_bytes += 1;
                    }
                }
                state.data[offset_in_chunk..offset_in_chunk + data.len()].copy_from_slice(data);
                state.bytes_received += new_bytes;

                if state.bytes_received == actual_chunk_size {
                    completed_data = Some(state.data.clone());
                }
            } else if !self.chunk_macs[chunk_idx].is_computed() {
                let mut buf = vec![0u8; actual_chunk_size];
                buf[offset_in_chunk..offset_in_chunk + data.len()].copy_from_slice(data);
                let mut coverage = vec![0u8; actual_chunk_size];
                for idx in offset_in_chunk..offset_in_chunk + data.len() {
                    coverage[idx] = 1;
                }

                states[chunk_idx] = Some(ChunkState {
                    data: buf,
                    bytes_received: data.len(),
                    coverage,
                });

                if data.len() == actual_chunk_size {
                    completed_data = Some(states[chunk_idx].as_ref().unwrap().data.clone());
                }
            }
        }

        if let Some(data) = completed_data {
            return Ok(Some(data));
        }

        Ok(None)
    }

    /// Finalize and return the combined MAC
    pub fn finalize(&self) -> Option<[u8; 8]> {
        let num_chunks = self.chunk_boundaries.len();

        // Verify we have all chunks
        for idx in 0..num_chunks {
            if !self.chunk_macs[idx].is_computed() {
                return None;
            }
        }

        // Combine MACs in order
        let mut final_mac_data = [0u8; 16];
        let mut final_mac =
            cbc::Encryptor::<Aes128>::new((&self.aes_key).into(), (&final_mac_data).into());

        for idx in 0..num_chunks {
            let cur_mac = self.chunk_macs[idx].load()?;
            final_mac.encrypt_block_b2b_mut((&cur_mac).into(), (&mut final_mac_data).into());
        }

        // XOR to produce final 8-byte MAC
        for i in 0..4 {
            final_mac_data[i] ^= final_mac_data[i + 4];
            final_mac_data[i + 4] = final_mac_data[i + 8] ^ final_mac_data[i + 12];
        }

        Some(final_mac_data[..8].try_into().unwrap())
    }
}

/// Computes a condensed MAC from an in-memory buffer.
///
/// This is useful when the entire file content is already in memory (e.g., after
/// parallel chunk downloads).
pub fn compute_condensed_mac_from_buffer(
    data: &[u8],
    size: u64,
    aes_key: &[u8; 16],
    aes_iv: &[u8; 8],
) -> Result<[u8; 8]> {
    let mut chunk_size: usize = 131_072; // 2^17
    let mut cur_mac = [0u8; 16];

    let mut final_mac_data = [0u8; 16];
    let mut final_mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&final_mac_data).into());

    let aes_iv_full = {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(aes_iv);
        iv[8..].copy_from_slice(aes_iv);
        iv
    };

    let total_size = usize::try_from(size).map_err(|_| {
        crate::Error::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "size parameter overflows usize",
        ))
    })?;

    // Validate that size doesn't exceed data buffer
    if total_size > data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "size {} exceeds data buffer length {}",
                total_size,
                data.len()
            ),
        )
        .into());
    }

    let mut offset = 0;

    while offset < total_size {
        let end = (offset + chunk_size).min(total_size);
        let chunk_data = &data[offset..end];

        let (chunks, leftover) = chunk_data.split_at(chunk_data.len() - chunk_data.len() % 16);

        let mut mac = cbc::Encryptor::<Aes128>::new(aes_key.into(), (&aes_iv_full).into());
        for chunk in chunks.chunks_exact(16) {
            mac.encrypt_block_b2b_mut(chunk.into(), (&mut cur_mac).into());
        }

        if !leftover.is_empty() {
            let mut padded_chunk = [0u8; 16];
            padded_chunk[..leftover.len()].copy_from_slice(leftover);
            mac.encrypt_block_b2b_mut((&padded_chunk).into(), (&mut cur_mac).into());
        }

        final_mac.encrypt_block_b2b_mut((&cur_mac).into(), (&mut final_mac_data).into());

        if chunk_size < 1_048_576 {
            chunk_size += 131_072;
        }
        offset = end;
    }

    for i in 0..4 {
        final_mac_data[i] = final_mac_data[i] ^ final_mac_data[i + 4];
        final_mac_data[i + 4] = final_mac_data[i + 8] ^ final_mac_data[i + 12];
    }

    Ok(final_mac_data[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const TEST_IV: [u8; 8] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];

    #[test]
    fn condensed_mac_buffer_matches_stream() {
        futures::executor::block_on(async {
            // Test that compute_condensed_mac_from_buffer produces same result as compute_condensed_mac
            let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
            let size = data.len() as u64;

            let stream_mac = {
                let cursor = futures::io::Cursor::new(&data);
                compute_condensed_mac(cursor, size, &TEST_KEY, &TEST_IV)
                    .await
                    .unwrap()
            };

            let buffer_mac =
                compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

            assert_eq!(stream_mac, buffer_mac);
        });
    }

    #[test]
    fn condensed_mac_buffer_matches_stream_large() {
        futures::executor::block_on(async {
            // Test with larger data that spans multiple MEGA chunks (>128KB)
            let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
            let size = data.len() as u64;

            let stream_mac = {
                let cursor = futures::io::Cursor::new(&data);
                compute_condensed_mac(cursor, size, &TEST_KEY, &TEST_IV)
                    .await
                    .unwrap()
            };

            let buffer_mac =
                compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

            assert_eq!(stream_mac, buffer_mac);
        });
    }

    #[test]
    fn condensed_mac_empty_data() {
        futures::executor::block_on(async {
            let data: Vec<u8> = vec![];
            let size = 0u64;

            let stream_mac = {
                let cursor = futures::io::Cursor::new(&data);
                compute_condensed_mac(cursor, size, &TEST_KEY, &TEST_IV)
                    .await
                    .unwrap()
            };

            let buffer_mac =
                compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

            assert_eq!(stream_mac, buffer_mac);
        });
    }

    #[test]
    fn condensed_mac_single_chunk() {
        futures::executor::block_on(async {
            // Test with data smaller than one MEGA chunk (128KB)
            let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
            let size = data.len() as u64;

            let stream_mac = {
                let cursor = futures::io::Cursor::new(&data);
                compute_condensed_mac(cursor, size, &TEST_KEY, &TEST_IV)
                    .await
                    .unwrap()
            };

            let buffer_mac =
                compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

            assert_eq!(stream_mac, buffer_mac);
        });
    }

    #[test]
    fn condensed_mac_exactly_one_chunk() {
        futures::executor::block_on(async {
            // Test with data exactly one MEGA chunk (128KB = 131072 bytes)
            let data: Vec<u8> = (0..131_072).map(|i| (i % 256) as u8).collect();
            let size = data.len() as u64;

            let stream_mac = {
                let cursor = futures::io::Cursor::new(&data);
                compute_condensed_mac(cursor, size, &TEST_KEY, &TEST_IV)
                    .await
                    .unwrap()
            };

            let buffer_mac =
                compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

            assert_eq!(stream_mac, buffer_mac);
        });
    }

    #[test]
    fn condensed_mac_unaligned_size() {
        futures::executor::block_on(async {
            // Test with data size not aligned to 16 bytes
            let data: Vec<u8> = (0..10007).map(|i| (i % 256) as u8).collect();
            let size = data.len() as u64;

            let stream_mac = {
                let cursor = futures::io::Cursor::new(&data);
                compute_condensed_mac(cursor, size, &TEST_KEY, &TEST_IV)
                    .await
                    .unwrap()
            };

            let buffer_mac =
                compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

            assert_eq!(stream_mac, buffer_mac);
        });
    }

    #[test]
    fn sparse_checksum_small_file() {
        futures::executor::block_on(async {
            // Files 17-8192 bytes: full CRC32 coverage
            let data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
            let cursor = futures::io::Cursor::new(&data);
            let checksum = compute_sparse_checksum(cursor, data.len() as u64)
                .await
                .unwrap();

            // Verify it's not all zeros
            assert_ne!(checksum, [0u8; 16]);
        });
    }

    #[test]
    fn sparse_checksum_deterministic() {
        futures::executor::block_on(async {
            let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

            let checksum1 = {
                let cursor = futures::io::Cursor::new(&data);
                compute_sparse_checksum(cursor, data.len() as u64)
                    .await
                    .unwrap()
            };

            let checksum2 = {
                let cursor = futures::io::Cursor::new(&data);
                compute_sparse_checksum(cursor, data.len() as u64)
                    .await
                    .unwrap()
            };

            assert_eq!(checksum1, checksum2);
        });
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_mac_matches_buffer_in_order() -> Result<()> {
        // Test ParallelMacProcessor with chunks arriving in order
        let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
        let size = data.len() as u64;

        let buffer_mac =
            compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);
        let chunk_size = 100_000usize;
        let mut offset = 0u64;
        while offset < size {
            let end = (offset + chunk_size as u64).min(size);
            processor.add_chunk(offset, &data[offset as usize..end as usize])?;
            offset = end;
        }

        let parallel_mac = processor.finalize().unwrap();
        assert_eq!(parallel_mac, buffer_mac);
        Ok(())
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_mac_matches_buffer_out_of_order() -> Result<()> {
        // Test ParallelMacProcessor with chunks arriving out of order
        let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
        let size = data.len() as u64;

        let buffer_mac =
            compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

        // Split into chunk ranges and deliver out of order
        let chunk_size = 100_000usize;
        let chunk_ranges: Vec<(u64, usize, usize)> = (0..)
            .map(|i| {
                let start = i * chunk_size;
                let end = ((i + 1) * chunk_size).min(data.len());
                (start as u64, start, end)
            })
            .take_while(|(_, start, end)| start < end)
            .collect();

        // Deliver in reverse order
        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);
        for (offset, start, end) in chunk_ranges.into_iter().rev() {
            processor.add_chunk(offset, &data[start..end])?;
        }

        let parallel_mac = processor.finalize().unwrap();
        assert_eq!(parallel_mac, buffer_mac);
        Ok(())
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_mac_matches_buffer_large_file() -> Result<()> {
        // Test with data spanning multiple MEGA chunk sizes (128KB -> 1MB)
        let data: Vec<u8> = (0..3_000_000).map(|i| (i % 256) as u8).collect();
        let size = data.len() as u64;

        let buffer_mac =
            compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

        // Split data into chunk ranges
        let chunk_size = 500_000usize;
        let chunk_ranges: Vec<(u64, usize, usize)> = (0..)
            .map(|i| {
                let start = i * chunk_size;
                let end = ((i + 1) * chunk_size).min(data.len());
                (start as u64, start, end)
            })
            .take_while(|(_, start, end)| start < end)
            .collect();

        // Deliver even-indexed chunks first, then odd-indexed
        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);
        for (i, &(offset, start, end)) in chunk_ranges.iter().enumerate() {
            if i % 2 == 0 {
                processor.add_chunk(offset, &data[start..end])?;
            }
        }
        for (i, &(offset, start, end)) in chunk_ranges.iter().enumerate() {
            if i % 2 == 1 {
                processor.add_chunk(offset, &data[start..end])?;
            }
        }

        let parallel_mac = processor.finalize().unwrap();
        assert_eq!(parallel_mac, buffer_mac);
        Ok(())
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn add_chunk_unaligned_boundaries() -> Result<()> {
        // Test add_chunk when download chunks don't align with MEGA chunk boundaries.
        // This is the bug that caused CondensedMacMismatch: MEGA chunks are 128KB->1MB,
        // but download chunks are fixed size (e.g., 128MB), so boundaries don't align.
        //
        // Example: MEGA chunks at 0, 128KB, 384KB, ..., 4.5MB, 5.5MB, 6.5MB, ...
        // Download chunk (32MB) at 5MB would split the MEGA chunk from 4.5MB-5.5MB.

        // Create ~6MB of data to span the variable-size MEGA chunk region
        let data: Vec<u8> = (0..6_000_000).map(|i| (i % 256) as u8).collect();
        let size = data.len() as u64;

        let expected_mac =
            compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);

        // Simulate download chunks that DON'T align with MEGA chunk boundaries.
        // Use 1.5MB chunks - this will definitely split some 1MB MEGA chunks.
        let download_chunk_size = 1_500_000usize;
        let mut offset = 0u64;
        while offset < size {
            let end = (offset as usize + download_chunk_size).min(data.len());
            let chunk_data = &data[offset as usize..end];

            // Test the new add_chunk method with unaligned boundaries
            processor.add_chunk(offset, chunk_data)?;

            offset = end as u64;
        }

        let computed_mac = processor.finalize().unwrap();
        assert_eq!(
            computed_mac, expected_mac,
            "MAC mismatch with unaligned download chunks"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn add_chunk_parallel_simulation() -> Result<()> {
        // Simulate parallel workers with interleaved chunk processing.
        // Worker 0 gets chunks 0, 2, 4, ... and Worker 1 gets chunks 1, 3, 5, ...
        // This tests concurrent access to ParallelMacProcessor and partial chunk buffering.

        let data: Vec<u8> = (0..10_000_000).map(|i| (i % 256) as u8).collect();
        let size = data.len() as u64;

        let expected_mac =
            compute_condensed_mac_from_buffer(&data, size, &TEST_KEY, &TEST_IV).unwrap();

        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);

        // Use 2MB download chunks, delivered out of order (simulating 2 workers)
        let download_chunk_size = 2_000_000usize;
        let chunks: Vec<(u64, usize, usize)> = (0..)
            .map(|i| {
                let start = i * download_chunk_size;
                let end = ((i + 1) * download_chunk_size).min(data.len());
                (start as u64, start, end)
            })
            .take_while(|(_, start, end)| start < end)
            .collect();

        // Worker 0: even chunks first
        for (i, &(offset, start, end)) in chunks.iter().enumerate() {
            if i % 2 == 0 {
                processor.add_chunk(offset, &data[start..end])?;
            }
        }
        // Worker 1: odd chunks
        for (i, &(offset, start, end)) in chunks.iter().enumerate() {
            if i % 2 == 1 {
                processor.add_chunk(offset, &data[start..end])?;
            }
        }

        let computed_mac = processor.finalize().unwrap();
        assert_eq!(
            computed_mac, expected_mac,
            "MAC mismatch with parallel worker simulation"
        );
        Ok(())
    }
}
