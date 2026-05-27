#[cfg(feature = "parallel")]
use std::io::{Error as IoError, ErrorKind};
use std::pin::pin;

use aes::Aes128;
use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use cipher::{
    typenum::U16, Block, BlockBackend, BlockClosure, BlockEncrypt, BlockSizeUser, KeyInit,
};
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
    let aes = Aes128::new(aes_key.into());
    let mut final_mac_data = [0u8; 16];

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

        let cur_mac = compute_chunk_mac_with_cipher(&aes, &aes_iv, chunks, leftover);
        encrypt_cbc_block(&aes, &mut final_mac_data, &cur_mac);

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

/// Iterator over the plaintext MAC chunk boundaries MEGA uses for a file size.
#[derive(Debug, Clone)]
pub struct MegaChunkBoundaries {
    file_size: u64,
    offset: u64,
    next_size: u64,
    index: u32,
}

impl MegaChunkBoundaries {
    #[must_use]
    fn new(file_size: u64) -> Self {
        Self {
            file_size,
            offset: 0,
            next_size: 131_072,
            index: 0,
        }
    }
}

impl Iterator for MegaChunkBoundaries {
    type Item = MegaChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.file_size {
            return None;
        }

        let offset = self.offset;
        let length = self.next_size.min(self.file_size - offset);
        let index = self.index;

        self.offset += length;
        self.index += 1;
        if self.next_size < 1_048_576 {
            self.next_size += 131_072;
        }

        Some(MegaChunk {
            index,
            offset,
            length,
        })
    }
}

const MEGA_CHUNK_SIZE_STEP: u64 = 131_072;
const MEGA_MAX_CHUNK_SIZE: u64 = 1_048_576;
const MEGA_RAMP_CHUNKS: usize = 8;
const MEGA_RAMP_BYTES: u64 = MEGA_CHUNK_SIZE_STEP * 36;

fn mega_chunk_count(file_size: u64) -> usize {
    if file_size == 0 {
        return 0;
    }

    if file_size <= MEGA_RAMP_BYTES {
        let mut offset = 0;
        for idx in 0..MEGA_RAMP_CHUNKS {
            let size = MEGA_CHUNK_SIZE_STEP * (idx as u64 + 1);
            offset += size;
            if file_size <= offset {
                return idx + 1;
            }
        }
    }

    let remaining = file_size - MEGA_RAMP_BYTES;
    MEGA_RAMP_CHUNKS + remaining.div_ceil(MEGA_MAX_CHUNK_SIZE) as usize
}

fn mega_chunk_by_index(file_size: u64, index: usize) -> Option<MegaChunk> {
    if index >= mega_chunk_count(file_size) {
        return None;
    }

    let (offset, max_length) = if index < MEGA_RAMP_CHUNKS {
        let idx = index as u64;
        (
            MEGA_CHUNK_SIZE_STEP * idx * (idx + 1) / 2,
            MEGA_CHUNK_SIZE_STEP * (idx + 1),
        )
    } else {
        (
            MEGA_RAMP_BYTES + (index - MEGA_RAMP_CHUNKS) as u64 * MEGA_MAX_CHUNK_SIZE,
            MEGA_MAX_CHUNK_SIZE,
        )
    };

    Some(MegaChunk {
        index: index as u32,
        offset,
        length: max_length.min(file_size - offset),
    })
}

fn mega_chunk_for_offset(file_size: u64, offset: u64) -> Option<(usize, MegaChunk)> {
    if offset >= file_size {
        return None;
    }

    let index = if offset < MEGA_RAMP_BYTES {
        let mut chunk_start = 0;
        let mut index = 0;
        while index < MEGA_RAMP_CHUNKS {
            let size = MEGA_CHUNK_SIZE_STEP * (index as u64 + 1);
            if offset < chunk_start + size {
                break;
            }
            chunk_start += size;
            index += 1;
        }
        index
    } else {
        MEGA_RAMP_CHUNKS + ((offset - MEGA_RAMP_BYTES) / MEGA_MAX_CHUNK_SIZE) as usize
    };

    mega_chunk_by_index(file_size, index).map(|chunk| (index, chunk))
}

/// Returns the plaintext MAC chunk boundaries MEGA uses for a file size.
#[must_use]
pub fn mega_chunk_boundaries(file_size: u64) -> Vec<MegaChunk> {
    mega_chunk_boundaries_iter(file_size).collect()
}

/// Streams the plaintext MAC chunk boundaries MEGA uses for a file size.
#[must_use]
pub fn mega_chunk_boundaries_iter(file_size: u64) -> MegaChunkBoundaries {
    MegaChunkBoundaries::new(file_size)
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
    num_chunks: usize,

    // Computed MACs per MEGA chunk: 16-byte MAC stored as two u64s with computed flag
    chunk_macs: Vec<MacEntry>,

    // Partial chunk state. Allocated only when a caller sends partial MEGA chunks.
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

        let num_chunks = mega_chunk_count(file_size);
        Self {
            aes_key: *aes_key,
            aes_iv_full,
            file_size,
            num_chunks,
            chunk_macs: (0..num_chunks)
                .map(|_| MacEntry {
                    lo: std::sync::atomic::AtomicU64::new(0),
                    hi: std::sync::atomic::AtomicU64::new(0),
                    computed: std::sync::atomic::AtomicBool::new(false),
                })
                .collect(),
            chunk_state: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns (mega_chunk_index, offset_within_chunk) for a file offset
    fn mega_chunk_for_offset(&self, offset: u64) -> Option<(usize, u64)> {
        let (idx, chunk) = mega_chunk_for_offset(self.file_size, offset)?;
        Some((idx, offset - chunk.offset))
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
    let (blocks, leftover) = data.split_at(data.len() - data.len() % 16);
    let aes = Aes128::new(aes_key.into());
    compute_chunk_mac_with_cipher(&aes, aes_iv, blocks, leftover)
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
pub struct MegaChunkMac {
    aes: Aes128,
    cur_mac: [u8; 16],
    partial: [u8; 16],
    partial_len: usize,
}

#[cfg(feature = "parallel")]
pub struct MegaCondensedMac {
    aes: Aes128,
    final_mac_data: [u8; 16],
}

#[cfg(feature = "parallel")]
impl MegaCondensedMac {
    #[must_use]
    pub fn new(aes_key: &[u8; 16]) -> Self {
        Self {
            aes: Aes128::new(aes_key.into()),
            final_mac_data: [0; 16],
        }
    }

    pub fn update_chunk_mac(&mut self, chunk_mac: &[u8; 16]) {
        encrypt_cbc_block(&self.aes, &mut self.final_mac_data, chunk_mac);
    }

    #[must_use]
    pub fn finalize(mut self) -> [u8; 8] {
        for i in 0..4 {
            self.final_mac_data[i] ^= self.final_mac_data[i + 4];
            self.final_mac_data[i + 4] = self.final_mac_data[i + 8] ^ self.final_mac_data[i + 12];
        }
        self.final_mac_data[..8].try_into().unwrap()
    }
}

#[cfg(feature = "parallel")]
impl MegaChunkMac {
    #[must_use]
    pub fn new(aes_key: &[u8; 16], aes_iv: &[u8; 8]) -> Self {
        let mut aes_iv_full = [0u8; 16];
        aes_iv_full[..8].copy_from_slice(aes_iv);
        aes_iv_full[8..].copy_from_slice(aes_iv);
        Self {
            aes: Aes128::new(aes_key.into()),
            cur_mac: aes_iv_full,
            partial: [0u8; 16],
            partial_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.partial_len > 0 {
            let needed = 16 - self.partial_len;
            let take = needed.min(data.len());
            self.partial[self.partial_len..self.partial_len + take].copy_from_slice(&data[..take]);
            self.partial_len += take;
            data = &data[take..];
            if self.partial_len == 16 {
                encrypt_cbc_block(&self.aes, &mut self.cur_mac, &self.partial);
                self.partial = [0u8; 16];
                self.partial_len = 0;
            }
        }

        let block_len = data.len() - (data.len() % 16);
        let (blocks, leftover) = data.split_at(block_len);
        encrypt_cbc_blocks(&self.aes, &mut self.cur_mac, blocks);

        if !leftover.is_empty() {
            self.partial[..leftover.len()].copy_from_slice(leftover);
            self.partial_len = leftover.len();
        }
    }

    #[must_use]
    pub fn finalize(mut self) -> [u8; 16] {
        if self.partial_len > 0 {
            let mut padded = [0u8; 16];
            padded[..self.partial_len].copy_from_slice(&self.partial[..self.partial_len]);
            encrypt_cbc_block(&self.aes, &mut self.cur_mac, &padded);
        }
        self.cur_mac
    }
}

fn compute_chunk_mac_with_cipher(
    aes: &Aes128,
    aes_iv: &[u8; 16],
    blocks: &[u8],
    leftover: &[u8],
) -> [u8; 16] {
    let mut cur_mac = *aes_iv;
    encrypt_cbc_blocks(aes, &mut cur_mac, blocks);

    if !leftover.is_empty() {
        let mut padded = [0u8; 16];
        padded[..leftover.len()].copy_from_slice(leftover);
        encrypt_cbc_block(aes, &mut cur_mac, &padded);
    }

    cur_mac
}

fn encrypt_cbc_block(aes: &Aes128, state: &mut [u8; 16], input: &[u8; 16]) {
    for (dst, src) in state.iter_mut().zip(input) {
        *dst ^= *src;
    }
    aes.encrypt_block(state.into());
}

struct CbcMacBlocks<'a, 'b> {
    state: &'a mut [u8; 16],
    blocks: &'b [u8],
}

impl BlockSizeUser for CbcMacBlocks<'_, '_> {
    type BlockSize = U16;
}

impl BlockClosure for CbcMacBlocks<'_, '_> {
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = U16>>(self, backend: &mut B) {
        let mut state = Block::<B>::clone_from_slice(self.state);
        let mut offset = 0;
        while offset < self.blocks.len() {
            // SAFETY: callers pass only complete 16-byte block runs. `[u8; 16]`
            // has byte alignment, so unaligned input slices are fine.
            let input = unsafe { &*self.blocks.as_ptr().add(offset).cast::<[u8; 16]>() };
            for (dst, src) in state.iter_mut().zip(input) {
                *dst ^= *src;
            }
            backend.proc_block_inplace(&mut state);
            offset += 16;
        }
        self.state.copy_from_slice(&state);
    }
}

fn encrypt_cbc_blocks(aes: &Aes128, state: &mut [u8; 16], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % 16, 0);
    if !blocks.is_empty() {
        aes.encrypt_with_backend(CbcMacBlocks { state, blocks });
    }
}

#[cfg(feature = "parallel")]
impl ParallelMacProcessor {
    /// Add data at the given file offset. Can be called from multiple threads.
    ///
    /// Processes data linearly through MEGA chunks:
    /// - One initial boundary calculation to find the starting chunk
    /// - Then linear iteration through successive chunks
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

        while !remaining.is_empty() && chunk_idx < self.num_chunks {
            let info = mega_chunk_by_index(self.file_size, chunk_idx)
                .ok_or_else(|| parallel_chunk_range_error(pos, end_offset, self.file_size))?;
            let chunk_end = info.offset + info.length;
            let offset_in_chunk = (pos - info.offset) as usize;
            let bytes_until_end = (chunk_end - pos) as usize;
            let to_take = remaining.len().min(bytes_until_end);
            let (for_this_chunk, rest) = remaining.split_at(to_take);

            // Fast path: complete, aligned chunk - compute MAC directly
            if offset_in_chunk == 0 && to_take == info.length as usize {
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
                    info.length as usize,
                )? {
                    let mac = compute_chunk_mac_inner(&self.aes_key, &self.aes_iv_full, &data);
                    self.chunk_macs[chunk_idx].store(mac);
                    let mut states = self.lock_chunk_state();
                    if chunk_idx < states.len() {
                        states[chunk_idx] = None;
                    }
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
            if chunk_idx >= states.len() {
                states.resize_with(chunk_idx + 1, || None);
            }

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
        let aes = Aes128::new((&self.aes_key).into());

        // Verify we have all chunks
        for idx in 0..self.num_chunks {
            if !self.chunk_macs[idx].is_computed() {
                return None;
            }
        }

        // Combine MACs in order
        let mut final_mac_data = [0u8; 16];

        for idx in 0..self.num_chunks {
            let cur_mac = self.chunk_macs[idx].load()?;
            encrypt_cbc_block(&aes, &mut final_mac_data, &cur_mac);
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
    let aes = Aes128::new(aes_key.into());
    let mut final_mac_data = [0u8; 16];

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
        let cur_mac = compute_chunk_mac_with_cipher(&aes, &aes_iv_full, chunks, leftover);
        encrypt_cbc_block(&aes, &mut final_mac_data, &cur_mac);

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
    fn mega_chunk_count_matches_boundary_iterator() {
        for size in [
            0,
            1,
            MEGA_CHUNK_SIZE_STEP,
            MEGA_CHUNK_SIZE_STEP + 1,
            MEGA_RAMP_BYTES - 1,
            MEGA_RAMP_BYTES,
            MEGA_RAMP_BYTES + 1,
            MEGA_RAMP_BYTES + MEGA_MAX_CHUNK_SIZE,
            MEGA_RAMP_BYTES + MEGA_MAX_CHUNK_SIZE + 1,
            64 * 1024 * 1024 + 17,
        ] {
            assert_eq!(
                mega_chunk_count(size),
                mega_chunk_boundaries_iter(size).count(),
                "size {size}"
            );
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn mega_chunk_offset_lookup_matches_boundary_iterator() {
        for size in [
            1,
            MEGA_CHUNK_SIZE_STEP,
            MEGA_RAMP_BYTES - 1,
            MEGA_RAMP_BYTES,
            MEGA_RAMP_BYTES + 2 * MEGA_MAX_CHUNK_SIZE + 17,
        ] {
            for expected in mega_chunk_boundaries_iter(size) {
                for offset in [expected.offset, expected.offset + expected.length - 1] {
                    let (index, found) = mega_chunk_for_offset(size, offset).unwrap();
                    assert_eq!(index, expected.index as usize);
                    assert_eq!(found, expected);
                }
            }
            assert!(mega_chunk_for_offset(size, size).is_none());
        }
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_mac_processor_starts_without_partial_state() {
        let processor = ParallelMacProcessor::new(10 * 1024 * 1024, &TEST_KEY, &TEST_IV);

        assert_eq!(processor.num_chunks, mega_chunk_count(10 * 1024 * 1024));
        assert!(processor.lock_chunk_state().is_empty());
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_mac_processor_full_chunks_do_not_allocate_partial_state() -> Result<()> {
        let size = MEGA_RAMP_BYTES + MEGA_MAX_CHUNK_SIZE;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);

        for chunk in mega_chunk_boundaries_iter(size) {
            let start = chunk.offset as usize;
            let end = start + chunk.length as usize;
            processor.add_chunk(chunk.offset, &data[start..end])?;
        }

        assert!(processor.lock_chunk_state().is_empty());
        assert!(processor.finalize().is_some());
        Ok(())
    }

    #[test]
    #[cfg(feature = "parallel")]
    fn parallel_mac_processor_allocates_partial_state_only_for_split_chunks() -> Result<()> {
        let size = MEGA_RAMP_BYTES + 17;
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let processor = ParallelMacProcessor::new(size, &TEST_KEY, &TEST_IV);
        let first = mega_chunk_boundaries_iter(size).next().unwrap();
        let split = first.length as usize / 2;

        processor.add_chunk(first.offset, &data[..split])?;
        assert!(!processor.lock_chunk_state().is_empty());

        processor.add_chunk(
            first.offset + split as u64,
            &data[split..first.length as usize],
        )?;
        assert!(processor.lock_chunk_state()[first.index as usize].is_none());
        Ok(())
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
