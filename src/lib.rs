//! Decompression library for the AZO format.
//!
//! AZO is an LZ77 variant with arithmetic coding, adaptive probability models,
//! and an optional x86 CALL/JMP address filter. The entry point is
//! [`extract_azo`]; see its docs for the streaming and bomb-limit parameters.

pub(crate) mod crc;
pub(crate) mod match_code;
pub(crate) mod model;
pub(crate) mod range;
pub(crate) mod recent;
pub(crate) mod table;
pub mod x86;

use std::fmt;
use std::io::{Read, Write};

use self::match_code::MatchCode;
use self::model::BoolState;
use self::model::PredictProb;
use self::range::RangeDecoder;

/// Errors returned by [`extract_azo`].
#[derive(Debug)]
#[non_exhaustive]
pub enum AzoError {
    /// An I/O error while reading the stream or writing the output.
    Io(std::io::Error),
    /// The stream is malformed, unsupported, or exceeds a safety limit.
    Failed(String),
}

impl fmt::Display for AzoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Failed(e) => write!(f, "AZO error: {e}"),
        }
    }
}

impl std::error::Error for AzoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Failed(_) => None,
        }
    }
}

impl From<std::io::Error> for AzoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Decryption callback type. Called with a mutable slice to decrypt in place.
pub type DecryptFn<'a> = &'a mut dyn FnMut(&mut [u8]);

/// Safety ceiling on a single decompressed block. `blockSize` is an untrusted
/// u32 from the stream (up to 4 GiB) with no maximum defined by the format, so
/// a crafted block could otherwise force a multi-gigabyte allocation. Only one
/// block buffer is live at a time, so this also bounds peak memory.
const MAX_BLOCK_SIZE: usize = 256 * 1024 * 1024;

/// Extract an AZO compressed stream.
///
/// Reads `compressed_size` bytes from `reader`, optionally decrypts them
/// with `decrypt`, decompresses, and writes output to `writer`.
/// Returns the CRC32 of the decompressed data.
///
/// `max_output` bounds the total number of decompressed bytes across all
/// blocks. Pass the expected uncompressed size to reject decompression bombs
/// early; `None` disables the check (unbounded output).
pub fn extract_azo<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    compressed_size: u64,
    max_output: Option<u64>,
    decrypt: Option<DecryptFn<'_>>,
) -> Result<u32, AzoError> {
    // Grow from the bytes actually present rather than pre-allocating the
    // declared size, so a bogus compressed_size can't trigger a huge alloc.
    let mut data = Vec::new();
    if reader
        .by_ref()
        .take(compressed_size)
        .read_to_end(&mut data)? as u64
        != compressed_size
    {
        return Err(AzoError::Failed("truncated AZO stream".into()));
    }
    if let Some(f) = decrypt {
        f(&mut data);
    }

    if data.len() < 2 {
        return Err(AzoError::Failed("data too short".into()));
    }

    let version = data[0];
    let flags = data[1];
    if version != 0x31 {
        return Err(AzoError::Failed(format!(
            "unsupported AZO version: {version}"
        )));
    }
    let x86_filter_enabled = flags & 0x01 != 0;

    let mut hasher = crc::Crc32::new();
    let mut pos = 2;
    let mut total_output: u64 = 0;

    loop {
        if pos + 12 > data.len() {
            return Err(AzoError::Failed("truncated block header".into()));
        }

        let block_size = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
        let compress_size = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().unwrap());
        let check_value = u32::from_be_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        pos += 12;

        // Terminal block: both sizes zero.
        if block_size == 0 && compress_size == 0 {
            break;
        }

        if (block_size ^ compress_size) != check_value {
            return Err(AzoError::Failed("block check value mismatch".into()));
        }

        // A non-terminal block must produce output and be backed by data;
        // otherwise `decompress_block` would index an empty buffer, or a 1-byte
        // block could be inflated into a huge one (decompression bomb).
        if block_size == 0 {
            return Err(AzoError::Failed("zero block size".into()));
        }
        if compress_size == 0 {
            return Err(AzoError::Failed("zero compressed size".into()));
        }

        if block_size as usize > MAX_BLOCK_SIZE {
            return Err(AzoError::Failed(format!(
                "block size {block_size} exceeds limit"
            )));
        }

        if let Some(max) = max_output {
            total_output = total_output
                .checked_add(block_size as u64)
                .filter(|&t| t <= max)
                .ok_or_else(|| AzoError::Failed("output exceeds max_output".into()))?;
        }

        let block_end = pos
            .checked_add(compress_size as usize)
            .filter(|&e| e <= data.len())
            .ok_or_else(|| AzoError::Failed("truncated block data".into()))?;
        let block_data = &data[pos..block_end];
        pos = block_end;

        let mut output = if compress_size == block_size {
            block_data.to_vec()
        } else {
            decompress_block(block_data, block_size as usize)?
        };

        if x86_filter_enabled {
            x86::x86_filter(&mut output);
        }

        hasher.update(&output);
        writer.write_all(&output)?;
    }

    Ok(hasher.finalize())
}

fn decompress_block(data: &[u8], block_size: usize) -> Result<Vec<u8>, AzoError> {
    let mut entropy = RangeDecoder::new(data);
    entropy.initialize();

    let mut buf = vec![0u8; block_size];

    let mut alpha = PredictProb::new(256, 256, 5);
    let mut match_flag = BoolState::new(8);
    let mut match_code = MatchCode::new();

    buf[0] = alpha.decode(&mut entropy, 0) as u8;

    let mut i = 1;
    while i < block_size {
        if match_flag.decode(&mut entropy) == 0 {
            let context = buf[i - 1] as usize;
            buf[i] = alpha.decode(&mut entropy, context) as u8;
            i += 1;
        } else {
            let (distance, length) = match_code.decode(&mut entropy, i as u32);

            if distance == 0 || distance as usize > i {
                return Err(AzoError::Failed(format!(
                    "invalid match: distance={distance}, pos={i}"
                )));
            }

            let src_start = i - distance as usize;
            for j in 0..length as usize {
                if i + j >= block_size {
                    break;
                }
                buf[i + j] = buf[src_start + j];
            }
            i += length as usize;
        }
    }

    if !entropy.fully_consumed() {
        return Err(AzoError::Failed(
            "trailing bytes in compressed block".into(),
        ));
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run(stream: &[u8]) -> Result<u32, AzoError> {
        let mut out = Vec::new();
        extract_azo(
            &mut Cursor::new(stream),
            &mut out,
            stream.len() as u64,
            None,
            None,
        )
    }

    /// Build a valid stream header plus one block header with the given sizes.
    fn block_stream(block_size: u32, compress_size: u32, data: &[u8]) -> Vec<u8> {
        let mut s = vec![0x31, 0x00];
        s.extend_from_slice(&block_size.to_be_bytes());
        s.extend_from_slice(&compress_size.to_be_bytes());
        s.extend_from_slice(&(block_size ^ compress_size).to_be_bytes());
        s.extend_from_slice(data);
        s
    }

    #[test]
    fn rejects_oversized_block() {
        // version, flags, then a block declaring blockSize = 0xFFFFFFFF.
        let mut s = vec![0x31, 0x00];
        s.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // blockSize
        s.extend_from_slice(&1u32.to_be_bytes()); // compressSize
        s.extend_from_slice(&0xFFFF_FFFEu32.to_be_bytes()); // check = bs ^ cs
        s.push(0x00); // one byte of block data
        assert!(matches!(run(&s), Err(AzoError::Failed(_))));
    }

    #[test]
    fn rejects_zero_block_size() {
        // Regression: block_size=0 with compress_size!=0 must not reach the
        // empty-buffer `buf[0]` write (previously an index-out-of-bounds panic).
        let s = block_stream(0, 1, &[0x00]);
        assert!(matches!(run(&s), Err(AzoError::Failed(_))));
    }

    #[test]
    fn rejects_zero_compress_size() {
        // Regression: compress_size=0 with block_size!=0 is a bomb backing.
        let s = block_stream(256, 0, &[]);
        assert!(matches!(run(&s), Err(AzoError::Failed(_))));
    }

    #[test]
    fn enforces_max_output() {
        // A block declaring 256 bytes of output rejected under a 100-byte cap.
        let s = block_stream(256, 4, &[0x00; 4]);
        let mut out = Vec::new();
        let r = extract_azo(
            &mut Cursor::new(&s),
            &mut out,
            s.len() as u64,
            Some(100),
            None,
        );
        assert!(matches!(r, Err(AzoError::Failed(_))));
    }

    #[test]
    fn rejects_truncated_stream() {
        // Claim more bytes than the reader can provide.
        let mut out = Vec::new();
        let data = [0x31u8, 0x00];
        let r = extract_azo(&mut Cursor::new(&data[..]), &mut out, 100, None, None);
        assert!(matches!(r, Err(AzoError::Failed(_))));
    }
}
