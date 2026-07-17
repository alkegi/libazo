use std::io::Cursor;

#[test]
fn test_empty_data() {
    let data: Vec<u8> = vec![];
    let mut output = Vec::new();
    let result = libazo::extract_azo(&mut Cursor::new(data), &mut output, 0, None, None);
    assert!(result.is_err());
}

#[test]
fn test_one_byte() {
    let data = vec![0x31];
    let mut output = Vec::new();
    let result = libazo::extract_azo(&mut Cursor::new(&data), &mut output, 1, None, None);
    assert!(result.is_err());
}

#[test]
fn test_bad_version() {
    // Version 0x32 instead of 0x31
    let data = vec![
        0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut output = Vec::new();
    let result = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut output,
        data.len() as u64,
        None,
        None,
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("version"),
        "expected version error, got: {err}"
    );
}

#[test]
fn test_truncated_block_header() {
    // Valid stream header but not enough data for block header (needs 12 bytes)
    let data = vec![0x31, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut output = Vec::new();
    let result = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut output,
        data.len() as u64,
        None,
        None,
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("truncated"),
        "expected truncated error, got: {err}"
    );
}

#[test]
fn test_terminal_block() {
    // Valid header + terminal block (block_size=0, compress_size=0)
    let mut data = vec![0x31, 0x00]; // version + flags
    // block_size=0 (BE)
    data.extend_from_slice(&0u32.to_be_bytes());
    // compress_size=0 (BE)
    data.extend_from_slice(&0u32.to_be_bytes());
    // check_value = 0 ^ 0 = 0 (BE)
    data.extend_from_slice(&0u32.to_be_bytes());

    let mut output = Vec::new();
    let result = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut output,
        data.len() as u64,
        None,
        None,
    );
    assert!(result.is_ok());
    assert!(output.is_empty());
}

#[test]
fn test_check_value_mismatch() {
    let mut data = vec![0x31, 0x00];
    // block_size=100 (BE)
    data.extend_from_slice(&100u32.to_be_bytes());
    // compress_size=50 (BE)
    data.extend_from_slice(&50u32.to_be_bytes());
    // wrong check_value (should be 100 ^ 50 = 86)
    data.extend_from_slice(&0u32.to_be_bytes());

    let mut output = Vec::new();
    let result = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut output,
        data.len() as u64,
        None,
        None,
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("check value"),
        "expected check value error, got: {err}"
    );
}

#[test]
fn test_truncated_block_data() {
    let block_size: u32 = 100;
    let compress_size: u32 = 50;
    let check_value = block_size ^ compress_size;

    let mut data = vec![0x31, 0x00];
    data.extend_from_slice(&block_size.to_be_bytes());
    data.extend_from_slice(&compress_size.to_be_bytes());
    data.extend_from_slice(&check_value.to_be_bytes());
    // Only 10 bytes of compressed data instead of 50
    data.extend_from_slice(&[0u8; 10]);

    let mut output = Vec::new();
    let result = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut output,
        data.len() as u64,
        None,
        None,
    );
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("truncated"),
        "expected truncated error, got: {err}"
    );
}

#[test]
fn test_stored_block() {
    // Stored block: compress_size == block_size, data passes through unmodified
    let content = b"Hello, AZO!";
    let block_size = content.len() as u32;
    let compress_size = block_size; // stored
    let check_value = block_size ^ compress_size; // 0

    let mut data = vec![0x31, 0x00]; // version, no x86 filter
    data.extend_from_slice(&block_size.to_be_bytes());
    data.extend_from_slice(&compress_size.to_be_bytes());
    data.extend_from_slice(&check_value.to_be_bytes());
    data.extend_from_slice(content);
    // Terminal block
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());

    let mut output = Vec::new();
    let crc = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut output,
        data.len() as u64,
        None,
        None,
    )
    .unwrap();
    assert_eq!(&output, content);
    // CRC-32 of b"Hello, AZO!"
    assert_eq!(crc, 0xB88B_40D9);
}

#[test]
fn test_decrypt_callback() {
    // XOR "encryption" -- decrypt by XOR again
    let content = b"Secret AZO data";
    let block_size = content.len() as u32;
    let compress_size = block_size;
    let check_value = block_size ^ compress_size;

    let mut plaintext_stream = vec![0x31, 0x00];
    plaintext_stream.extend_from_slice(&block_size.to_be_bytes());
    plaintext_stream.extend_from_slice(&compress_size.to_be_bytes());
    plaintext_stream.extend_from_slice(&check_value.to_be_bytes());
    plaintext_stream.extend_from_slice(content);
    plaintext_stream.extend_from_slice(&0u32.to_be_bytes());
    plaintext_stream.extend_from_slice(&0u32.to_be_bytes());
    plaintext_stream.extend_from_slice(&0u32.to_be_bytes());

    // "Encrypt" by XOR with 0x42
    let encrypted: Vec<u8> = plaintext_stream.iter().map(|b| b ^ 0x42).collect();

    let mut output = Vec::new();
    let crc = libazo::extract_azo(
        &mut Cursor::new(&encrypted),
        &mut output,
        encrypted.len() as u64,
        None,
        Some(&mut |data: &mut [u8]| {
            for b in data.iter_mut() {
                *b ^= 0x42;
            }
        }),
    )
    .unwrap();

    assert_eq!(&output, content);
    // CRC-32 of b"Secret AZO data"
    assert_eq!(crc, 0xB63B_9760);
}

#[test]
fn test_reader_too_short() {
    // compressed_size says 100 but reader only has 10 bytes
    let data = vec![0u8; 10];
    let mut output = Vec::new();
    let result = libazo::extract_azo(&mut Cursor::new(&data), &mut output, 100, None, None);
    assert!(result.is_err());
}
