//! Regression tests that decode real AZO streams end to end.
use std::io::Cursor;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name);
    assert!(p.is_file(), "test samples are missing: {}", p.display());
    p
}

fn decode(name: &str) -> (Vec<u8>, u32) {
    let data = std::fs::read(fixture(name)).expect("read fixture");
    let mut out = Vec::new();
    let crc = libazo::extract_azo(
        &mut Cursor::new(&data),
        &mut out,
        data.len() as u64,
        None,
        None,
    )
    .expect("decode azo");
    (out, crc)
}

#[test]
fn gpl_license() {
    let (out, crc) = decode("gpl.txt.azo");
    assert_eq!(out.len(), 36388);
    let text = std::str::from_utf8(&out).expect("valid utf-8");
    assert!(text.starts_with("                    GNU GENERAL PUBLIC LICENSE"));
    assert!(text.contains("Free Software Foundation"));
    assert_eq!(crc, 0xA293_0E54);
}

#[test]
fn repeated_bytes() {
    let (out, crc) = decode("aaa.txt.azo");
    assert_eq!(out, vec![b'a'; 100]);
    assert_eq!(crc, 0xAF70_7A64);
}

#[test]
fn rejects_trailing_garbage_in_block() {
    // The tag lookahead can absorb up to 4 trailing bytes, so append 8 to
    // guarantee an unconsumed tail.
    let data = std::fs::read(fixture("gpl.txt.azo")).expect("read fixture");
    let block_size = u32::from_be_bytes(data[2..6].try_into().unwrap());
    let compress_size = u32::from_be_bytes(data[6..10].try_into().unwrap());
    let payload = &data[14..14 + compress_size as usize];

    let padded_size = compress_size + 8;
    let mut s = vec![0x31, 0x00];
    s.extend_from_slice(&block_size.to_be_bytes());
    s.extend_from_slice(&padded_size.to_be_bytes());
    s.extend_from_slice(&(block_size ^ padded_size).to_be_bytes());
    s.extend_from_slice(payload);
    s.extend_from_slice(&[0u8; 8]);
    s.extend_from_slice(&[0u8; 12]); // terminal block

    let mut out = Vec::new();
    let r = libazo::extract_azo(&mut Cursor::new(&s), &mut out, s.len() as u64, None, None);
    assert!(r.is_err(), "trailing garbage must be rejected");
}

#[test]
fn executable_with_x86_filter() {
    // Multi-block stream with the x86 CALL/JMP filter enabled (flags bit 0).
    let (out, crc) = decode("bandizip32.exe.azo");
    assert_eq!(out.len(), 2242424);
    assert_eq!(&out[..2], b"MZ"); // valid PE header
    assert_eq!(crc, 0x6F34_2184);
}
