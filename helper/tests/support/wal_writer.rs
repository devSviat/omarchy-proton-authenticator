#![allow(dead_code)]

pub struct Frame {
    pub page: u32,
    pub commit_pages: u32,
    pub data: Vec<u8>,
}

fn word(be: bool, b: &[u8]) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

pub fn checksum(be: bool, seed: (u32, u32), data: &[u8]) -> (u32, u32) {
    let (mut s0, mut s1) = seed;
    for c in data.as_chunks::<8>().0 {
        s0 = s0.wrapping_add(word(be, &c[0..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(word(be, &c[4..8])).wrapping_add(s0);
    }
    (s0, s1)
}

pub fn salts(wal: &[u8]) -> (u32, u32) {
    (
        u32::from_be_bytes(wal[16..20].try_into().unwrap()),
        u32::from_be_bytes(wal[20..24].try_into().unwrap()),
    )
}

pub fn parse_frames(wal: &[u8], page_size: usize) -> Vec<Frame> {
    let frame_len = 24 + page_size;
    wal[32..]
        .chunks_exact(frame_len)
        .map(|f| Frame {
            page: u32::from_be_bytes(f[0..4].try_into().unwrap()),
            commit_pages: u32::from_be_bytes(f[4..8].try_into().unwrap()),
            data: f[24..].to_vec(),
        })
        .collect()
}

pub fn build(be: bool, page_size: u32, salts: (u32, u32), frames: &[Frame]) -> Vec<u8> {
    let put = |out: &mut Vec<u8>, v: u32| out.extend_from_slice(&v.to_be_bytes());
    let mut out = Vec::new();
    put(&mut out, if be { 0x377f_0683 } else { 0x377f_0682 });
    put(&mut out, 3_007_000);
    put(&mut out, page_size);
    put(&mut out, 0);
    put(&mut out, salts.0);
    put(&mut out, salts.1);
    let mut sum = checksum(be, (0, 0), &out);
    put(&mut out, sum.0);
    put(&mut out, sum.1);
    for f in frames {
        let mut header = Vec::new();
        put(&mut header, f.page);
        put(&mut header, f.commit_pages);
        put(&mut header, salts.0);
        put(&mut header, salts.1);
        sum = checksum(be, checksum(be, sum, &header[..8]), &f.data);
        put(&mut header, sum.0);
        put(&mut header, sum.1);
        out.extend_from_slice(&header);
        out.extend_from_slice(&f.data);
    }
    out
}
