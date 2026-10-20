use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const DB_HEADER_LEN: usize = 100;
const WAL_HEADER_LEN: usize = 32;
const FRAME_HEADER_LEN: usize = 24;
const WAL_MAGIC_LE: u32 = 0x377f_0682;
const WAL_MAGIC_BE: u32 = 0x377f_0683;
const WAL_VERSION: u32 = 3_007_000;

struct Committed {
    frames: Vec<(u32, usize)>,
    db_pages: u32,
}

pub fn has_sqlite_header(main: &[u8]) -> bool {
    main.len() >= DB_HEADER_LEN && main.starts_with(SQLITE_MAGIC)
}

pub fn page_size(main: &[u8]) -> Result<usize> {
    if !has_sqlite_header(main) {
        return Err(ErrorCode::VaultFormatChanged);
    }
    let raw = u16::from_be_bytes([main[16], main[17]]);
    let size = if raw == 1 { 65536 } else { usize::from(raw) };
    if size < 512 || !size.is_power_of_two() {
        return Err(ErrorCode::VaultFormatChanged);
    }
    Ok(size)
}

fn be32(bytes: &[u8], offset: usize) -> u32 {
    match bytes.get(offset..offset + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

fn checksum(big_endian: bool, seed: (u32, u32), data: &[u8]) -> (u32, u32) {
    let (mut s0, mut s1) = seed;
    for c in data.chunks_exact(8) {
        let (x0, x1) = if big_endian {
            (
                u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
            )
        } else {
            (
                u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
            )
        };
        s0 = s0.wrapping_add(x0).wrapping_add(s1);
        s1 = s1.wrapping_add(x1).wrapping_add(s0);
    }
    (s0, s1)
}

fn committed_frames(wal: &[u8], page_size: usize) -> Result<Option<Committed>> {
    if wal.len() < WAL_HEADER_LEN {
        return Ok(None);
    }
    let big_endian = match be32(wal, 0) {
        WAL_MAGIC_LE => false,
        WAL_MAGIC_BE => true,
        _ => return Ok(None),
    };
    if be32(wal, 4) != WAL_VERSION {
        return Err(ErrorCode::VaultFormatChanged);
    }
    if checksum(big_endian, (0, 0), &wal[..24]) != (be32(wal, 24), be32(wal, 28)) {
        return Ok(None);
    }
    if usize::try_from(be32(wal, 8)).ok() != Some(page_size) {
        return Err(ErrorCode::VaultFormatChanged);
    }

    let salts = &wal[16..24];
    let frame_len = FRAME_HEADER_LEN + page_size;
    let mut seed = (be32(wal, 24), be32(wal, 28));
    let mut frames = Vec::new();
    let mut committed_len = 0;
    let mut db_pages = 0;
    let mut offset = WAL_HEADER_LEN;
    while let Some(frame) = wal.get(offset..offset + frame_len) {
        let (header, data) = frame.split_at(FRAME_HEADER_LEN);
        let page_number = be32(header, 0);
        if page_number == 0 || &header[8..16] != salts {
            break;
        }
        let sum = checksum(big_endian, checksum(big_endian, seed, &header[..8]), data);
        if sum != (be32(header, 16), be32(header, 20)) {
            break;
        }
        seed = sum;
        frames.push((page_number, offset + FRAME_HEADER_LEN));
        let commit_pages = be32(header, 4);
        if commit_pages != 0 {
            committed_len = frames.len();
            db_pages = commit_pages;
        }
        offset += frame_len;
    }
    frames.truncate(committed_len);
    if frames.is_empty() {
        return Ok(None);
    }
    Ok(Some(Committed { frames, db_pages }))
}

/// Builds the database image as SQLite would see it with the WAL applied.
/// The buffer is allocated once at its final size so no unzeroed copy is left behind.
pub fn build_image(
    main: &[u8],
    wal: Option<&[u8]>,
    max_image: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let page_size = page_size(main)?;
    let committed = match wal {
        Some(wal) => committed_frames(wal, page_size)?.map(|c| (wal, c)),
        None => None,
    };
    let total = match &committed {
        Some((_, c)) => usize::try_from(c.db_pages)
            .ok()
            .and_then(|pages| pages.checked_mul(page_size))
            .ok_or(ErrorCode::VaultFormatChanged)?,
        None => main.len(),
    };
    if total > max_image || total == 0 {
        return Err(ErrorCode::VaultFormatChanged);
    }

    let mut image = Zeroizing::new(Vec::with_capacity(total));
    image.extend_from_slice(&main[..main.len().min(total)]);
    image.resize(total, 0);

    if let Some((wal, committed)) = committed {
        for (page_number, data_offset) in committed.frames {
            if page_number > committed.db_pages {
                continue;
            }
            let start = usize::try_from(page_number - 1)
                .ok()
                .and_then(|n| n.checked_mul(page_size))
                .ok_or(ErrorCode::VaultFormatChanged)?;
            let dest = image
                .get_mut(start..start + page_size)
                .ok_or(ErrorCode::VaultFormatChanged)?;
            let src = wal
                .get(data_offset..data_offset + page_size)
                .ok_or(ErrorCode::VaultFormatChanged)?;
            dest.copy_from_slice(src);
        }
    }
    Ok(image)
}
