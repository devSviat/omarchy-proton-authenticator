use std::io::{self, Cursor, Read, Seek};

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const DB_HEADER_LEN: usize = 100;
const WAL_HEADER_LEN: usize = 32;
const FRAME_HEADER_LEN: usize = 24;
const WAL_MAGIC_LE: u32 = 0x377f_0682;
const WAL_MAGIC_BE: u32 = 0x377f_0683;
const WAL_VERSION: u32 = 3_007_000;

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
    for c in data.as_chunks::<8>().0 {
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

/// Result of one sequential walk over the WAL.
struct Walk {
    /// Frames that passed the salt and cumulative checksum checks.
    valid: usize,
    /// Frame count up to and including the last valid commit frame.
    committed: usize,
    db_pages: u32,
}

fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(_) => Err(ErrorCode::Internal),
    }
}

/// Walks the WAL from its start, checking the header and every frame's salts
/// and cumulative checksum, and calls `on_frame` for at most `limit` valid
/// frames. Only one frame is buffered at a time. `Ok(None)` means the WAL has
/// no usable header and SQLite would ignore it.
fn walk<R: Read>(
    reader: &mut R,
    page_size: usize,
    limit: usize,
    mut on_frame: impl FnMut(u32, &[u8]) -> Result<()>,
) -> Result<Option<Walk>> {
    let mut header = [0u8; WAL_HEADER_LEN];
    if !read_full(reader, &mut header)? {
        return Ok(None);
    }
    let big_endian = match be32(&header, 0) {
        WAL_MAGIC_LE => false,
        WAL_MAGIC_BE => true,
        _ => return Ok(None),
    };
    if be32(&header, 4) != WAL_VERSION {
        return Err(ErrorCode::VaultFormatChanged);
    }
    if checksum(big_endian, (0, 0), &header[..24]) != (be32(&header, 24), be32(&header, 28)) {
        return Ok(None);
    }
    if usize::try_from(be32(&header, 8)).ok() != Some(page_size) {
        return Err(ErrorCode::VaultFormatChanged);
    }

    let salts = &header[16..24];
    let mut seed = (be32(&header, 24), be32(&header, 28));
    let mut frame = Zeroizing::new(vec![0u8; FRAME_HEADER_LEN + page_size]);
    let mut walk = Walk {
        valid: 0,
        committed: 0,
        db_pages: 0,
    };
    while walk.valid < limit && read_full(reader, &mut frame)? {
        let (head, data) = frame.split_at(FRAME_HEADER_LEN);
        let page_number = be32(head, 0);
        if page_number == 0 || &head[8..16] != salts {
            break;
        }
        let sum = checksum(big_endian, checksum(big_endian, seed, &head[..8]), data);
        if sum != (be32(head, 16), be32(head, 20)) {
            break;
        }
        seed = sum;
        walk.valid += 1;
        on_frame(page_number, data)?;
        let commit_pages = be32(head, 4);
        if commit_pages != 0 {
            walk.committed = walk.valid;
            walk.db_pages = commit_pages;
        }
    }
    Ok(Some(walk))
}

/// Outcome of applying a WAL to an image.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// The image now matches what SQLite would see.
    Done,
    /// The two passes over the WAL disagreed: it changed while being read.
    Changed,
}

/// Applies the committed WAL frames to `image`, which holds the main file
/// and was allocated with its final capacity. The WAL is read twice: pass 1
/// finds the last valid commit, pass 2 copies frames up to it. Only one frame
/// is held in memory, so the WAL can be far larger than the image.
///
/// The image is resized within its capacity, never reallocated, so no
/// unzeroized copy of its contents is left behind.
pub fn apply_wal<R: Read + Seek>(
    image: &mut Zeroizing<Vec<u8>>,
    wal: Option<&mut R>,
    max_image: usize,
) -> Result<Applied> {
    let page_size = page_size(image)?;
    let committed = match wal {
        Some(wal) => {
            wal.rewind().map_err(|_| ErrorCode::Internal)?;
            match walk(wal, page_size, usize::MAX, |_, _| Ok(()))? {
                Some(w) if w.committed > 0 => Some((wal, w)),
                _ => None,
            }
        }
        None => None,
    };
    let total = match &committed {
        Some((_, w)) => usize::try_from(w.db_pages)
            .ok()
            .and_then(|pages| pages.checked_mul(page_size))
            .ok_or(ErrorCode::VaultFormatChanged)?,
        None => image.len(),
    };
    if total > max_image || total > image.capacity() || total == 0 {
        return Err(ErrorCode::VaultFormatChanged);
    }
    image.resize(total, 0);

    let Some((wal, plan)) = committed else {
        return Ok(Applied::Done);
    };
    wal.rewind().map_err(|_| ErrorCode::Internal)?;
    let replay = walk(wal, page_size, plan.committed, |page_number, data| {
        if page_number > plan.db_pages {
            return Ok(());
        }
        let start = usize::try_from(page_number - 1)
            .ok()
            .and_then(|n| n.checked_mul(page_size))
            .ok_or(ErrorCode::VaultFormatChanged)?;
        image
            .get_mut(start..start + page_size)
            .ok_or(ErrorCode::VaultFormatChanged)?
            .copy_from_slice(data);
        Ok(())
    })?;
    match replay {
        Some(w) if w.valid == plan.committed && w.db_pages == plan.db_pages => Ok(Applied::Done),
        _ => Ok(Applied::Changed),
    }
}

/// Builds the database image from in-memory files as SQLite would see it with
/// the WAL applied, allocating only what the committed size needs.
pub fn build_image(
    main: &[u8],
    wal: Option<&[u8]>,
    max_image: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if main.len() > max_image {
        return Err(ErrorCode::VaultFormatChanged);
    }
    let page_size = page_size(main)?;
    let committed_len = match wal {
        Some(wal) => walk(&mut Cursor::new(wal), page_size, usize::MAX, |_, _| Ok(()))?
            .filter(|w| w.committed > 0)
            .and_then(|w| usize::try_from(w.db_pages).ok()?.checked_mul(page_size)),
        None => None,
    };
    let capacity = committed_len
        .filter(|&len| len <= max_image)
        .map_or(main.len(), |len| len.max(main.len()));
    let mut image = Zeroizing::new(Vec::with_capacity(capacity));
    image.extend_from_slice(main);
    let mut cursor = wal.map(Cursor::new);
    match apply_wal(&mut image, cursor.as_mut(), max_image)? {
        Applied::Done => Ok(image),
        Applied::Changed => Err(ErrorCode::Internal),
    }
}
