//! Read-only parser for the subset of the SQLite file format needed to read
//! plain rowid tables from an in-memory image. Format reference:
//! https://www.sqlite.org/fileformat2.html
use std::fmt;

use zeroize::Zeroizing;

use crate::error::{ErrorCode, Result};

const MAGIC: &[u8; 16] = b"SQLite format 3\0";
const HEADER_LEN: usize = 100;
const MIN_USABLE: usize = 480;
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_DEPTH: usize = 20;
const MAX_COLUMNS: usize = 64;
const TABLE_LEAF: u8 = 0x0D;
const TABLE_INTERIOR: u8 = 0x05;
const ENCODING_UTF8: u32 = 1;

fn bad<T>() -> Result<T> {
    Err(ErrorCode::VaultFormatChanged)
}

/// One decoded record column. `Debug` prints only the variant: contents can be secret.
#[derive(Clone, Copy, PartialEq)]
pub enum Column<'a> {
    Null,
    Int(i64),
    Real(f64),
    Text(&'a str),
    Blob(&'a [u8]),
}

impl fmt::Debug for Column<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "Null",
            Self::Int(_) => "Int",
            Self::Real(_) => "Real",
            Self::Text(_) => "Text",
            Self::Blob(_) => "Blob",
        })
    }
}

pub struct Image<'a> {
    data: &'a [u8],
    page_size: usize,
    usable: usize,
    page_count: usize,
}

fn be16(bytes: &[u8], offset: usize) -> Result<usize> {
    match bytes.get(offset..offset + 2) {
        Some(b) => Ok(usize::from(u16::from_be_bytes([b[0], b[1]]))),
        None => bad(),
    }
}

fn be32(bytes: &[u8], offset: usize) -> Result<u32> {
    match bytes.get(offset..offset + 4) {
        Some(b) => Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
        None => bad(),
    }
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for i in 0..8 {
        let byte = *buf.get(i)?;
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    let last = *buf.get(8)?;
    Some(((value << 8) | u64::from(last), 9))
}

fn varint(buf: &[u8]) -> Result<(u64, usize)> {
    read_varint(buf).ok_or(ErrorCode::VaultFormatChanged)
}

fn local_payload_size(payload: usize, usable: usize) -> usize {
    let max_local = usable - 35;
    if payload <= max_local {
        return payload;
    }
    let min_local = (usable - 12) * 32 / 255 - 23;
    let k = min_local + (payload - min_local) % (usable - 4);
    if k <= max_local {
        k
    } else {
        min_local
    }
}

fn serial_size(serial: u64) -> Result<usize> {
    Ok(match serial {
        0 | 8 | 9 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        10 | 11 => return bad(),
        n => {
            let len = if n % 2 == 0 {
                (n - 12) / 2
            } else {
                (n - 13) / 2
            };
            usize::try_from(len)
                .ok()
                .filter(|&l| l <= MAX_PAYLOAD)
                .ok_or(ErrorCode::VaultFormatChanged)?
        }
    })
}

fn parse_record(payload: &[u8]) -> Result<Vec<Column<'_>>> {
    let (header_size, used) = varint(payload)?;
    let header_size = usize::try_from(header_size).map_err(|_| ErrorCode::VaultFormatChanged)?;
    if header_size < used || header_size > payload.len() {
        return bad();
    }
    let mut serials = Vec::new();
    let mut pos = used;
    while pos < header_size {
        let (serial, len) = varint(&payload[pos..header_size])?;
        pos += len;
        serials.push(serial);
        if serials.len() > MAX_COLUMNS {
            return bad();
        }
    }
    let mut columns = Vec::with_capacity(serials.len());
    let mut offset = header_size;
    for serial in serials {
        let size = serial_size(serial)?;
        let end = offset
            .checked_add(size)
            .ok_or(ErrorCode::VaultFormatChanged)?;
        let body = payload
            .get(offset..end)
            .ok_or(ErrorCode::VaultFormatChanged)?;
        offset = end;
        columns.push(match serial {
            0 => Column::Null,
            1..=6 => {
                let mut v: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
                for &b in body {
                    v = (v << 8) | i64::from(b);
                }
                Column::Int(v)
            }
            7 => {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(body);
                Column::Real(f64::from_be_bytes(raw))
            }
            8 => Column::Int(0),
            9 => Column::Int(1),
            n if n % 2 == 0 => Column::Blob(body),
            _ => {
                Column::Text(std::str::from_utf8(body).map_err(|_| ErrorCode::VaultFormatChanged)?)
            }
        });
    }
    Ok(columns)
}

enum Payload<'a> {
    Local(&'a [u8]),
    Assembled(Zeroizing<Vec<u8>>),
}

impl Payload<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Local(b) => b,
            Self::Assembled(b) => b,
        }
    }
}

impl<'a> Image<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_LEN || !data.starts_with(MAGIC) {
            return bad();
        }
        let raw = be16(data, 16)?;
        let page_size = if raw == 1 { 65536 } else { raw };
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return bad();
        }
        let reserved = usize::from(data[20]);
        let usable = page_size - reserved;
        if usable < MIN_USABLE {
            return bad();
        }
        if be32(data, 56)? != ENCODING_UTF8 {
            return bad();
        }
        if data.len() % page_size != 0 {
            return bad();
        }
        Ok(Self {
            data,
            page_size,
            usable,
            page_count: data.len() / page_size,
        })
    }

    fn page(&self, number: usize) -> Result<&'a [u8]> {
        if number < 1 || number > self.page_count {
            return bad();
        }
        let start = (number - 1) * self.page_size;
        self.data
            .get(start..start + self.page_size)
            .ok_or(ErrorCode::VaultFormatChanged)
    }

    fn payload(&self, cell: &'a [u8], total: usize, visited: &mut [bool]) -> Result<Payload<'a>> {
        let local = local_payload_size(total, self.usable);
        if local == total {
            return cell
                .get(..total)
                .map(Payload::Local)
                .ok_or(ErrorCode::VaultFormatChanged);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(cell.get(..local).ok_or(ErrorCode::VaultFormatChanged)?);
        let mut next = be32(cell, local)? as usize;
        while out.len() < total {
            if next < 2 || next > self.page_count || visited[next] {
                return bad();
            }
            visited[next] = true;
            let page = self.page(next)?;
            let take = (total - out.len()).min(self.usable - 4);
            out.extend_from_slice(page.get(4..4 + take).ok_or(ErrorCode::VaultFormatChanged)?);
            next = be32(page, 0)? as usize;
        }
        Ok(Payload::Assembled(out))
    }

    /// Calls `f(rowid, columns)` for every row of the table rooted at `root`, in rowid order.
    pub fn scan<F>(&self, root: u32, mut f: F) -> Result<()>
    where
        F: FnMut(i64, &[Column<'_>]) -> Result<()>,
    {
        let root = usize::try_from(root).map_err(|_| ErrorCode::VaultFormatChanged)?;
        let mut visited = vec![false; self.page_count + 1];
        let mut stack = vec![(root, 0usize)];
        while let Some((number, depth)) = stack.pop() {
            if depth > MAX_DEPTH || number < 1 || number > self.page_count || visited[number] {
                return bad();
            }
            visited[number] = true;
            let page = self.page(number)?;
            let header = if number == 1 { HEADER_LEN } else { 0 };
            let kind = *page.get(header).ok_or(ErrorCode::VaultFormatChanged)?;
            let cell_count = be16(page, header + 3)?;
            match kind {
                TABLE_LEAF => {
                    let array = header + 8;
                    self.check_array(array, cell_count)?;
                    for i in 0..cell_count {
                        let cell = self.cell(page, array, i)?;
                        let (total, a) = varint(cell)?;
                        let (rowid, b) = varint(&cell[a..])?;
                        let total = usize::try_from(total)
                            .ok()
                            .filter(|&t| t <= MAX_PAYLOAD)
                            .ok_or(ErrorCode::VaultFormatChanged)?;
                        let payload = self.payload(&cell[a + b..], total, &mut visited)?;
                        let columns = parse_record(payload.bytes())?;
                        f(rowid as i64, &columns)?;
                    }
                }
                TABLE_INTERIOR => {
                    let array = header + 12;
                    self.check_array(array, cell_count)?;
                    let mut children = Vec::with_capacity(cell_count + 1);
                    for i in 0..cell_count {
                        let cell = self.cell(page, array, i)?;
                        let child = be32(cell, 0)? as usize;
                        varint(cell.get(4..).ok_or(ErrorCode::VaultFormatChanged)?)?;
                        children.push(child);
                    }
                    children.push(be32(page, header + 8)? as usize);
                    for child in children.into_iter().rev() {
                        if child < 2 || child > self.page_count {
                            return bad();
                        }
                        stack.push((child, depth + 1));
                    }
                }
                _ => return bad(),
            }
        }
        Ok(())
    }

    fn check_array(&self, array: usize, cell_count: usize) -> Result<()> {
        match cell_count.checked_mul(2).and_then(|n| n.checked_add(array)) {
            Some(end) if end <= self.usable => Ok(()),
            _ => bad(),
        }
    }

    fn cell(&self, page: &'a [u8], array: usize, index: usize) -> Result<&'a [u8]> {
        let pointer = be16(page, array + 2 * index)?;
        let min = array + 2 * (index + 1);
        if pointer < min || pointer >= self.usable {
            return bad();
        }
        page.get(pointer..self.usable)
            .ok_or(ErrorCode::VaultFormatChanged)
    }

    /// Root page of the `sqlite_schema` entry with `type == "table"` and this name.
    pub fn table_root(&self, name: &str) -> Result<Option<u32>> {
        let mut found = None;
        self.scan(1, |_, columns| {
            let [Column::Text(kind), Column::Text(entry), _, root, ..] = columns else {
                return bad();
            };
            if *kind == "table" && *entry == name && found.is_none() {
                let Column::Int(root) = root else {
                    return bad();
                };
                let root = u32::try_from(*root).map_err(|_| ErrorCode::VaultFormatChanged)?;
                if root < 2 || root as usize > self.page_count {
                    return bad();
                }
                found = Some(root);
            }
            Ok(())
        })?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_bytes(mut v: u64) -> Vec<u8> {
        if v > 0x00ff_ffff_ffff_ffff {
            let mut out = vec![0u8; 9];
            out[8] = (v & 0xff) as u8;
            v >>= 8;
            for i in (0..8).rev() {
                out[i] = ((v & 0x7f) as u8) | 0x80;
                v >>= 7;
            }
            return out;
        }
        let mut groups = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            groups.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        groups.reverse();
        groups
    }

    #[test]
    fn varint_edge_cases() {
        assert_eq!(read_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_varint(&[0x7f]), Some((127, 1)));
        assert_eq!(read_varint(&[0x81, 0x00]), Some((128, 2)));
        assert_eq!(read_varint(&[0xff, 0x7f]), Some((16383, 2)));
        assert_eq!(read_varint(&[0xff; 9]), Some((u64::MAX, 9)));
        assert_eq!(
            read_varint(&[0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            Some((1 << 57, 9))
        );
        assert_eq!(read_varint(&[0x81]), None);
        assert_eq!(read_varint(&[0xff; 8]), None);
        assert_eq!(read_varint(&[]), None);
        assert_eq!(read_varint(&[0x05, 0xff]), Some((5, 1)));
    }

    #[test]
    fn varint_roundtrip() {
        for v in [
            0,
            1,
            127,
            128,
            300,
            1 << 20,
            1 << 35,
            (1 << 56) - 1,
            1 << 56,
            u64::MAX,
        ] {
            let bytes = varint_bytes(v);
            assert_eq!(read_varint(&bytes), Some((v, bytes.len())), "{v}");
        }
    }

    fn record(serials: &[u64], body: &[u8]) -> Vec<u8> {
        let mut header: Vec<u8> = serials.iter().flat_map(|s| varint_bytes(*s)).collect();
        let size = u8::try_from(header.len() + 1).unwrap();
        header.insert(0, size);
        header.extend_from_slice(body);
        header
    }

    #[test]
    fn every_serial_type() {
        let mut body = Vec::new();
        body.push(0xFE);
        body.extend_from_slice(&[0xFF, 0xFE]);
        body.extend_from_slice(&[0x80, 0x00, 0x00]);
        body.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        body.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]);
        body.extend_from_slice(&i64::MIN.to_be_bytes());
        body.extend_from_slice(&1.5f64.to_be_bytes());
        body.extend_from_slice(&[1, 2, 3]);
        body.extend_from_slice(b"hi");
        let rec = record(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 18, 17], &body);
        let cols = parse_record(&rec).unwrap();
        assert_eq!(
            cols,
            vec![
                Column::Null,
                Column::Int(-2),
                Column::Int(-2),
                Column::Int(-8_388_608),
                Column::Int(65_536),
                Column::Int(-2),
                Column::Int(i64::MIN),
                Column::Real(1.5),
                Column::Int(0),
                Column::Int(1),
                Column::Blob(&[1, 2, 3]),
                Column::Text("hi"),
            ]
        );
    }

    #[test]
    fn invalid_serial_types_and_bodies_are_rejected() {
        assert!(parse_record(&record(&[10], &[])).is_err());
        assert!(parse_record(&record(&[11], &[])).is_err());
        assert!(parse_record(&record(&[15], &[0xC3])).is_err());
        assert!(parse_record(&record(&[15], &[0xC3, 0x28])).is_err());
        assert!(parse_record(&record(&[4], &[1, 2, 3])).is_err());
        assert!(parse_record(&[0x09, 0x01]).is_err());
        assert!(parse_record(&[]).is_err());
        let mut many = vec![66u8];
        many.extend(std::iter::repeat_n(8u8, 65));
        assert!(parse_record(&many).is_err());
    }

    #[test]
    fn overflow_local_size_matches_spec() {
        for usable in [480usize, 512, 1024, 4096, 65536] {
            let x = usable - 35;
            let m = ((usable - 12) * 32 / 255) - 23;
            for p in [0, 1, x - 1, x, x + 1, x + 100, 3 * usable, 200_000, 1 << 20] {
                let expected = if p <= x {
                    p
                } else {
                    let k = m + ((p - m) % (usable - 4));
                    if k <= x {
                        k
                    } else {
                        m
                    }
                };
                assert_eq!(local_payload_size(p, usable), expected, "{usable} {p}");
            }
        }
        assert_eq!(local_payload_size(4062, 4096), 489);
        assert_eq!(local_payload_size(5000, 4096), 908);
    }

    const PS: usize = 512;

    fn db_header(pages: usize) -> Vec<u8> {
        let mut h = vec![0u8; PS];
        h[..16].copy_from_slice(MAGIC);
        h[16..18].copy_from_slice(&(PS as u16).to_be_bytes());
        h[56..60].copy_from_slice(&1u32.to_be_bytes());
        h[28..32].copy_from_slice(&(pages as u32).to_be_bytes());
        h
    }

    fn leaf(page: &mut [u8], offset: usize, cells: &[Vec<u8>]) {
        page[offset] = TABLE_LEAF;
        page[offset + 3..offset + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        let mut end = PS;
        for (i, cell) in cells.iter().enumerate() {
            end -= cell.len();
            page[end..end + cell.len()].copy_from_slice(cell);
            let at = offset + 8 + 2 * i;
            page[at..at + 2].copy_from_slice(&(end as u16).to_be_bytes());
        }
    }

    fn interior(page: &mut [u8], children: &[u32], right: u32) {
        page[0] = TABLE_INTERIOR;
        page[3..5].copy_from_slice(&(children.len() as u16).to_be_bytes());
        page[8..12].copy_from_slice(&right.to_be_bytes());
        for (i, child) in children.iter().enumerate() {
            let cell = [&child.to_be_bytes()[..], &[i as u8 + 1]].concat();
            let end = PS - (i + 1) * cell.len();
            page[end..end + cell.len()].copy_from_slice(&cell);
            let at = 12 + 2 * i;
            page[at..at + 2].copy_from_slice(&(end as u16).to_be_bytes());
        }
    }

    fn schema_cell(root: u8) -> Vec<u8> {
        let body = [&b"table"[..], b"t", b"t", &[root], b"x"].concat();
        let rec = record(&[23, 15, 15, 1, 15], &body);
        [varint_bytes(rec.len() as u64), vec![1], rec].concat()
    }

    fn row_cell(rowid: u8, text: &str) -> Vec<u8> {
        let rec = record(&[13 + 2 * text.len() as u64], text.as_bytes());
        [varint_bytes(rec.len() as u64), vec![rowid], rec].concat()
    }

    fn image(pages: Vec<Vec<u8>>) -> Vec<u8> {
        let mut first = db_header(pages.len() + 1);
        leaf(&mut first, HEADER_LEN, &[schema_cell(2)]);
        let mut out = first;
        for p in pages {
            out.extend(p);
        }
        out
    }

    fn rows(img: &[u8], root: u32) -> Result<Vec<(i64, String)>> {
        let image = Image::parse(img)?;
        let mut out = Vec::new();
        image.scan(root, |rowid, cols| {
            let [Column::Text(t)] = cols else {
                return bad();
            };
            out.push((rowid, (*t).to_string()));
            Ok(())
        })?;
        Ok(out)
    }

    #[test]
    fn leaf_and_interior_scan_in_order() {
        let mut p2 = vec![0u8; PS];
        interior(&mut p2, &[3], 4);
        let mut p3 = vec![0u8; PS];
        leaf(&mut p3, 0, &[row_cell(1, "a"), row_cell(2, "b")]);
        let mut p4 = vec![0u8; PS];
        leaf(&mut p4, 0, &[row_cell(3, "c")]);
        let img = image(vec![p2, p3, p4]);
        let parsed = Image::parse(&img).unwrap();
        assert_eq!(parsed.table_root("t").unwrap(), Some(2));
        assert_eq!(parsed.table_root("other").unwrap(), None);
        assert_eq!(
            rows(&img, 2).unwrap(),
            vec![(1, "a".into()), (2, "b".into()), (3, "c".into())]
        );
    }

    #[test]
    fn cycles_and_out_of_range_pages_are_rejected() {
        let mut p2 = vec![0u8; PS];
        interior(&mut p2, &[2], 2);
        assert!(rows(&image(vec![p2]), 2).is_err());

        let mut p2 = vec![0u8; PS];
        interior(&mut p2, &[3], 3);
        let mut p3 = vec![0u8; PS];
        interior(&mut p3, &[2], 2);
        assert!(rows(&image(vec![p2, p3]), 2).is_err());

        let mut p2 = vec![0u8; PS];
        interior(&mut p2, &[99], 3);
        let mut p3 = vec![0u8; PS];
        leaf(&mut p3, 0, &[row_cell(1, "a")]);
        assert!(rows(&image(vec![p2, p3]), 2).is_err());

        let mut p2 = vec![0u8; PS];
        interior(&mut p2, &[1], 1);
        assert!(rows(&image(vec![p2]), 2).is_err());
        assert!(rows(&image(vec![vec![0u8; PS]]), 9).is_err());
        assert!(rows(&image(vec![vec![0u8; PS]]), 2).is_err());
    }

    #[test]
    fn excessive_depth_is_rejected() {
        let mut pages = Vec::new();
        for n in 0..25u32 {
            let mut p = vec![0u8; PS];
            interior(&mut p, &[], n + 3);
            pages.push(p);
        }
        let mut last = vec![0u8; PS];
        leaf(&mut last, 0, &[row_cell(1, "a")]);
        pages.push(last);
        assert!(rows(&image(pages), 2).is_err());
    }

    #[test]
    fn bad_header_fields_are_rejected() {
        let good = image(vec![{
            let mut p = vec![0u8; PS];
            leaf(&mut p, 0, &[row_cell(1, "a")]);
            p
        }]);
        assert!(Image::parse(&good).is_ok());

        let mut v = good.clone();
        v[0] = b'X';
        assert!(Image::parse(&v).is_err());

        for raw in [0u16, 256, 1000, 3] {
            let mut v = good.clone();
            v[16..18].copy_from_slice(&raw.to_be_bytes());
            assert!(Image::parse(&v).is_err(), "page size {raw}");
        }

        let mut v = good.clone();
        v[20] = 40;
        assert!(Image::parse(&v).is_err());

        for enc in [0u32, 2, 3] {
            let mut v = good.clone();
            v[56..60].copy_from_slice(&enc.to_be_bytes());
            assert!(Image::parse(&v).is_err(), "encoding {enc}");
        }

        assert!(Image::parse(&good[..good.len() - 1]).is_err());
        assert!(Image::parse(&good[..50]).is_err());
    }

    #[test]
    fn index_pages_and_bad_cell_pointers_are_rejected() {
        let mut p2 = vec![0u8; PS];
        leaf(&mut p2, 0, &[row_cell(1, "a")]);
        p2[0] = 0x0A;
        assert!(rows(&image(vec![p2]), 2).is_err());

        let mut p2 = vec![0u8; PS];
        leaf(&mut p2, 0, &[row_cell(1, "a")]);
        p2[8..10].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(rows(&image(vec![p2]), 2).is_err());

        let mut p2 = vec![0u8; PS];
        leaf(&mut p2, 0, &[row_cell(1, "a")]);
        p2[3..5].copy_from_slice(&0xFFFFu16.to_be_bytes());
        assert!(rows(&image(vec![p2]), 2).is_err());
    }
}
