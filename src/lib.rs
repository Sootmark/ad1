//! AccessData AD1 logical images: the "custom content images" FTK Imager
//! writes when an examiner exports chosen files and folders instead of a
//! whole disk. Written from the public notes on the format (P. C.
//! Bjelland's "AccessData Format (AD1)") and checked on real images.
//!
//! An image is one or more segment files (`.ad1`, `.ad2`, …), each opening
//! with a 512-byte margin (`ADSEGMENTEDFILE`: segment number, count, size).
//! Addresses skip the margins, so the segments' payloads read as one
//! stream. It starts with the image header (`ADLOGICALIMAGE`: version, zlib
//! chunk size, the first item, the source's name), then the items: a tree
//! of folders and files, each with a chain of metadata (category, key and a
//! text value: sizes, timestamps, hashes, file system attributes and
//! security) and, for content, a table of zlib chunks.
//!
//! Every address is bounds-checked and every walk guarded against cycles:
//! a damaged image gives errors for what it touches, never a panic.
//! Encrypted images (`ADCRYPT`) are recognised and refused.

use core::fmt;
use std::collections::HashSet;
use std::io::{self, Read, Seek, SeekFrom};

/// This crate's version, for provenance.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Every segment's margin.
const MARGIN: u64 = 512;
const SEGMENT_SIGNATURE: &[u8] = b"ADSEGMENTEDFILE";
const IMAGE_SIGNATURE: &[u8] = b"ADLOGICALIMAGE";
const ENCRYPTED_SIGNATURE: &[u8] = b"ADCRYPT";
/// Fixed part of an item's header, before its name.
const ITEM_HEADER: usize = 48;
/// Fixed part of a metadata entry, before its value.
const METADATA_HEADER: usize = 20;
/// Limits beyond which a structure is damage, not data.
const MAX_ITEMS: usize = 20_000_000;
const MAX_ATTRIBUTES: usize = 10_000;
const MAX_NAME: usize = 1 << 16;
const MAX_VALUE: usize = 1 << 20;
const MAX_CHUNK_SIZE: u32 = 1 << 26;

/// Item type of a folder.
pub const FOLDER: u32 = 5;

/// Metadata category of hashes and other text.
pub const TEXT: u32 = 1;
/// Metadata category of sizes and other numbers.
pub const NUMBER: u32 = 3;
/// Metadata category of flags (`true`/`false`).
pub const FLAG: u32 = 4;
/// Metadata category of timestamps.
pub const TIME: u32 = 5;

/// Metadata keys (with their category) that are understood.
pub mod key {
    /// MD5 of the content ([`super::TEXT`]).
    pub const MD5: u32 = 0x5001;
    /// SHA-1 of the content ([`super::TEXT`]).
    pub const SHA1: u32 = 0x5002;
    /// Logical size ([`super::NUMBER`]).
    pub const SIZE: u32 = 0x3;
    /// Last access ([`super::TIME`]).
    pub const ACCESSED: u32 = 0x7;
    /// Creation ([`super::TIME`]).
    pub const CREATED: u32 = 0x8;
    /// Last modification ([`super::TIME`]).
    pub const MODIFIED: u32 = 0x9;
    /// NTFS: last change of the file record ([`super::TIME`]).
    pub const RECORD_CHANGED: u32 = 0xa002;
}

/// Why an image, or part of it, couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Address in the image (past the margins) where it went wrong.
    pub address: u64,
    /// What went wrong.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at address {})", self.reason, self.address)
    }
}

impl std::error::Error for Error {}

fn error(address: u64, reason: impl Into<String>) -> Error {
    Error {
        address,
        reason: reason.into(),
    }
}

/// One metadata entry of an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Its category ([`TEXT`], [`NUMBER`], [`FLAG`], [`TIME`], …).
    pub category: u32,
    /// Its key (see [`key`]).
    pub key: u32,
    /// Its value, as the image stores it: text.
    pub value: String,
}

/// A file or folder in the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its name.
    pub name: String,
    /// Its path from the image's top, `/`-separated.
    pub path: String,
    /// Its parent's index in [`Image::items`].
    pub parent: Option<usize>,
    /// Its type: 0 a file, [`FOLDER`], other values for special entries.
    pub kind: u32,
    /// Its content's size in bytes.
    pub size: u64,
    /// Its metadata, in the image's order.
    pub attributes: Vec<Attribute>,
    /// Its address in the image.
    pub address: u64,
    /// Where its chunk table is; 0 when it has no content.
    chunks: u64,
}

impl Item {
    /// Whether it's a folder.
    #[must_use]
    pub fn is_folder(&self) -> bool {
        self.kind == FOLDER
    }

    /// Whether it has content to read.
    #[must_use]
    pub fn has_content(&self) -> bool {
        self.chunks != 0
    }

    /// The value of an attribute, if present.
    #[must_use]
    pub fn attribute(&self, category: u32, key: u32) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.category == category && a.key == key)
            .map(|a| a.value.as_str())
    }

    /// The MD5 of its content recorded at acquisition, lowercase hex.
    #[must_use]
    pub fn md5(&self) -> Option<&str> {
        self.attribute(TEXT, key::MD5)
    }

    /// The SHA-1 of its content recorded at acquisition, lowercase hex.
    #[must_use]
    pub fn sha1(&self) -> Option<&str> {
        self.attribute(TEXT, key::SHA1)
    }

    /// A timestamp ([`key::ACCESSED`], [`key::CREATED`], …) as a FILETIME
    /// (UTC, 100 ns since 1601), when present and readable.
    #[must_use]
    pub fn time(&self, key: u32) -> Option<u64> {
        filetime(self.attribute(TIME, key)?)
    }
}

/// `YYYYMMDDTHHMMSS[.ffffff]` (UTC, as FTK writes it) as a FILETIME.
fn filetime(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |range: core::ops::Range<usize>| -> Option<i64> {
        let part = whole.get(range)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if whole.len() != 15 || whole.as_bytes()[8] != b'T' {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (hour, minute, second) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let ticks = if fraction.is_empty() {
        0
    } else {
        if fraction.len() > 7 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // To 100 ns: `.918811` is 9,188,110 ticks.
        let padded = format!("{fraction:0<7}");
        padded.parse::<i64>().ok()?
    };
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second + 11_644_473_600;
    u64::try_from(seconds.checked_mul(10_000_000)? + ticks).ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// An opened image.
#[derive(Debug)]
pub struct Image<R> {
    segments: Vec<R>,
    segment_size: u64,
    /// Format version (3 or 4).
    pub version: u32,
    /// Size of the zlib chunks content is stored in.
    pub chunk_size: u32,
    /// The source's name as the image records it (`Custom Content
    /// Image([Multi])`, a volume's name…).
    pub source: String,
    /// Every item, each folder before what it holds.
    pub items: Vec<Item>,
    /// Items and metadata that couldn't be read, and why.
    pub problems: Vec<String>,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

impl<R: Read + Seek> Image<R> {
    /// Open an image from its segments, in order.
    ///
    /// # Errors
    /// When a segment isn't one of this image (signature, number, count),
    /// the image is encrypted, or its header can't be read.
    pub fn open(mut segments: Vec<R>) -> Result<Self, Error> {
        let count = segments.len();
        if count == 0 {
            return Err(error(0, "no segments"));
        }
        let mut segment_size = 0;
        for (index, segment) in segments.iter_mut().enumerate() {
            let mut margin = [0; MARGIN as usize];
            segment
                .seek(SeekFrom::Start(0))
                .and_then(|_| segment.read_exact(&mut margin))
                .map_err(|e| error(0, format!("segment {}: {e}", index + 1)))?;
            if margin.starts_with(ENCRYPTED_SIGNATURE) {
                return Err(error(0, "encrypted AD1 image (not supported)"));
            }
            if !margin.starts_with(SEGMENT_SIGNATURE) {
                return Err(error(
                    0,
                    format!("segment {}: not an AD1 segment", index + 1),
                ));
            }
            let number = u32_at(&margin, 24).unwrap_or(0) as usize;
            let of = u32_at(&margin, 28).unwrap_or(0) as usize;
            if number != index + 1 || of != count {
                return Err(error(
                    0,
                    format!("segment {} says it is {number} of {of}", index + 1),
                ));
            }
            if index == 0 {
                // The segment's whole size, margin included.
                segment_size = u64_at(&margin, 32).unwrap_or(0).saturating_sub(MARGIN);
            }
        }
        if segment_size == 0 {
            return Err(error(0, "segment size of 0"));
        }
        let mut image = Self {
            segments,
            segment_size,
            version: 0,
            chunk_size: 0,
            source: String::new(),
            items: Vec::new(),
            problems: Vec::new(),
        };
        let first = image.read_header()?;
        image.walk(first);
        Ok(image)
    }

    /// Read `buf.len()` bytes at `address`, across segments if need be.
    fn read_at(&mut self, address: u64, buf: &mut [u8]) -> Result<(), Error> {
        let mut done = 0;
        while done < buf.len() {
            let at = address + done as u64;
            let index = (at / self.segment_size) as usize;
            let within = at % self.segment_size;
            let wanted = ((self.segment_size - within) as usize).min(buf.len() - done);
            let segment = self
                .segments
                .get_mut(index)
                .ok_or_else(|| error(at, "address past the last segment"))?;
            segment
                .seek(SeekFrom::Start(MARGIN + within))
                .and_then(|_| segment.read_exact(&mut buf[done..done + wanted]))
                .map_err(|e| error(at, format!("read failed: {e}")))?;
            done += wanted;
        }
        Ok(())
    }

    fn bytes_at(&mut self, address: u64, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0; len];
        self.read_at(address, &mut buf)?;
        Ok(buf)
    }

    /// The image header; where the first item is.
    fn read_header(&mut self) -> Result<u64, Error> {
        let header = self.bytes_at(0, 92)?;
        if !header.starts_with(IMAGE_SIGNATURE) {
            return Err(error(0, "no image header (ADLOGICALIMAGE)"));
        }
        let truncated = || error(0, "image header truncated");
        self.version = u32_at(&header, 16).ok_or_else(truncated)?;
        self.chunk_size = u32_at(&header, 24).ok_or_else(truncated)?;
        if self.chunk_size == 0 || self.chunk_size > MAX_CHUNK_SIZE {
            return Err(error(24, format!("zlib chunk size {}", self.chunk_size)));
        }
        let first = u64_at(&header, 36).ok_or_else(truncated)?;
        let name_len = (u32_at(&header, 44).ok_or_else(truncated)? as usize).min(MAX_NAME);
        let name_at = if self.version >= 4 {
            u64_at(&header, 52).ok_or_else(truncated)?
        } else {
            48
        };
        match self.bytes_at(name_at, name_len) {
            Ok(name) => self.source = text(&name),
            Err(e) => self.problems.push(format!("source name: {e}")),
        }
        Ok(first)
    }

    /// Read every item, depth first; a damaged item is a problem, and so
    /// is what it held.
    fn walk(&mut self, first: u64) {
        let mut seen = HashSet::new();
        let mut groups = vec![(first, None::<usize>)];
        while let Some((mut address, parent)) = groups.pop() {
            while address != 0 {
                if !seen.insert(address) {
                    self.problems
                        .push(format!("item at {address} reached twice"));
                    break;
                }
                if self.items.len() >= MAX_ITEMS {
                    self.problems.push(format!("more than {MAX_ITEMS} items"));
                    return;
                }
                match self.item(address, parent) {
                    Ok((item, next, child)) => {
                        let index = self.items.len();
                        self.items.push(item);
                        if child != 0 {
                            groups.push((child, Some(index)));
                        }
                        address = next;
                    }
                    Err(e) => {
                        self.problems.push(e.to_string());
                        break;
                    }
                }
            }
        }
    }

    /// The item at `address`, where its next sibling and first child are.
    fn item(&mut self, address: u64, parent: Option<usize>) -> Result<(Item, u64, u64), Error> {
        let header = self.bytes_at(address, ITEM_HEADER)?;
        let field = |at| u64_at(&header, at).unwrap_or(0);
        let (next, child, metadata, chunks, size) =
            (field(0), field(8), field(16), field(24), field(32));
        let kind = u32_at(&header, 40).unwrap_or(0);
        let name_len = u32_at(&header, 44).unwrap_or(0) as usize;
        if name_len > MAX_NAME {
            return Err(error(address, format!("item name of {name_len} bytes")));
        }
        let name = text(&self.bytes_at(address + ITEM_HEADER as u64, name_len)?);
        let path = match parent.and_then(|p| self.items.get(p)) {
            Some(p) => format!("{}/{name}", p.path),
            None => name.clone(),
        };
        let attributes = self.attributes(metadata);
        Ok((
            Item {
                name,
                path,
                parent,
                kind,
                size,
                attributes,
                address,
                chunks,
            },
            next,
            child,
        ))
    }

    /// The metadata chain starting at `address`.
    fn attributes(&mut self, mut address: u64) -> Vec<Attribute> {
        let mut attributes = Vec::new();
        let mut seen = HashSet::new();
        while address != 0 && attributes.len() < MAX_ATTRIBUTES && seen.insert(address) {
            let header = match self.bytes_at(address, METADATA_HEADER) {
                Ok(header) => header,
                Err(e) => {
                    self.problems.push(format!("metadata: {e}"));
                    break;
                }
            };
            let len = (u32_at(&header, 16).unwrap_or(0) as usize).min(MAX_VALUE);
            match self.bytes_at(address + METADATA_HEADER as u64, len) {
                Ok(value) => attributes.push(Attribute {
                    category: u32_at(&header, 8).unwrap_or(0),
                    key: u32_at(&header, 12).unwrap_or(0),
                    value: text(&value),
                }),
                Err(e) => {
                    self.problems.push(format!("metadata: {e}"));
                    break;
                }
            }
            address = u64_at(&header, 0).unwrap_or(0);
        }
        attributes
    }

    /// A reader over the content of item `index` (empty for items without
    /// any), decompressed a chunk at a time.
    ///
    /// # Errors
    /// When there's no such item, or its chunk table can't be read.
    pub fn content(&mut self, index: usize) -> Result<Content<'_, R>, Error> {
        let item = self
            .items
            .get(index)
            .ok_or_else(|| error(0, format!("no item {index}")))?;
        let (table_at, size) = (item.chunks, item.size);
        if table_at == 0 {
            return Ok(Content::empty(self));
        }
        let count = u64::from_le_bytes(
            self.bytes_at(table_at, 8)?
                .try_into()
                .map_err(|_| error(table_at, "chunk count"))?,
        );
        // Enough chunks for the size, and no more than it could need.
        let needed = size.div_ceil(u64::from(self.chunk_size));
        if count != needed && !(count == 1 && size == 0) {
            return Err(error(
                table_at,
                format!(
                    "{count} chunks for {size} bytes in chunks of {}",
                    self.chunk_size
                ),
            ));
        }
        let table = self.bytes_at(table_at + 8, (count as usize + 1) * 8)?;
        let bounds = table
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap_or_default()))
            .collect();
        Ok(Content {
            image: self,
            bounds,
            next: 0,
            buffer: Vec::new(),
            position: 0,
            remaining: size,
        })
    }
}

/// An item's content, decompressed as it's read.
#[derive(Debug)]
pub struct Content<'a, R> {
    image: &'a mut Image<R>,
    /// Chunk boundaries: chunk `i` spans `bounds[i]..bounds[i + 1]`.
    bounds: Vec<u64>,
    next: usize,
    buffer: Vec<u8>,
    position: usize,
    remaining: u64,
}

impl<'a, R: Read + Seek> Content<'a, R> {
    fn empty(image: &'a mut Image<R>) -> Self {
        Self {
            image,
            bounds: Vec::new(),
            next: 0,
            buffer: Vec::new(),
            position: 0,
            remaining: 0,
        }
    }

    /// Decompress the next chunk into the buffer.
    fn fill(&mut self) -> io::Result<()> {
        let (Some(&start), Some(&end)) =
            (self.bounds.get(self.next), self.bounds.get(self.next + 1))
        else {
            return Err(corrupt("content ends before its size"));
        };
        let chunk_size = self.image.chunk_size as usize;
        // A chunk can't compress to much more than its size.
        if end <= start || end - start > (chunk_size as u64) * 2 + 1024 {
            return Err(corrupt(format!("chunk {} spans {start}..{end}", self.next)));
        }
        let compressed = self
            .image
            .bytes_at(start, (end - start) as usize)
            .map_err(|e| corrupt(e.to_string()))?;
        self.buffer = common::deflate::zlib_decompress(&compressed, chunk_size)?;
        let expected = self.remaining.min(chunk_size as u64) as usize;
        if self.buffer.len() != expected {
            return Err(corrupt(format!(
                "chunk {} holds {} bytes, expected {expected}",
                self.next,
                self.buffer.len()
            )));
        }
        self.position = 0;
        self.next += 1;
        Ok(())
    }
}

fn corrupt(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

impl<R: Read + Seek> Read for Content<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position == self.buffer.len() {
            if self.remaining == 0 {
                return Ok(0);
            }
            self.fill()?;
        }
        let n = buf.len().min(self.buffer.len() - self.position);
        buf[..n].copy_from_slice(&self.buffer[self.position..self.position + n]);
        self.position += n;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Text as the image stores it (UTF-8), up to the first NUL.
fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_read_as_ftk_writes_them() {
        // 2017-09-29 08:45:11.680123 UTC (MFTECmd: ...11.6801233).
        assert_eq!(
            filetime("20170929T084511.680123"),
            Some(131_511_483_116_801_230)
        );
        assert_eq!(filetime("20190314T031656"), Some(131_970_070_160_000_000));
        assert_eq!(filetime("2019-03-14"), None);
        assert_eq!(filetime("20191314T031656"), None);
    }
}
