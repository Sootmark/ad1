//! Images written here, as FTK Imager lays them out (the layout checked on
//! its images in `tests/images.rs`): versions 3 and 4, folders and files,
//! content across several chunks and several segments, metadata, and
//! damage anywhere.

use std::io::{Cursor, Read};

use ad1::{key, Image, FOLDER, TEXT, TIME};

const CHUNK: usize = 1 << 16;

/// A zlib stream of stored blocks.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(65_535).collect()
    };
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&common::checksum::adler32(data).to_be_bytes());
    out
}

enum Node {
    Folder(&'static str, Vec<Node>),
    File(&'static str, Vec<u8>),
}

/// The image stream (past the margins) and the addresses it assigns.
struct Writer {
    stream: Vec<u8>,
}

impl Writer {
    fn put(&mut self, bytes: &[u8]) -> u64 {
        let at = self.stream.len() as u64;
        self.stream.extend_from_slice(bytes);
        at
    }

    fn patch(&mut self, at: u64, value: u64) {
        let at = at as usize;
        self.stream[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Write `nodes` as siblings; the first one's address.
    fn group(&mut self, nodes: &[Node], parent: u64) -> u64 {
        let mut first = 0;
        let mut previous: Option<u64> = None;
        for node in nodes {
            let (name, kind, data) = match node {
                Node::Folder(name, _) => (*name, FOLDER, None),
                Node::File(name, data) => (*name, 0, Some(data.as_slice())),
            };
            let at = self.stream.len() as u64;
            let mut header = vec![0; 48];
            header[32..40].copy_from_slice(&(data.map_or(0, <[u8]>::len) as u64).to_le_bytes());
            header[40..44].copy_from_slice(&kind.to_le_bytes());
            header[44..48].copy_from_slice(&(name.len() as u32).to_le_bytes());
            header.extend_from_slice(name.as_bytes());
            header.extend_from_slice(&parent.to_le_bytes());
            self.put(&header);
            if let Some(data) = data {
                let table = self.chunks(data);
                self.patch(at + 24, table);
            }
            let metadata = self.metadata(&[
                (
                    TEXT,
                    key::MD5,
                    format!("{:x}", md5(data.unwrap_or_default())),
                ),
                (TIME, key::MODIFIED, "20240212T101112.123456".to_owned()),
            ]);
            self.patch(at + 16, metadata);
            if let Node::Folder(_, children) = node {
                let child = self.group(children, at);
                self.patch(at + 8, child);
            }
            match previous {
                Some(p) => self.patch(p, at),
                None => first = at,
            }
            previous = Some(at);
        }
        first
    }

    fn chunks(&mut self, data: &[u8]) -> u64 {
        let pieces: Vec<Vec<u8>> = data.chunks(CHUNK).map(zlib).collect();
        let table = self.put(&(pieces.len() as u64).to_le_bytes());
        let mut at = table + 8 + 8 * (pieces.len() as u64 + 1);
        let mut bounds = Vec::new();
        for piece in &pieces {
            bounds.extend_from_slice(&at.to_le_bytes());
            at += piece.len() as u64;
        }
        bounds.extend_from_slice(&at.to_le_bytes());
        self.put(&bounds);
        for piece in &pieces {
            self.put(piece);
        }
        table
    }

    fn metadata(&mut self, entries: &[(u32, u32, String)]) -> u64 {
        let mut first = 0;
        let mut previous: Option<u64> = None;
        for (category, key, value) in entries {
            let mut entry = vec![0; 8];
            entry.extend_from_slice(&category.to_le_bytes());
            entry.extend_from_slice(&key.to_le_bytes());
            entry.extend_from_slice(&(value.len() as u32).to_le_bytes());
            entry.extend_from_slice(value.as_bytes());
            let at = self.put(&entry);
            match previous {
                Some(p) => self.patch(p, at),
                None => first = at,
            }
            previous = Some(at);
        }
        first
    }
}

fn md5(data: &[u8]) -> u128 {
    u128::from_be_bytes(common::md5::Md5::digest(data))
}

const SOURCE: &str = "Custom Content Image([Multi])";

/// A version 4 image of `tree`, in segments of `units` × 64 KiB of payload.
fn image(tree: &[Node], units: u32) -> Vec<Vec<u8>> {
    image_of_version(tree, units, 4)
}

/// Version 3 holds the source's name in the header; version 4 points to it.
fn image_of_version(tree: &[Node], units: u32, version: u32) -> Vec<Vec<u8>> {
    let mut writer = Writer {
        stream: vec![0; 92],
    };
    writer.stream[..14].copy_from_slice(b"ADLOGICALIMAGE");
    writer.stream[16..20].copy_from_slice(&version.to_le_bytes());
    writer.stream[24..28].copy_from_slice(&(CHUNK as u32).to_le_bytes());
    writer.stream[44..48].copy_from_slice(&(SOURCE.len() as u32).to_le_bytes());
    if version >= 4 {
        let name = writer.put(SOURCE.as_bytes());
        writer.patch(52, name);
    } else {
        writer.stream[48..48 + SOURCE.len()].copy_from_slice(SOURCE.as_bytes());
    }
    let first = writer.group(tree, 0);
    writer.stream[36..44].copy_from_slice(&first.to_le_bytes());
    let size = u64::from(units) << 16;
    let pieces: Vec<&[u8]> = writer.stream.chunks(size as usize).collect();
    pieces
        .iter()
        .enumerate()
        .map(|(i, piece)| {
            let mut segment = vec![0; 512];
            segment[..15].copy_from_slice(b"ADSEGMENTEDFILE");
            segment[16..20].copy_from_slice(&1u32.to_le_bytes());
            segment[20..24].copy_from_slice(&2u32.to_le_bytes());
            segment[24..28].copy_from_slice(&(i as u32 + 1).to_le_bytes());
            segment[28..32].copy_from_slice(&(pieces.len() as u32).to_le_bytes());
            segment[32..40].copy_from_slice(&(size + 512).to_le_bytes());
            segment[40..44].copy_from_slice(&512u32.to_le_bytes());
            segment.extend_from_slice(piece);
            segment
        })
        .collect()
}

fn open(segments: &[Vec<u8>]) -> Result<Image<Cursor<Vec<u8>>>, ad1::Error> {
    Image::open(segments.iter().cloned().map(Cursor::new).collect())
}

fn content(image: &mut Image<Cursor<Vec<u8>>>, path: &str) -> Vec<u8> {
    let index = image.items.iter().position(|i| i.path == path).unwrap();
    let mut out = Vec::new();
    image.content(index).unwrap().read_to_end(&mut out).unwrap();
    out
}

fn tree() -> Vec<Node> {
    let big: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    vec![Node::Folder(
        "C:",
        vec![
            Node::Folder(
                "Windows",
                vec![
                    Node::File("notepad.exe", b"MZ just a stub".to_vec()),
                    Node::File("big.bin", big),
                ],
            ),
            Node::File("empty.txt", Vec::new()),
        ],
    )]
}

#[test]
fn reads_items_metadata_and_content() {
    let segments = image(&tree(), 100);
    assert_eq!(segments.len(), 1);
    let mut image = open(&segments).unwrap();
    assert!(image.problems.is_empty(), "{:?}", image.problems);
    assert_eq!(image.version, 4);
    assert_eq!(image.source, SOURCE);
    let paths: Vec<&str> = image.items.iter().map(|i| i.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "C:",
            "C:/Windows",
            "C:/empty.txt",
            "C:/Windows/notepad.exe",
            "C:/Windows/big.bin"
        ]
    );
    assert!(image.items[0].is_folder() && !image.items[0].has_content());
    let big = &image.items[4];
    assert_eq!(big.size, 200_000);
    assert_eq!(big.md5(), Some(format!("{:x}", md5(&tree_big())).as_str()));
    // 2024-02-12 10:11:12.123456 UTC.
    assert_eq!(big.time(key::MODIFIED), Some(133_522_062_721_234_560));
    assert_eq!(content(&mut image, "C:/Windows/big.bin"), tree_big());
    assert_eq!(
        content(&mut image, "C:/Windows/notepad.exe"),
        b"MZ just a stub"
    );
    assert!(content(&mut image, "C:/empty.txt").is_empty());
}

fn tree_big() -> Vec<u8> {
    (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect()
}

#[test]
fn version_3() {
    let mut image = open(&image_of_version(&tree(), 1, 3)).unwrap();
    assert!(image.problems.is_empty(), "{:?}", image.problems);
    assert_eq!((image.version, image.source.as_str()), (3, SOURCE));
    assert_eq!(image.items.len(), 5);
    assert_eq!(content(&mut image, "C:/Windows/big.bin"), tree_big());
}

#[test]
fn content_spans_segments() {
    // 64 KiB of payload per segment: the big file crosses several.
    let segments = image(&tree(), 1);
    assert!(segments.len() >= 4, "{} segments", segments.len());
    let mut image = open(&segments).unwrap();
    assert!(image.problems.is_empty(), "{:?}", image.problems);
    assert_eq!(content(&mut image, "C:/Windows/big.bin"), tree_big());
}

#[test]
fn refuses_what_isnt_an_image_of_these_segments() {
    let segments = image(&tree(), 1);
    // Missing a segment, or out of order.
    assert!(open(&segments[..1]).is_err());
    let mut swapped = segments.clone();
    swapped.swap(0, 1);
    assert!(open(&swapped).is_err());
    assert!(open(&[b"not an image".to_vec()]).is_err());
    let mut encrypted = segments[0].clone();
    encrypted[..7].copy_from_slice(b"ADCRYPT");
    let e = open(&[encrypted]).unwrap_err();
    assert!(e.reason.contains("encrypted"), "{e}");
}

#[test]
fn a_damaged_chunk_is_an_error_for_that_item() {
    let mut segments = image(&tree(), 100);
    let image_ok = open(&segments).unwrap();
    let big = image_ok.items.iter().find(|i| i.name == "big.bin").unwrap();
    // Corrupt a byte inside the big file's first chunk.
    let at = 512 + big.address as usize + 200;
    segments[0][at] ^= 0xff;
    let mut image = open(&segments).unwrap();
    let index = image.items.iter().position(|i| i.name == "big.bin");
    if let Some(index) = index {
        let mut out = Vec::new();
        let read = image.content(index).and_then(|mut c| {
            c.read_to_end(&mut out).map_err(|e| ad1::Error {
                address: 0,
                reason: e.to_string(),
            })
        });
        assert!(read.is_err() || out != tree_big());
    }
    // The other items read as before.
    assert_eq!(
        content(&mut image, "C:/Windows/notepad.exe"),
        b"MZ just a stub"
    );
}

mod damage {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        /// Damaged anywhere, an image opens or is refused, and reading every
        /// item's content ends, with data or an error: never a panic.
        #[test]
        fn damaged_images_never_panic(flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..40)) {
            let mut segments = image(&tree(), 1);
            let count = segments.len();
            for (at, byte) in flips {
                let segment = &mut segments[at % count];
                let len = segment.len();
                segment[(at / count) % len] = byte;
            }
            if let Ok(mut image) = open(&segments) {
                for index in 0..image.items.len() {
                    if let Ok(mut content) = image.content(index) {
                        let _ = std::io::copy(&mut content, &mut std::io::sink());
                    }
                }
            }
        }
    }
}
