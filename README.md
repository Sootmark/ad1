# ad1

AccessData AD1 logical images: the "custom content images" FTK Imager writes when an examiner exports chosen files and folders instead of a whole disk (common in real cases and in CTF material). Written from the public notes on the format. One dependency, its sibling `sootmark-common` (zlib, hashes).

```toml
[dependencies]
sootmark-ad1 = "0.1"
```

```rust
use std::fs::File;
use std::io::BufReader;

let mut image = ad1::Image::open(vec![BufReader::new(File::open("evidence.ad1")?)])?;
for index in 0..image.items.len() {
    let item = image.items[index].clone();
    if item.has_content() {
        let mut out = File::create(item.name.replace('/', "_"))?;
        std::io::copy(&mut image.content(index)?, &mut out)?;
    }
}
```

## What you get

- `Image::open(segments)`: every segment checked (signature, number, count), the image header (version 3 or 4, zlib chunk size, the source's name), and every item: a tree of folders and files with paths from the image's top, their type, size and metadata.
- `Item`: `path`, `parent`, `kind` (0 a file, `FOLDER`), `size`, and `attributes` (category, key and the text value FTK stores: sizes, flags, timestamps, hashes, NTFS attributes, owners and access control entries). Accessors for what's understood: `md5()` and `sha1()` recorded at acquisition, and `time(key)` (accessed, created, modified, NTFS record change) as a FILETIME: FTK writes UTC, to the microsecond.
- `Image::content(index)`: the item's content, decompressed a 64 KiB chunk at a time (never the whole file in memory), each chunk's Adler-32 checked and its size held to what the item declares.
- Segments (`.ad1`, `.ad2`, …) read as one stream: addresses skip each segment's 512-byte margin.
- Damage is an error for what it touches, never a panic: a looping or truncated item tree stops there with a problem recorded; a damaged chunk fails that item's read. Encrypted images (`ADCRYPT`) are recognised and refused.

Not yet: encrypted images, and verifying the image-wide hash FTK logs.

## How it's checked

- `tests/images.rs` reads every item of images FTK Imager made and compares each content with the MD5 FTK recorded at acquisition:
  - [pyad1](https://github.com/pcbje/pyad1)'s test image (Apache-2.0, in `tests/fixtures/pyad1/`): version 4, four segments, folders, a 6 MB text read across segment boundaries; the tree also matches what [dissect.evidence](https://github.com/fox-it/dissect.evidence)'s tests expect of it.
  - dissect.evidence's own test images (AGPL, so CI downloads them rather than copying them in): long names, compressed content.
  - any folder of images named by `SOOTMARK_AD1_IMAGES`.
- `tests/synthetic.rs` writes images as FTK lays them out: version 3 (no public version 3 image is known), nested folders, content across chunks and across segments, empty files, missing and misordered segments, a damaged chunk, and damage anywhere (property tests: opened or refused, read or failed, never a panic).

## Licence

MIT or Apache-2.0, at your option.
