//! Images made by FTK Imager: every item's content is read and checked
//! against the MD5 FTK recorded when it made the image.
//!
//! - pyad1's test image (Apache-2.0, in `tests/fixtures/pyad1/`): four
//!   segments, a tree of folders, files read across segment boundaries.
//! - Any other images: set `SOOTMARK_AD1_IMAGES` to a folder holding some
//!   (`x.ad1` with its `x.ad2`, …, searched recursively). CI points it at
//!   dissect.evidence's AGPL test images, downloaded rather than copied.

use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use common::md5::Md5;

/// The segments of the image whose first segment is `first`: `x.ad1`,
/// `x.ad2`, … while they exist.
fn segments(first: &Path) -> Vec<BufReader<File>> {
    (1..)
        .map_while(|n| File::open(first.with_extension(format!("ad{n}"))).ok())
        .map(BufReader::new)
        .collect()
}

/// Open the image and check every content against its MD5; the image and
/// how many contents were checked.
fn check(first: &Path) -> (ad1::Image<BufReader<File>>, usize) {
    let mut image = ad1::Image::open(segments(first)).unwrap();
    let at = first.display();
    assert!(image.problems.is_empty(), "{at}: {:?}", image.problems);
    let mut checked = 0;
    for index in 0..image.items.len() {
        let item = image.items[index].clone();
        let Some(recorded) = item.md5() else {
            continue;
        };
        let mut hasher = Md5::new();
        let copied = io::copy(&mut image.content(index).unwrap(), &mut hasher).unwrap();
        assert_eq!(copied, item.size, "{at}: {}", item.path);
        assert_eq!(
            common::hex::encode(&hasher.finalize()),
            recorded,
            "{at}: {}",
            item.path
        );
        checked += 1;
    }
    (image, checked)
}

#[test]
fn pyad1_image() {
    let first =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pyad1/text-and-pictures.ad1");
    let (image, checked) = check(&first);
    assert_eq!(image.version, 4);
    assert_eq!(image.source, r"C:\Users\pcbje\Desktop\Data");
    let paths: Vec<(&str, bool)> = image
        .items
        .iter()
        .map(|i| (i.path.as_str(), i.is_folder()))
        .collect();
    assert_eq!(
        paths,
        [
            ("Pictures", true),
            ("Text", true),
            ("Text/norvig-big.txt", false),
            ("Pictures/0-0-581-Hydrangeas.jpg", false),
            ("Pictures/1-0-858-Chrysanthemum.jpg", false),
            ("Pictures/2-0-826-Desert.jpg", false),
            ("Pictures/4-0-757-Jellyfish.jpg", false),
            ("Pictures/5-0-762-Koala.jpg", false),
            ("Pictures/6-0-548-Lighthouse.jpg", false),
            ("Pictures/7-0-759-Penguins.jpg", false),
        ]
    );
    assert_eq!(checked, 8);
}

fn first_segments(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            first_segments(&path, found);
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("ad1"))
        {
            found.push(path);
        }
    }
}

#[test]
fn images_in_a_folder() {
    let Some(dir) = std::env::var_os("SOOTMARK_AD1_IMAGES") else {
        eprintln!("skipped: set SOOTMARK_AD1_IMAGES to a folder of AD1 images");
        return;
    };
    let mut found = Vec::new();
    first_segments(Path::new(&dir), &mut found);
    assert!(!found.is_empty(), "no .ad1 files in {dir:?}");
    for first in found {
        let (image, checked) = check(&first);
        eprintln!(
            "{}: {} items, {checked} contents match their MD5",
            first.display(),
            image.items.len()
        );
        assert!(checked > 0, "{}", first.display());
    }
}
