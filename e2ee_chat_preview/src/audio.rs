//! What an audio file's tags say of it, as lofty reads them: its title, artist, album and year,
//! and its cover.

/// What an audio file's tags say of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tags {
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<u16>,
    /// The cover's MIME type and bytes.
    pub cover: Option<(String, Vec<u8>)>,
}

/// The tags of the audio file `data`, if it has any: ID3, MP4, FLAC or Vorbis comments. Its
/// main tag first, then the others, as an MP3's ID3v1 after its ID3v2; the front cover, or else
/// its first picture, only if it is an image a page shows, whatever its tag calls it.
#[cfg(feature = "audio")]
pub fn tags(data: &[u8]) -> Option<Tags> {
    use std::{borrow::Cow, io::Cursor};

    use lofty::{
        config::ParseOptions,
        picture::PictureType,
        prelude::{Accessor, TaggedFileExt},
        probe::Probe,
        tag::Tag,
    };

    let file = Probe::new(Cursor::new(data))
        .options(ParseOptions::new().read_properties(false))
        .guess_file_type()
        .ok()?
        .read()
        .ok()?;
    let all: Vec<&Tag> = file.primary_tag().into_iter().chain(file.tags()).collect();
    let text = |field: fn(&Tag) -> Option<Cow<'_, str>>| {
        all.iter()
            .find_map(|tag| Some(field(tag)?.trim().to_string()).filter(|text| !text.is_empty()))
    };
    let pictures = || all.iter().flat_map(|tag| tag.pictures());
    let cover = pictures()
        .find(|picture| picture.pic_type() == PictureType::CoverFront)
        .or_else(|| pictures().next())
        .and_then(|picture| {
            let mime = picture_type(picture.data())?;
            Some((mime.to_string(), picture.data().to_vec()))
        });
    let tags = Tags {
        title: text(|tag| tag.title()),
        artist: text(|tag| tag.artist()),
        album: text(|tag| tag.album()),
        year: all.iter().find_map(|tag| tag.date()).map(|date| date.year),
        cover,
    };
    (tags != Tags::default()).then_some(tags)
}

/// The MIME type of the picture `data`, by its first bytes, if a page shows it as an image:
/// PNG, JPEG, GIF, WebP, AVIF or BMP.
#[cfg(feature = "audio")]
fn picture_type(data: &[u8]) -> Option<&'static str> {
    match data {
        [0x89, b'P', b'N', b'G', ..] => Some("image/png"),
        [0xFF, 0xD8, 0xFF, ..] => Some("image/jpeg"),
        [b'G', b'I', b'F', b'8', ..] => Some("image/gif"),
        _ if data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") => Some("image/webp"),
        [
            _,
            _,
            _,
            _,
            b'f',
            b't',
            b'y',
            b'p',
            b'a',
            b'v',
            b'i',
            b'f' | b's',
            ..,
        ] => Some("image/avif"),
        [b'B', b'M', ..] => Some("image/bmp"),
        _ => None,
    }
}

#[cfg(all(test, feature = "audio"))]
mod tests {
    use lofty::{
        config::WriteOptions,
        id3::v2::Id3v2Tag,
        picture::{MimeType, Picture, PictureType},
        prelude::{Accessor, TagExt},
    };

    use super::*;

    /// A one-pixel PNG.
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89\0\0\0\rIDATx\x9cc\xf8\x0f\0\x01\x01\x01\0\x18\xdd\x8d\xb0\0\0\0\0IEND\xaeB`\x82";

    /// An MP3 of `tag` and a few frames of silence: MPEG-1 layer III, 128 kbit/s at 44.1 kHz.
    fn mp3(tag: &Id3v2Tag) -> Vec<u8> {
        let mut mp3 = vec![];
        tag.dump_to(&mut mp3, WriteOptions::default()).unwrap();
        for _ in 0..4 {
            mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
            mp3.extend_from_slice(&[0; 413]);
        }
        mp3
    }

    fn cover(data: &[u8]) -> Picture {
        Picture::unchecked(data.to_vec())
            .pic_type(PictureType::CoverFront)
            .mime_type(MimeType::Png)
            .build()
    }

    #[test]
    fn titles_artists_albums_and_covers() {
        let mut tag = Id3v2Tag::new();
        tag.set_title("Song".into());
        tag.set_artist("Singer".into());
        tag.set_album("Album".into());
        tag.insert_picture(cover(PNG));
        let read = tags(&mp3(&tag)).expect("tags");
        assert_eq!(read.title.as_deref(), Some("Song"));
        assert_eq!(read.artist.as_deref(), Some("Singer"));
        assert_eq!(read.album.as_deref(), Some("Album"));
        assert_eq!(read.cover, Some(("image/png".to_string(), PNG.to_vec())));
    }

    #[test]
    fn a_cover_that_is_no_image_is_left_out() {
        let mut tag = Id3v2Tag::new();
        tag.set_title("Song".into());
        tag.insert_picture(cover(b"<svg onload=alert(1)>"));
        assert_eq!(tags(&mp3(&tag)).expect("tags").cover, None);
    }

    #[test]
    fn no_tags_say_nothing() {
        assert_eq!(tags(b"RIFF....WAVEfmt "), None);
    }
}
