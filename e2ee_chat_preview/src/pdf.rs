//! PDF pages as pixels, drawn by hayro, a page at a time.

use std::sync::Arc;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::{LoadPdfError, Pdf};
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{PixmapSettings, RenderCache, RenderSettings};

/// The most pixels a page is drawn with, along either side: more than a canvas takes, or than
/// any screen shows.
pub const MAX_SIDE: u32 = 8192;

/// A PDF document.
pub struct Document {
    pdf: Pdf,
}

/// A page, drawn.
pub struct Page {
    pub width: u32,
    pub height: u32,
    /// Its RGBA pixels, row by row, opaque.
    pub pixels: Vec<u8>,
}

impl Document {
    pub fn open(data: Vec<u8>) -> Result<Self, String> {
        match Pdf::new(Arc::new(data)) {
            Ok(pdf) => Ok(Self { pdf }),
            Err(LoadPdfError::Decryption(_)) => Err("it is encrypted".to_string()),
            Err(LoadPdfError::Invalid) => Err("it is not a PDF, or a damaged one".to_string()),
        }
    }

    /// Each page's size, in points, as it shows: rotated if it says so.
    pub fn sizes(&self) -> Vec<(f32, f32)> {
        self.pdf
            .pages()
            .iter()
            .map(|page| page.render_dimensions())
            .collect()
    }

    /// The page `index`, drawn `width` pixels wide, or narrower if it would be more than
    /// [`MAX_SIDE`] pixels on a side, on white.
    pub fn render(&self, index: usize, width: u32) -> Result<Page, String> {
        let pages = self.pdf.pages();
        let page = pages.get(index).ok_or("no such page")?;
        let scale = scale(width, page.render_dimensions()).ok_or("the page has no size")?;
        let pixmap = hayro::render(
            page,
            &RenderCache::new(),
            &InterpreterSettings::default(),
            &RenderSettings::default(),
            &PixmapSettings {
                x_scale: scale,
                y_scale: scale,
                bg_color: WHITE,
            },
        );
        Ok(Page {
            width: pixmap.width().into(),
            height: pixmap.height().into(),
            pixels: pixmap.data_as_u8_slice().to_vec(),
        })
    }
}

/// The scale that draws a page of `size`, in points, `width` pixels wide, or narrower if it would
/// be more than [`MAX_SIDE`] pixels on a side.
fn scale(width: u32, (page_width, page_height): (f32, f32)) -> Option<f32> {
    if !(page_width > 0.0 && page_height > 0.0) {
        return None;
    }
    let scale = (width.min(MAX_SIDE) as f32 / page_width).min(MAX_SIDE as f32 / page_height);
    (scale > 0.0).then_some(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-page PDF, 200 by 100 points, with a black square at its bottom left.
    fn square() -> Vec<u8> {
        let content = "0 0 0 rg 0 0 50 50 re f";
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Contents 4 0 R >>".to_string(),
            format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()),
        ];
        let mut pdf = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, object) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", i + 1).as_bytes());
        }
        let xref = pdf.len();
        pdf.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1)
                .as_bytes(),
        );
        pdf
    }

    #[test]
    fn draws_a_page() {
        let document = Document::open(square()).unwrap();
        assert_eq!(document.sizes(), [(200.0, 100.0)]);
        let page = document.render(0, 400).unwrap();
        assert_eq!((page.width, page.height), (400, 200));
        assert_eq!(page.pixels.len(), 400 * 200 * 4);
        let pixel = |x: usize, y: usize| &page.pixels[(y * 400 + x) * 4..][..4];
        // White above, black in the square, at the bottom left, opaque everywhere.
        assert_eq!(pixel(300, 20), [255, 255, 255, 255]);
        assert_eq!(pixel(20, 180), [0, 0, 0, 255]);
        assert!(document.render(1, 400).is_err());
    }

    #[test]
    fn stays_within_bounds() {
        assert_eq!(scale(400, (200.0, 100.0)), Some(2.0));
        assert_eq!(scale(u32::MAX, (200.0, 100.0)), Some(MAX_SIDE as f32 / 200.0));
        assert_eq!(scale(400, (100.0, 1e6)), Some(MAX_SIDE as f32 / 1e6));
        assert_eq!(scale(400, (0.0, 100.0)), None);
        assert_eq!(scale(400, (f32::NAN, 100.0)), None);
        assert_eq!(scale(0, (200.0, 100.0)), None);
    }

    #[test]
    fn refuses_what_is_not_a_pdf() {
        assert!(Document::open(b"not a pdf".to_vec()).is_err());
    }
}
