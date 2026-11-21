//! PDF pages as pixels, drawn by hayro, a page at a time.

use std::sync::Arc;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::{LoadPdfError, Pdf};
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{PixmapSettings, RenderCache, RenderSettings};

/// Maximum width or height of a rendered page, in pixels.
pub const MAX_SIDE: u32 = 8192;
/// Maximum number of pixels in a rendered page, limiting each RGBA buffer to 64 MiB.
pub const MAX_PIXELS: u32 = 16_777_216;

/// A PDF document.
pub struct Document {
    pdf: Pdf,
}

/// A page drawn on white, with opaque RGBA pixels in row order.
pub type Page = crate::rpc::RenderedPage;

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

    /// Draw page `index` on white at the requested width, scaling it proportionally to fit
    /// [`MAX_SIDE`] per side and [`MAX_PIXELS`] in total. Returns an error if either
    /// dimension would occupy less than one pixel.
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

/// Choose one scale for both axes before hayro allocates its render context and pixmap.
fn scale(width: u32, (page_width, page_height): (f32, f32)) -> Option<f32> {
    if width == 0
        || !page_width.is_finite()
        || !page_height.is_finite()
        || page_width <= 0.0
        || page_height <= 0.0
    {
        return None;
    }
    let max_width = width.min(MAX_SIDE);
    let (pw, ph) = (f64::from(page_width), f64::from(page_height));
    let limit = (f64::from(max_width) / pw)
        .min(f64::from(MAX_SIDE) / ph)
        .min((f64::from(MAX_PIXELS) / (pw * ph)).sqrt());
    // Tiny dimensions can yield a limit larger than the largest finite f32 scale.
    let mut scale = (limit as f32).min(f32::MAX);
    loop {
        // Converting the limit to f32 can round up. Check hayro's products before its u16 cast.
        let rw = (page_width * scale) as u32;
        let rh = (page_height * scale) as u32;
        if rw == 0 || rh == 0 {
            return None;
        }
        if rw <= max_width
            && rh <= MAX_SIDE
            && u64::from(rw) * u64::from(rh) <= u64::from(MAX_PIXELS)
        {
            return Some(scale);
        }
        scale = scale.next_down();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-page PDF with a black square at its bottom left.
    fn square(width: u32, height: u32) -> Vec<u8> {
        let content = "0 0 0 rg 0 0 50 50 re f";
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Contents 4 0 R >>"
            ),
            format!(
                "<< /Length {} >>\nstream\n{content}\nendstream",
                content.len()
            ),
        ];
        let mut pdf = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, object) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", i + 1).as_bytes());
        }
        let xref = pdf.len();
        pdf.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
        );
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objects.len() + 1
            )
            .as_bytes(),
        );
        pdf
    }

    #[test]
    fn draws_a_page() {
        let document = Document::open(square(200, 100)).unwrap();
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

    fn raster_size(width: u32, size: (f32, f32)) -> (u32, u32) {
        let scale = scale(width, size).unwrap();
        let (w, h) = ((size.0 * scale) as u32, (size.1 * scale) as u32);
        assert!((1..=width.min(MAX_SIDE)).contains(&w));
        assert!((1..=MAX_SIDE).contains(&h));
        assert!(u64::from(w) * u64::from(h) <= u64::from(MAX_PIXELS));
        (w, h)
    }

    #[test]
    fn requested_width_and_long_side_limit() {
        assert_eq!(raster_size(400, (200.0, 100.0)), (400, 200));
        assert_eq!(raster_size(400, (100.0, 200.0)), (400, 800));
        assert_eq!(raster_size(u32::MAX, (8000.0, 100.0)), (MAX_SIDE, 102));
        assert_eq!(raster_size(400, (100.0, 8000.0)), (102, MAX_SIDE));
        assert_eq!(raster_size(1, (1.0, 1.0)), (1, 1));
    }

    #[test]
    fn square_and_nearly_square_pages_fit_the_area_limit() {
        for width in [8192, u32::MAX] {
            assert_eq!(raster_size(width, (8192.0, 8192.0)), (4096, 4096));
            assert_eq!(raster_size(width, (8192.0, 8000.0)), (4144, 4047));
            assert_eq!(raster_size(width, (8000.0, 8192.0)), (4047, 4144));
        }
    }

    #[test]
    fn extreme_finite_sizes() {
        for side in [1e20, 1e25, f32::MAX] {
            let (w, h) = raster_size(u32::MAX, (side, side));
            assert_eq!(w, h);
            assert!((4095..=4096).contains(&w));
        }
        // Even the largest finite scale can draw only a few pixels from such a small page.
        assert_eq!(
            raster_size(MAX_SIDE, (f32::MIN_POSITIVE, f32::MIN_POSITIVE)),
            (3, 3)
        );
        assert_eq!(
            scale(MAX_SIDE, (f32::from_bits(1), f32::from_bits(1))),
            None
        );
    }

    #[test]
    fn rejects_invalid_and_subpixel_dimensions() {
        for invalid in [0.0, -1.0, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(scale(400, (invalid, 100.0)), None);
            assert_eq!(scale(400, (100.0, invalid)), None);
        }
        assert_eq!(scale(0, (200.0, 100.0)), None);
        for size in [(100.0, 1e6), (1e6, 100.0)] {
            assert_eq!(scale(u32::MAX, size), None);
        }
        let document = Document::open(square(100, 1_000_000)).unwrap();
        assert_eq!(
            document.render(0, MAX_SIDE).unwrap_err(),
            "the page has no size"
        );
    }

    #[test]
    fn draws_a_large_media_box_within_the_rgba_budget() {
        let document = Document::open(square(8192, 8192)).unwrap();
        let page = document.render(0, u32::MAX).unwrap();
        assert_eq!((page.width, page.height), (4096, 4096));
        assert_eq!(
            page.pixels.len(),
            page.width as usize * page.height as usize * 4
        );
    }

    #[test]
    fn refuses_what_is_not_a_pdf() {
        assert!(Document::open(b"not a pdf".to_vec()).is_err());
    }
}
