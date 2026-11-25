//! PDF pages as pixels, drawn by hayro, a page at a time.

use std::sync::Arc;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::page::Page as SyntaxPage;
use hayro::hayro_syntax::{LoadPdfError, Pdf};
use hayro::vello_cpu::Pixmap;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{PixmapSettings, RenderCache, RenderSettings};

use crate::Worker;
use crate::rpc::{Method, PagePixels, PdfOpened, RenderedPage, Request, Response, WorkerService};

/// Maximum number of pages accepted in one PDF document.
pub use crate::rpc::MAX_PAGES;
/// Maximum PDF input size accepted by [`Document::open`] (64 MiB).
pub use crate::rpc::MAX_PDF_BYTES;
/// Maximum number of pixels in a rendered page, limiting each RGBA buffer to 64 MiB.
pub use crate::rpc::MAX_PDF_PIXELS as MAX_PIXELS;
/// Maximum width or height of a rendered page, in pixels.
pub use crate::rpc::MAX_PDF_SIDE as MAX_SIDE;

/// Maximum number of PDF documents kept open simultaneously by [`PdfService`] (LRU eviction).
pub const MAX_OPEN_DOCS: usize = 4;

/// A PDF document with a per-document [`RenderCache`] reused across page renders.
pub struct Document {
    // SAFETY: `cache` may cache references borrowing from `pdf` (`&XRef`, `&Page`). Rust drops
    // struct fields in declaration order, so `cache` is always dropped strictly before `pdf`.
    // `pdf` is stored behind `Arc<Pdf>` and never mutated or replaced, so moving `Document`
    // never invalidates heap pointers referenced by `cache`.
    cache: RenderCache<'static>,
    pdf: Arc<Pdf>,
}

/// A page drawn on white, with opaque RGBA pixels in row order.
pub type Page = RenderedPage;

impl Document {
    pub fn open(data: Vec<u8>) -> Result<Self, String> {
        if data.len() > MAX_PDF_BYTES {
            return Err("the PDF is too large".to_string());
        }
        let pdf = match Pdf::new(Arc::new(data)) {
            Ok(pdf) => pdf,
            Err(LoadPdfError::Decryption(_)) => return Err("it is encrypted".to_string()),
            Err(LoadPdfError::Invalid) => {
                return Err("it is not a PDF, or a damaged one".to_string());
            }
        };
        if pdf.pages().len() > MAX_PAGES {
            return Err(format!("the PDF has too many pages (maximum {MAX_PAGES})"));
        }
        Ok(Self {
            cache: RenderCache::new(),
            pdf: Arc::new(pdf),
        })
    }

    /// Each page's size, in points, as it shows: rotated if it says so.
    pub fn sizes(&self) -> Vec<(f32, f32)> {
        self.pdf
            .pages()
            .iter()
            .map(|page| page.render_dimensions())
            .collect()
    }

    /// Draw page `index` into a hayro [`Pixmap`] without an intermediate `Vec<u8>` copy.
    pub fn render_pixmap(&self, index: usize, width: u32) -> Result<Pixmap, String> {
        let pages = self.pdf.pages();
        let page = pages.get(index).ok_or("no such page")?;
        let scale = scale(width, page.render_dimensions()).ok_or("the page has no size")?;
        // SAFETY: `page` borrows from `self.pdf` (behind `Arc<Pdf>`, immutable for the life of
        // `Document`). `self.cache` is declared before `self.pdf`, so any cached references
        // derived from `page` are dropped strictly before `self.pdf`.
        let page: &'static SyntaxPage<'static> = unsafe { std::mem::transmute(page) };
        Ok(hayro::render(
            page,
            &self.cache,
            &InterpreterSettings::default(),
            &RenderSettings::default(),
            &PixmapSettings {
                x_scale: scale,
                y_scale: scale,
                bg_color: WHITE,
            },
        ))
    }

    /// Draw page `index` on white at the requested width, scaling it proportionally to fit
    /// [`MAX_SIDE`] per side and [`MAX_PIXELS`] in total. Returns an error if either
    /// dimension would occupy less than one pixel.
    pub fn render(&self, index: usize, width: u32) -> Result<Page, String> {
        let pixmap = self.render_pixmap(index, width)?;
        Ok(Page {
            width: pixmap.width().into(),
            height: pixmap.height().into(),
            pixels: pixmap.data_as_u8_slice().to_vec(),
        })
    }
}

/// Stateful [`WorkerService`] managing open PDF documents with bounded LRU eviction.
pub struct PdfService {
    /// Open documents ordered least-recently-used at index 0, most-recently-used at the back.
    documents: Vec<(u32, Document)>,
    next_id: u32,
    max_open: usize,
}

impl Default for PdfService {
    fn default() -> Self {
        Self::new()
    }
}

impl PdfService {
    pub fn new() -> Self {
        Self::with_max_open(MAX_OPEN_DOCS)
    }

    pub fn with_max_open(max_open: usize) -> Self {
        Self {
            documents: Vec::new(),
            next_id: 0,
            max_open: max_open.max(1),
        }
    }

    /// Number of currently retained PDF documents.
    pub fn open_count(&self) -> usize {
        self.documents.len()
    }
}

impl WorkerService for PdfService {
    fn accepts(&self, method: Method) -> bool {
        method.is_served_by(Worker::Pdf)
    }

    fn handle(&mut self, req: Request) -> Result<Response, String> {
        match req {
            Request::Open(bytes) => {
                let document = Document::open(bytes)?;
                let sizes = document
                    .sizes()
                    .into_iter()
                    .map(|(w, h)| (f64::from(w), f64::from(h)))
                    .collect();
                let doc_id = self.next_id.checked_add(1).ok_or("no more document IDs")?;
                self.next_id = doc_id;
                if self.documents.len() >= self.max_open {
                    self.documents.remove(0);
                }
                self.documents.push((doc_id, document));
                Ok(Response::Opened(PdfOpened { doc_id, sizes }))
            }
            Request::Render {
                doc_id,
                page,
                width,
            } => {
                let pos = self
                    .documents
                    .iter()
                    .position(|(id, _)| *id == doc_id)
                    .ok_or("no such document")?;
                // Touch LRU order: move the active document to the MRU back slot.
                let last = self.documents.len() - 1;
                if pos != last {
                    let entry = self.documents.remove(pos);
                    self.documents.push(entry);
                }
                let (_, document) = self.documents.last().expect("document just moved to back");
                let pixmap = document.render_pixmap(page as usize, width)?;
                Ok(Response::Rendered(RenderedPage {
                    width: pixmap.width().into(),
                    height: pixmap.height().into(),
                    pixels: PagePixels::Pixmap(pixmap),
                }))
            }
            Request::Close { doc_id } => {
                self.documents.retain(|(id, _)| *id != doc_id);
                Ok(Response::Closed)
            }
            other => Err(format!("no method {}", other.method().as_str())),
        }
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

    /// A synthetic PDF with `count` distinct page objects sharing one content stream.
    fn multi_page_square(width: u32, height: u32, count: usize) -> Vec<u8> {
        let content = "0 0 0 rg 0 0 50 50 re f";
        // Object 1: Catalog, Object 2: Pages, Object 3: shared Contents stream,
        // Objects 4..(4 + count): distinct Page objects.
        let kids: String = (0..count)
            .map(|i| format!("{} 0 R", i + 4))
            .collect::<Vec<_>>()
            .join(" ");
        let mut objects = Vec::with_capacity(3 + count);
        objects.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
        objects.push(format!("<< /Type /Pages /Kids [{kids}] /Count {count} >>"));
        objects.push(format!(
            "<< /Length {} >>\nstream\n{content}\nendstream",
            content.len()
        ));
        let page_obj = format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] /Contents 3 0 R >>"
        );
        for _ in 0..count {
            objects.push(page_obj.clone());
        }
        let mut pdf = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::with_capacity(objects.len());
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

    /// A one-page PDF with a black square at its bottom left.
    fn square(width: u32, height: u32) -> Vec<u8> {
        multi_page_square(width, height, 1)
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

    #[test]
    fn reuses_render_cache_across_multiple_pages() {
        let document = Document::open(multi_page_square(200, 100, 3)).unwrap();
        assert_eq!(document.sizes().len(), 3);
        let p0 = document.render(0, 200).unwrap();
        let p1 = document.render(1, 200).unwrap();
        let p2 = document.render(2, 200).unwrap();
        assert_eq!(p0.pixels, p1.pixels);
        assert_eq!(p1.pixels, p2.pixels);
    }

    #[test]
    fn rejects_oversized_pdf_bytes_and_page_counts() {
        let oversized = vec![0u8; MAX_PDF_BYTES + 1];
        assert!(Document::open(oversized).is_err());

        let too_many_pages = multi_page_square(100, 100, MAX_PAGES + 1);
        assert!(Document::open(too_many_pages).is_err());

        let at_limit = multi_page_square(100, 100, MAX_PAGES);
        let doc = Document::open(at_limit).unwrap();
        assert_eq!(doc.sizes().len(), MAX_PAGES);
    }

    #[test]
    fn pdf_service_enforces_lru_eviction_and_dispatch() {
        let mut service = PdfService::new();
        assert!(service.accepts(Method::Open));
        assert!(service.accepts(Method::Render));
        assert!(service.accepts(Method::Close));
        assert!(!service.accepts(Method::Svg));

        let mut ids = Vec::new();
        for _ in 0..MAX_OPEN_DOCS {
            let Response::Opened(opened) = service.handle(Request::Open(square(100, 100))).unwrap()
            else {
                panic!("expected Opened");
            };
            ids.push(opened.doc_id);
        }
        assert_eq!(service.open_count(), MAX_OPEN_DOCS);

        // Touch the oldest document (`ids[0]`) so `ids[1]` becomes the LRU entry.
        let Response::Rendered(page) = service
            .handle(Request::Render {
                doc_id: ids[0],
                page: 0,
                width: 100,
            })
            .unwrap()
        else {
            panic!("expected Rendered");
        };
        assert_eq!((page.width, page.height), (100, 100));
        assert_eq!(page.pixels.len(), 100 * 100 * 4);

        // Opening one more document must evict `ids[1]`, keeping `ids[0]` alive.
        let Response::Opened(fifth) = service.handle(Request::Open(square(100, 100))).unwrap()
        else {
            panic!("expected Opened");
        };
        assert_eq!(service.open_count(), MAX_OPEN_DOCS);
        assert!(
            service
                .handle(Request::Render {
                    doc_id: ids[1],
                    page: 0,
                    width: 100,
                })
                .is_err()
        );
        assert!(
            service
                .handle(Request::Render {
                    doc_id: ids[0],
                    page: 0,
                    width: 100,
                })
                .is_ok()
        );

        // Failed Open must NOT evict any live document.
        assert!(
            service
                .handle(Request::Open(b"not a pdf".to_vec()))
                .is_err()
        );
        assert_eq!(service.open_count(), MAX_OPEN_DOCS);

        // Close removes the document cleanly.
        assert_eq!(
            service
                .handle(Request::Close {
                    doc_id: fifth.doc_id
                })
                .unwrap(),
            Response::Closed
        );
        assert_eq!(service.open_count(), MAX_OPEN_DOCS - 1);
        assert!(
            service
                .handle(Request::Render {
                    doc_id: fifth.doc_id,
                    page: 0,
                    width: 100,
                })
                .is_err()
        );

        // Unrelated method is rejected.
        assert!(
            service
                .handle(Request::Svg("flowchart LR\nA-->B".into()))
                .is_err()
        );
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
