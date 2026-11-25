//! The preview workers' requests and replies. The `rpc` feature adds their JavaScript
//! `postMessage` encoding, including transfer lists for buffers sent in either direction.
//!
//! With that feature, clients pass borrowed requests to `encode_request_frame`, post the
//! returned value with its transfer list, and dispatch `WorkerEvent::Reply` to the method's
//! decoder (or via [`RpcCall`]). Workers decode `RequestFrame`, check [`WorkerService::accepts`],
//! dispatch to [`WorkerService::handle`], and wrap `Response::encode` or a method error with
//! `encode_reply_frame`.

use std::fmt;
use std::ops::Deref;

use crate::Worker;
pub use crate::audio::Tags;
use crate::language::Group;

#[cfg(feature = "rpc")]
mod wire;
#[cfg(feature = "rpc")]
pub use wire::*;

/// Maximum PDF input size accepted by the PDF worker and RPC decoder (64 MiB).
pub const MAX_PDF_BYTES: usize = 64 << 20;
/// Maximum number of pages accepted in one PDF document.
pub const MAX_PAGES: usize = 2_000;
/// Maximum width or height of a rendered PDF page, in pixels.
pub const MAX_PDF_SIDE: u32 = 8192;
/// Maximum number of pixels in a rendered PDF page (64 MiB of RGBA).
pub const MAX_PDF_PIXELS: u32 = 16_777_216;
/// Maximum number of search matches returned (and examined) by the search worker.
pub const MATCHES_MAX: usize = 10_000;
/// Maximum source code size accepted by the syntax highlighter (1,000,000 bytes).
pub const HIGHLIGHT_MAX: usize = 1_000_000;
/// Maximum Mermaid source size accepted by the diagram worker (64 KiB).
pub const DIAGRAM_SOURCE_MAX: usize = 64 * 1024;
/// Maximum rendered SVG size returned by the diagram worker (2 MiB).
pub const DIAGRAM_SVG_MAX: usize = 2 * 1024 * 1024;

macro_rules! define_methods {
    ($( $variant:ident => ($name:literal, $worker:pat) ),+ $(,)?) => {
        /// A method name in a request frame.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Method {
            $($variant,)+
        }

        impl Method {
            /// Every defined RPC method, in declaration order.
            pub const ALL: &[Self] = &[$(Self::$variant,)+];

            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            pub fn parse(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Whether this worker handles the method. The language selects the code worker group.
            pub const fn is_served_by(self, worker: Worker) -> bool {
                match (self, worker) {
                    $((Self::$variant, $worker) => true,)+
                    _ => false,
                }
            }
        }
    };
}

define_methods! {
    Open      => ("open", Worker::Pdf),
    Render    => ("render", Worker::Pdf),
    Close     => ("close", Worker::Pdf),
    Tags      => ("tags", Worker::Audio),
    Find      => ("find", Worker::Search),
    Svg       => ("svg", Worker::Diagram),
    Highlight => ("highlight", Worker::Code(_)),
}

/// The arguments of each method. A client encodes a borrowed `Request<&[u8], &str>`.
/// Decoding in the worker produces an owned `Request<Vec<u8>, String>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request<B = Vec<u8>, S = String> {
    Open(B),
    Render {
        doc_id: u32,
        page: u32,
        width: u32,
    },
    Close {
        doc_id: u32,
    },
    Tags(B),
    Find {
        text: S,
        pattern: S,
        case: bool,
        regex: bool,
    },
    Svg(S),
    Highlight {
        language: S,
        text: S,
    },
}

impl<B, S> Request<B, S> {
    pub const fn method(&self) -> Method {
        match self {
            Self::Open(_) => Method::Open,
            Self::Render { .. } => Method::Render,
            Self::Close { .. } => Method::Close,
            Self::Tags(_) => Method::Tags,
            Self::Find { .. } => Method::Find,
            Self::Svg(_) => Method::Svg,
            Self::Highlight { .. } => Method::Highlight,
        }
    }
}

/// A preview worker's request handler, testable natively without a browser worker scope.
pub trait WorkerService {
    /// Whether this service serves `method`, checked before decoding potentially large arguments.
    fn accepts(&self, _method: Method) -> bool {
        true
    }

    /// Handle one decoded preview request.
    fn handle(&mut self, req: Request) -> Result<Response, String>;
}

/// The worker-local document ID and each page's width and height in points.
#[derive(Debug, Clone, PartialEq)]
pub struct PdfOpened {
    pub doc_id: u32,
    pub sizes: Vec<(f64, f64)>,
}

/// RGBA pixel storage for a rendered page. Holding a [`hayro::vello_cpu::Pixmap`] directly avoids
/// an extra full-page `Vec<u8>` clone when encoding directly into a JavaScript `Uint8ClampedArray`.
pub enum PagePixels {
    Bytes(Vec<u8>),
    #[cfg(feature = "pdf")]
    Pixmap(hayro::vello_cpu::Pixmap),
}

impl PagePixels {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes.as_slice(),
            #[cfg(feature = "pdf")]
            Self::Pixmap(pixmap) => pixmap.data_as_u8_slice(),
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl Deref for PagePixels {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for PagePixels {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Vec<u8>> for PagePixels {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Bytes(bytes)
    }
}

impl PartialEq for PagePixels {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PagePixels {}

impl fmt::Debug for PagePixels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PagePixels")
            .field("len", &self.len())
            .finish()
    }
}

/// A rendered PDF page. The client receives the transferred JavaScript pixel array directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage<P = Vec<u8>> {
    pub width: u32,
    pub height: u32,
    /// RGBA bytes in row order.
    pub pixels: P,
}

/// Search results in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchFound {
    /// Each match's start and end, in UTF-16 code units.
    pub matches: Vec<(u32, u32)>,
    /// Whether the search reached its limit and found further matches.
    pub more: bool,
}

/// The successful result of a worker method. Method errors travel as strings.
#[derive(Debug, PartialEq)]
pub enum Response {
    Opened(PdfOpened),
    Rendered(RenderedPage<PagePixels>),
    Closed,
    Tags(Option<Tags>),
    Found(SearchFound),
    Svg(String),
    Highlighted(String),
}

/// A typed preview worker RPC call pairing its target worker, request encoding, and reply decoder.
pub trait RpcCall<'a> {
    /// The decoded reply value returned to callers using the JS RPC wire codec.
    #[cfg(feature = "rpc")]
    type Reply;

    /// The wire method for this call.
    const METHOD: Method;

    /// The worker that serves this call.
    fn worker(&self) -> Worker;

    /// Borrowed request frame payload for this call.
    fn into_request(self) -> Request<&'a [u8], &'a str>;

    /// Decode the worker's JavaScript reply payload.
    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String>;
}

/// Typed RPC call for opening a PDF document.
#[derive(Debug, Clone, Copy)]
pub struct PdfOpenCall<'a>(pub &'a [u8]);

impl<'a> RpcCall<'a> for PdfOpenCall<'a> {
    #[cfg(feature = "rpc")]
    type Reply = PdfOpened;
    const METHOD: Method = Method::Open;

    fn worker(&self) -> Worker {
        Worker::Pdf
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Open(self.0)
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_pdf_open(value)
    }
}

/// Typed RPC call for rendering one page of an open PDF document.
#[derive(Debug, Clone, Copy)]
pub struct PdfRenderCall {
    pub doc_id: u32,
    pub page: u32,
    pub width: u32,
}

impl<'a> RpcCall<'a> for PdfRenderCall {
    #[cfg(feature = "rpc")]
    type Reply = RenderedPage<js_sys::Uint8ClampedArray>;
    const METHOD: Method = Method::Render;

    fn worker(&self) -> Worker {
        Worker::Pdf
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Render {
            doc_id: self.doc_id,
            page: self.page,
            width: self.width,
        }
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_pdf_render(value)
    }
}

/// Typed RPC call for closing an open PDF document.
#[derive(Debug, Clone, Copy)]
pub struct PdfCloseCall {
    pub doc_id: u32,
}

impl<'a> RpcCall<'a> for PdfCloseCall {
    #[cfg(feature = "rpc")]
    type Reply = ();
    const METHOD: Method = Method::Close;

    fn worker(&self) -> Worker {
        Worker::Pdf
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Close {
            doc_id: self.doc_id,
        }
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_pdf_close(value)
    }
}

/// Typed RPC call for extracting audio tags and cover art.
#[derive(Debug, Clone, Copy)]
pub struct AudioTagsCall<'a>(pub &'a [u8]);

impl<'a> RpcCall<'a> for AudioTagsCall<'a> {
    #[cfg(feature = "rpc")]
    type Reply = Option<Tags>;
    const METHOD: Method = Method::Tags;

    fn worker(&self) -> Worker {
        Worker::Audio
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Tags(self.0)
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_audio_tags(value)
    }
}

/// Typed RPC call for searching preview text.
#[derive(Debug, Clone, Copy)]
pub struct SearchFindCall<'a> {
    pub text: &'a str,
    pub pattern: &'a str,
    pub case: bool,
    pub regex: bool,
}

impl<'a> RpcCall<'a> for SearchFindCall<'a> {
    #[cfg(feature = "rpc")]
    type Reply = SearchFound;
    const METHOD: Method = Method::Find;

    fn worker(&self) -> Worker {
        Worker::Search
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Find {
            text: self.text,
            pattern: self.pattern,
            case: self.case,
            regex: self.regex,
        }
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_search_find(value)
    }
}

/// Typed RPC call for rendering a Mermaid diagram to SVG.
#[derive(Debug, Clone, Copy)]
pub struct DiagramSvgCall<'a>(pub &'a str);

impl<'a> RpcCall<'a> for DiagramSvgCall<'a> {
    #[cfg(feature = "rpc")]
    type Reply = String;
    const METHOD: Method = Method::Svg;

    fn worker(&self) -> Worker {
        Worker::Diagram
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Svg(self.0)
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_diagram_svg(value)
    }
}

/// Typed RPC call for syntax-highlighting source code.
#[derive(Debug, Clone, Copy)]
pub struct CodeHighlightCall<'a> {
    pub group: Group,
    pub language: &'a str,
    pub text: &'a str,
}

impl<'a> RpcCall<'a> for CodeHighlightCall<'a> {
    #[cfg(feature = "rpc")]
    type Reply = String;
    const METHOD: Method = Method::Highlight;

    fn worker(&self) -> Worker {
        Worker::Code(self.group)
    }

    fn into_request(self) -> Request<&'a [u8], &'a str> {
        Request::Highlight {
            language: self.language,
            text: self.text,
        }
    }

    #[cfg(feature = "rpc")]
    fn decode_reply(value: wasm_bindgen::JsValue) -> Result<Self::Reply, String> {
        decode_code_highlight(value)
    }
}

/// Interleave page dimensions or search offsets for a typed array.
pub fn pack_pairs<T: Copy>(pairs: &[(T, T)]) -> Vec<T> {
    pairs.iter().flat_map(|&(a, b)| [a, b]).collect()
}

/// Read complete pairs, returning an error if `flat` has an odd length.
pub fn unpack_pairs<T: Copy>(flat: &[T]) -> Result<Vec<(T, T)>, String> {
    let (chunks, remainder) = flat.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(format!(
            "expected an even number of elements, got {}",
            flat.len()
        ));
    }
    Ok(chunks.iter().map(|&[a, b]| (a, b)).collect())
}

/// A JavaScript number that exactly represents a `u32`.
pub fn whole_u32(value: f64) -> Option<u32> {
    (value.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(&value)).then_some(value as u32)
}

/// A JavaScript number that exactly represents a `u16`.
pub fn whole_u16(value: f64) -> Option<u16> {
    u16::try_from(whole_u32(value)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Group;

    #[test]
    fn requests_name_their_wire_method_and_worker() {
        let requests: [(Request<&[u8], &str>, _, _, _); 7] = [
            (Request::Open(&[]), "open", Method::Open, Worker::Pdf),
            (
                Request::Render {
                    doc_id: 1,
                    page: 0,
                    width: 2,
                },
                "render",
                Method::Render,
                Worker::Pdf,
            ),
            (
                Request::Close { doc_id: 1 },
                "close",
                Method::Close,
                Worker::Pdf,
            ),
            (Request::Tags(&[]), "tags", Method::Tags, Worker::Audio),
            (
                Request::Find {
                    text: "",
                    pattern: "",
                    case: true,
                    regex: false,
                },
                "find",
                Method::Find,
                Worker::Search,
            ),
            (Request::Svg(""), "svg", Method::Svg, Worker::Diagram),
            (
                Request::Highlight {
                    language: "rust",
                    text: "",
                },
                "highlight",
                Method::Highlight,
                Worker::Code(Group::Systems),
            ),
        ];
        assert_eq!(Method::ALL.len(), requests.len());
        for (request, name, method, worker) in requests {
            assert_eq!(request.method(), method);
            assert_eq!(method.as_str(), name);
            assert_eq!(Method::parse(name), Some(method));
            for kind in [
                Worker::Pdf,
                Worker::Audio,
                Worker::Search,
                Worker::Diagram,
                Worker::Code(Group::Systems),
            ] {
                assert_eq!(method.is_served_by(kind), kind == worker);
            }
        }
        for group in Group::ALL {
            assert!(Method::Highlight.is_served_by(Worker::Code(group)));
        }
        for unknown in ["", "Open", "render ", "ready", "unknown"] {
            assert_eq!(Method::parse(unknown), None);
        }
    }

    #[test]
    fn typed_rpc_calls_match_method_and_worker() {
        fn check<'a, C: RpcCall<'a>>(call: C) {
            let worker = call.worker();
            let req = call.into_request();
            assert_eq!(req.method(), C::METHOD);
            assert!(C::METHOD.is_served_by(worker));
        }
        check(PdfOpenCall(&[]));
        check(PdfRenderCall {
            doc_id: 1,
            page: 0,
            width: 100,
        });
        check(PdfCloseCall { doc_id: 1 });
        check(AudioTagsCall(&[]));
        check(SearchFindCall {
            text: "a",
            pattern: "a",
            case: true,
            regex: false,
        });
        check(DiagramSvgCall("flowchart LR\n A-->B"));
        for group in Group::ALL {
            check(CodeHighlightCall {
                group,
                language: "rust",
                text: "fn main() {}",
            });
        }
    }

    #[test]
    fn page_sizes_and_match_offsets_are_interleaved_in_order() {
        let sizes = [(0.25, 600.0), (810.5, 50.0)];
        assert_eq!(pack_pairs(&sizes), [0.25, 600.0, 810.5, 50.0]);
        assert_eq!(unpack_pairs(&pack_pairs(&sizes)).unwrap(), sizes);
        let offsets = [(0, 2), (17, u32::MAX)];
        assert_eq!(pack_pairs(&offsets), [0, 2, 17, u32::MAX]);
        assert_eq!(unpack_pairs(&pack_pairs(&offsets)).unwrap(), offsets);
        assert!(unpack_pairs(&[2, 3, 4]).is_err());
        assert!(unpack_pairs(&[1.0]).is_err());
        assert!(unpack_pairs::<u32>(&[]).unwrap().is_empty());
        assert!(pack_pairs::<f64>(&[]).is_empty());
    }

    #[test]
    fn numbers_must_be_whole_and_in_range() {
        for invalid in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1.0,
            -0.5,
            0.25,
            f64::MAX,
        ] {
            assert_eq!(whole_u32(invalid), None);
            assert_eq!(whole_u16(invalid), None);
        }
        for zero in [0.0, -0.0] {
            assert_eq!(whole_u32(zero), Some(0));
            assert_eq!(whole_u16(zero), Some(0));
        }
        let max16 = f64::from(u16::MAX);
        assert_eq!(whole_u16(max16), Some(u16::MAX));
        assert_eq!(whole_u16(max16 + 0.5), None);
        assert_eq!(whole_u16(max16 + 1.0), None);
        assert_eq!(whole_u32(max16 + 1.0), Some(65_536));
        let max32 = f64::from(u32::MAX);
        assert_eq!(whole_u32(max32), Some(u32::MAX));
        assert_eq!(whole_u32(max32 + 0.5), None);
        assert_eq!(whole_u32(max32 + 1.0), None);
        assert_eq!(whole_u16(max32), None);
    }
}
