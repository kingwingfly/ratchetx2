//! The preview workers' requests and replies. The `rpc` feature adds their JavaScript
//! `postMessage` encoding, including transfer lists for buffers sent in either direction.
//!
//! With that feature, clients pass borrowed requests to `encode_request_frame`, post the
//! returned value with its transfer list, and dispatch `WorkerEvent::Reply` to the method's
//! decoder. Workers read `RequestFrame::request` and wrap `Response::encode` or a method
//! error with `encode_reply_frame`.

use crate::Worker;
pub use crate::audio::Tags;

#[cfg(feature = "rpc")]
mod wire;
#[cfg(feature = "rpc")]
pub use wire::*;

/// A method name in a request frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Open,
    Render,
    Close,
    Tags,
    Find,
    Svg,
    Highlight,
}

impl Method {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Render => "render",
            Self::Close => "close",
            Self::Tags => "tags",
            Self::Find => "find",
            Self::Svg => "svg",
            Self::Highlight => "highlight",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [
            Self::Open,
            Self::Render,
            Self::Close,
            Self::Tags,
            Self::Find,
            Self::Svg,
            Self::Highlight,
        ]
        .into_iter()
        .find(|method| method.as_str() == name)
    }

    /// Whether this worker handles the method. The language selects the code worker group.
    pub const fn is_served_by(self, worker: Worker) -> bool {
        matches!(
            (self, worker),
            (Self::Open | Self::Render | Self::Close, Worker::Pdf)
                | (Self::Tags, Worker::Audio)
                | (Self::Find, Worker::Search)
                | (Self::Svg, Worker::Diagram)
                | (Self::Highlight, Worker::Code(_))
        )
    }
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

/// The worker-local document ID and each page's width and height in points.
#[derive(Debug, Clone, PartialEq)]
pub struct PdfOpened {
    pub doc_id: u32,
    pub sizes: Vec<(f64, f64)>,
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
    Rendered(RenderedPage),
    Closed,
    Tags(Option<Tags>),
    Found(SearchFound),
    Svg(String),
    Highlighted(String),
}

/// Interleave page dimensions or search offsets for a typed array.
pub fn pack_pairs<T: Copy>(pairs: &[(T, T)]) -> Vec<T> {
    pairs.iter().flat_map(|&(a, b)| [a, b]).collect()
}

/// Read complete pairs, ignoring an unpaired trailing value as the web client does.
pub fn unpack_pairs<T: Copy>(flat: &[T]) -> Vec<(T, T)> {
    flat.as_chunks::<2>()
        .0
        .iter()
        .map(|&[a, b]| (a, b))
        .collect()
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
    fn page_sizes_and_match_offsets_are_interleaved_in_order() {
        let sizes = [(0.25, 600.0), (810.5, 50.0)];
        assert_eq!(pack_pairs(&sizes), [0.25, 600.0, 810.5, 50.0]);
        assert_eq!(unpack_pairs(&pack_pairs(&sizes)), sizes);
        let offsets = [(0, 2), (17, u32::MAX)];
        assert_eq!(pack_pairs(&offsets), [0, 2, 17, u32::MAX]);
        assert_eq!(unpack_pairs(&pack_pairs(&offsets)), offsets);
        assert_eq!(unpack_pairs(&[2, 3, 4]), [(2, 3)]);
        assert!(unpack_pairs(&[1.0]).is_empty());
        assert!(unpack_pairs::<u32>(&[]).is_empty());
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
