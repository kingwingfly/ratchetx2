use js_sys::{Array, ArrayBuffer, Float64Array, Uint8Array, Uint8ClampedArray, Uint32Array};
use wasm_bindgen::{JsCast, JsValue};

use super::{
    Method, PdfOpened, RenderedPage, Request, Response, SearchFound, Tags, pack_pairs,
    unpack_pairs, whole_u16, whole_u32,
};
use crate::READY;

/// A `postMessage` value and the backing buffers whose ownership moves with it.
pub struct WirePayload {
    pub value: JsValue,
    pub transfer: Option<Array>,
}

impl WirePayload {
    pub fn new(value: impl Into<JsValue>) -> Self {
        Self {
            value: value.into(),
            transfer: None,
        }
    }

    fn with_buffer(value: impl Into<JsValue>, buffer: ArrayBuffer) -> Self {
        Self {
            value: value.into(),
            transfer: Some(Array::of1(&buffer)),
        }
    }
}

/// Encode `[id, method, ...arguments]`. Borrowed file bytes go straight into a transferable
/// `Uint8Array`.
pub fn encode_request_frame(id: u32, request: Request<&[u8], &str>) -> WirePayload {
    let frame = Array::of2(&id.into(), &request.method().as_str().into());
    match request {
        Request::Open(data) | Request::Tags(data) => {
            let bytes = Uint8Array::from(data);
            frame.push(&bytes);
            return WirePayload::with_buffer(frame, bytes.buffer());
        }
        Request::Render {
            doc_id,
            page,
            width,
        } => {
            frame.push_many(&[doc_id.into(), page.into(), width.into()]);
        }
        Request::Close { doc_id } => {
            frame.push(&doc_id.into());
        }
        Request::Find {
            text,
            pattern,
            case,
            regex,
        } => {
            frame.push_many(&[text.into(), pattern.into(), case.into(), regex.into()]);
        }
        Request::Svg(source) => {
            frame.push(&source.into());
        }
        Request::Highlight { language, text } => {
            frame.push_many(&[language.into(), text.into()]);
        }
    }
    WirePayload::new(frame)
}

// js-sys uses Array::is_array for the checked cast to Array, including across JS realms.
fn array(value: JsValue) -> Result<Array, String> {
    value
        .dyn_into()
        .map_err(|_| "expected an array".to_string())
}

fn fields<const N: usize>(array: &Array, offset: u32) -> Result<[JsValue; N], String> {
    let expected = offset + N as u32;
    let actual = array.length();
    if actual != expected {
        return Err(format!("expected {expected} array elements, got {actual}"));
    }
    Ok(std::array::from_fn(|i| array.get(offset + i as u32)))
}

fn tuple<const N: usize>(value: JsValue) -> Result<[JsValue; N], String> {
    fields(&array(value)?, 0)
}

fn string(value: JsValue) -> Result<String, String> {
    value
        .as_string()
        .ok_or_else(|| "expected a string".to_string())
}

fn boolean(value: JsValue) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| "expected a boolean".to_string())
}

fn number(value: JsValue) -> Result<u32, String> {
    value
        .as_f64()
        .and_then(whole_u32)
        .ok_or_else(|| "expected a whole u32".to_string())
}

fn bytes(value: JsValue) -> Result<Vec<u8>, String> {
    Ok(value
        .dyn_into::<Uint8Array>()
        .map_err(|_| "expected a Uint8Array")?
        .to_vec())
}

/// An incoming request envelope. Read the ID first so even an unknown method or malformed
/// argument can receive an error reply with its original ID.
pub struct RequestFrame {
    /// Echo this value in the reply. The web client uses a `u32`.
    pub id: JsValue,
    frame: Array,
}

impl RequestFrame {
    pub fn decode(data: JsValue) -> Result<Self, String> {
        let frame = array(data)?;
        if frame.length() == 0 {
            return Err("missing request ID".into());
        }
        Ok(Self {
            id: frame.get(0),
            frame,
        })
    }

    pub(crate) fn method_name(&self) -> Result<String, String> {
        string(self.frame.get(1))
    }

    // The original public worker::serve callback accepts a method name and an argument array.
    #[cfg(feature = "worker")]
    pub(crate) fn raw_arguments(&self) -> Array {
        self.frame.slice(2, self.frame.length())
    }

    /// Decode the method and its positional arguments into owned Rust values.
    pub fn request(&self) -> Result<Request, String> {
        let name = self.method_name()?;
        let method = Method::parse(&name).ok_or_else(|| format!("no method {name}"))?;
        Ok(match method {
            Method::Open => {
                let [data] = fields(&self.frame, 2)?;
                Request::Open(bytes(data)?)
            }
            Method::Render => {
                let [doc_id, page, width] = fields(&self.frame, 2)?;
                Request::Render {
                    doc_id: number(doc_id)?,
                    page: number(page)?,
                    width: number(width)?,
                }
            }
            Method::Close => {
                let [doc_id] = fields(&self.frame, 2)?;
                Request::Close {
                    doc_id: number(doc_id)?,
                }
            }
            Method::Tags => {
                let [data] = fields(&self.frame, 2)?;
                Request::Tags(bytes(data)?)
            }
            Method::Find => {
                let [text, pattern, case, regex] = fields(&self.frame, 2)?;
                Request::Find {
                    text: string(text)?,
                    pattern: string(pattern)?,
                    case: boolean(case)?,
                    regex: boolean(regex)?,
                }
            }
            Method::Svg => {
                let [source] = fields(&self.frame, 2)?;
                Request::Svg(string(source)?)
            }
            Method::Highlight => {
                let [language, text] = fields(&self.frame, 2)?;
                Request::Highlight {
                    language: string(language)?,
                    text: string(text)?,
                }
            }
        })
    }
}

impl Response {
    /// Encode a success value, including the transfer list for any typed array.
    pub fn encode(self) -> WirePayload {
        match self {
            Self::Opened(PdfOpened { doc_id, sizes }) => {
                let sizes = Float64Array::from(pack_pairs(&sizes).as_slice());
                WirePayload::with_buffer(Array::of2(&doc_id.into(), &sizes), sizes.buffer())
            }
            Self::Rendered(page) => {
                let pixels = Uint8ClampedArray::from(page.pixels.as_slice());
                WirePayload::with_buffer(
                    Array::of3(&page.width.into(), &page.height.into(), &pixels),
                    pixels.buffer(),
                )
            }
            Self::Closed => WirePayload::new(JsValue::UNDEFINED),
            Self::Tags(None) => WirePayload::new(JsValue::NULL),
            Self::Tags(Some(tags)) => encode_tags(tags),
            Self::Found(found) => {
                let matches = Uint32Array::from(pack_pairs(&found.matches).as_slice());
                WirePayload::with_buffer(Array::of2(&matches, &found.more.into()), matches.buffer())
            }
            Self::Svg(text) | Self::Highlighted(text) => WirePayload::new(text),
        }
    }
}

fn encode_tags(tags: Tags) -> WirePayload {
    let fields = Array::of4(
        &tags.title.map_or(JsValue::NULL, JsValue::from),
        &tags.artist.map_or(JsValue::NULL, JsValue::from),
        &tags.album.map_or(JsValue::NULL, JsValue::from),
        &tags.year.map_or(JsValue::NULL, JsValue::from),
    );
    match tags.cover {
        Some((mime, data)) => {
            let cover = Uint8Array::from(data.as_slice());
            fields.push(&mime.into());
            fields.push(&cover);
            WirePayload::with_buffer(fields, cover.buffer())
        }
        None => {
            fields.push_many(&[JsValue::NULL, JsValue::NULL]);
            WirePayload::new(fields)
        }
    }
}

/// Wrap a method result in `[id, true, value]` or `[id, false, error_string]`.
pub fn encode_reply_frame(id: &JsValue, result: Result<WirePayload, String>) -> WirePayload {
    match result {
        Ok(payload) => WirePayload {
            value: Array::of3(id, &JsValue::TRUE, &payload.value).into(),
            transfer: payload.transfer,
        },
        Err(error) => WirePayload::new(Array::of3(id, &JsValue::FALSE, &error.into())),
    }
}

/// A worker notification or a reply to a numbered client call.
#[derive(Debug)]
pub enum WorkerEvent {
    Ready,
    Reply {
        id: u32,
        result: Result<JsValue, JsValue>,
    },
}

impl WorkerEvent {
    /// Decode `MessageEvent.data()` from a worker, validating the call ID and status.
    pub fn decode(data: JsValue) -> Result<Self, String> {
        if data.as_string().as_deref() == Some(READY) {
            return Ok(Self::Ready);
        }
        let [id, ok, value] = tuple(data)?;
        let id = number(id)?;
        let result = if boolean(ok)? {
            Ok(value)
        } else if value.is_string() {
            Err(value)
        } else {
            return Err("expected a worker error string".into());
        };
        Ok(Self::Reply { id, result })
    }
}

/// Decode `[doc_id, Float64Array]` into an ID and width/height pairs in points.
pub fn decode_pdf_open(value: JsValue) -> Result<PdfOpened, String> {
    let [id, sizes] = tuple(value)?;
    let doc_id = number(id)?;
    let sizes = sizes
        .dyn_into::<Float64Array>()
        .map_err(|_| "expected a Float64Array of page sizes")?;
    Ok(PdfOpened {
        doc_id,
        sizes: unpack_pairs(&sizes.to_vec()),
    })
}

/// Keep the transferred pixel array in JavaScript for use with `ImageData`.
pub fn decode_pdf_render(value: JsValue) -> Result<RenderedPage<Uint8ClampedArray>, String> {
    let [width, height, pixels] = tuple(value)?;
    let (width, height) = (number(width)?, number(height)?);
    let pixels = pixels
        .dyn_into::<Uint8ClampedArray>()
        .map_err(|_| "expected Uint8ClampedArray pixels")?;
    let byte_len = width
        .checked_mul(height)
        .and_then(|area| area.checked_mul(4));
    if width == 0 || height == 0 || byte_len != Some(pixels.length()) {
        return Err("pixel buffer does not match the page dimensions".into());
    }
    Ok(RenderedPage {
        width,
        height,
        pixels,
    })
}

/// A successful close returns `undefined`.
pub fn decode_pdf_close(value: JsValue) -> Result<(), String> {
    value
        .is_undefined()
        .then_some(())
        .ok_or_else(|| "expected undefined".into())
}

fn nullable<T>(
    value: JsValue,
    decode: impl FnOnce(JsValue) -> Result<T, String>,
) -> Result<Option<T>, String> {
    if value.is_null() {
        Ok(None)
    } else {
        decode(value).map(Some)
    }
}

/// Decode nullable tags and their optional cover MIME type and bytes.
pub fn decode_audio_tags(value: JsValue) -> Result<Option<Tags>, String> {
    nullable(value, |value| {
        let [title, artist, album, year, mime, cover] = tuple(value)?;
        let cover = if mime.is_null() && cover.is_null() {
            None
        } else {
            Some((string(mime)?, bytes(cover)?))
        };
        Ok(Tags {
            title: nullable(title, string)?,
            artist: nullable(artist, string)?,
            album: nullable(album, string)?,
            year: nullable(year, |v| {
                v.as_f64()
                    .and_then(whole_u16)
                    .ok_or_else(|| "expected a whole u16 year".into())
            })?,
            cover,
        })
    })
}

/// Decode `[Uint32Array, more]` into UTF-16 start/end pairs and whether more matches were found.
pub fn decode_search_find(value: JsValue) -> Result<SearchFound, String> {
    let [matches, more] = tuple(value)?;
    let matches = matches
        .dyn_into::<Uint32Array>()
        .map_err(|_| "expected a Uint32Array of search offsets")?;
    Ok(SearchFound {
        matches: unpack_pairs(&matches.to_vec()),
        more: boolean(more)?,
    })
}

/// Read the SVG returned by the diagram worker.
pub fn decode_diagram_svg(value: JsValue) -> Result<String, String> {
    string(value)
}

/// Read the highlighted HTML returned by a code worker.
pub fn decode_code_highlight(value: JsValue) -> Result<String, String> {
    string(value)
}
