mod fonts;
mod preflight;
mod renderer;

use pulldown_latex::{Storage, config::DisplayMode};

use self::preflight::exceeds_tex_preflight;
use self::renderer::MathmlRenderer as Renderer;
use super::sanitize::escape;

#[cfg(test)]
pub(super) use self::renderer::MathmlRenderer;

/// Maximum `pulldown-latex` events rendered in a single expression before falling back to raw TeX.
const MATH_EVENTS_MAX: usize = 20_000;

/// The TeX `tex` as CSP-safe, HTML-escaped MathML, or HTML-escaped raw TeX on any parser or
/// rendering error.
pub(super) fn mathml(tex: &str, display_mode: DisplayMode) -> String {
    if exceeds_tex_preflight(tex) {
        return escape(tex);
    }
    let storage = Storage::new();
    let parser = pulldown_latex::Parser::new(tex, &storage);
    let mut events = Vec::new();
    for event in parser {
        let Ok(event) = event else {
            return escape(tex);
        };
        if events.len() >= MATH_EVENTS_MAX {
            return escape(tex);
        }
        events.push(event);
    }
    match Renderer::new(&events, display_mode).render() {
        Ok(rendered) => rendered,
        Err(()) => escape(tex),
    }
}
