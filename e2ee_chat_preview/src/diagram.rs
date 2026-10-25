//! Mermaid diagrams as SVG, laid out and drawn by merman, in Mermaid's dark theme. The SVG holds
//! no script, and the page shows it as an image, where none would run.

use merman::{
    Engine, MermaidConfig, OperationControl, RenderOutput, RenderRequest, Renderer, SvgRequest,
};

/// The Mermaid diagram `source`, as SVG, sized as it is drawn.
pub fn svg(source: &str) -> Result<String, String> {
    let theme = MermaidConfig::from_value(serde_json::json!({ "theme": "dark" }));
    let renderer = Renderer::new().with_engine(Engine::new().with_site_config(theme));
    let request = RenderRequest::svg(source, OperationControl::new(), SvgRequest::default());
    match renderer.render(request) {
        Ok(RenderOutput::Svg(Some(svg))) => Ok(sized(svg.svg())),
        Ok(_) => Err("not a Mermaid diagram".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// `svg` with the width and height of its view box, in place of a width of 100% that fills what
/// it is in: as an image, that leaves it no size of its own.
fn sized(svg: &str) -> String {
    let Some(end) = svg.find('>') else {
        return svg.to_string();
    };
    let (root, rest) = svg.split_at(end);
    let Some([_, _, width, height]) =
        attribute(root, "viewBox").and_then(|view| -> Option<[f64; 4]> {
            let numbers: Vec<f64> = view
                .split([' ', ','])
                .filter(|n| !n.is_empty())
                .filter_map(|n| n.parse().ok())
                .collect();
            numbers.try_into().ok()
        })
    else {
        return svg.to_string();
    };
    let mut root = root.to_string();
    for name in ["width", "height", "style"] {
        if let Some(value) = attribute(&root, name) {
            root = root.replacen(&format!(r#" {name}="{value}""#), "", 1);
        }
    }
    format!(r#"{root} width="{width}" height="{height}"{rest}"#)
}

/// The value of the attribute `name` of the start tag `tag`.
fn attribute<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let start = tag.find(&format!(r#" {name}=""#))? + name.len() + 3;
    let end = start + tag[start..].find('"')?;
    Some(&tag[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flowchart() {
        let svg = svg("flowchart LR\n  A[Alice] --> W[Worker] --> B[Bob]").unwrap();
        let root = &svg[..svg.find('>').unwrap()];
        assert!(!root.contains("100%"), "{root}");
        assert!(attribute(root, "width").is_some_and(|w| w.parse::<f64>().unwrap() > 100.0));
        assert!(attribute(root, "height").is_some_and(|h| h.parse::<f64>().unwrap() > 10.0));
        assert!(svg.contains("Alice") && svg.contains("Bob"));
        assert!(!svg.contains("<script"));
    }

    #[test]
    fn sequence_diagram() {
        assert!(svg("sequenceDiagram\n  Alice->>Bob: hi\n  Bob-->>Alice: hello").is_ok());
    }

    #[test]
    fn not_a_diagram() {
        assert!(svg("this is not mermaid").is_err());
    }

    #[test]
    fn sizes_from_the_view_box() {
        assert_eq!(
            sized(
                r#"<svg id="m" width="100%" style="max-width: 572px;" viewBox="0 0 572 61"><g/></svg>"#
            ),
            r#"<svg id="m" viewBox="0 0 572 61" width="572" height="61"><g/></svg>"#
        );
    }
}
