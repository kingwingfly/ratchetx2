The E2EE chat [web client](../e2ee_chat_web)'s file previews that are too large to load with the page, each in a web worker the page starts when a preview first needs it, which also keeps the work off the page's thread:

- `preview_pdf`: PDF pages, drawn to pixels by [hayro](https://github.com/LaurenzV/hayro), a page at a time. Encrypted PDFs do not open.
- `preview_diagram`: Mermaid diagrams, laid out and drawn to SVG by [merman](https://github.com/Latias94/merman), in Mermaid's dark theme, without the ELK layout, which is under the EPL-2.0.
- `preview_code_web`, `preview_code_systems`, `preview_code_apps` and `preview_code_scripts`: code highlighted by tree-sitter, with [arborium](https://github.com/bearcove/arborium)'s grammars. The grammars of all 39 languages would make a file larger than Cloudflare serves (25 MiB), so four workers share them, as `src/language.rs` lists, each with languages written together, as HTML is with JavaScript and CSS, whose grammars it embeds.

The web client's trunk build compiles them, and the web client takes only the table of languages, with no features. The grammars are C, so they need clang with its WebAssembly target and `llvm-ar`.

```sh
cargo test -p e2ee_chat_preview --all-features
```

To highlight another language, add its arborium crate to `Cargo.toml` and the `code` feature, its grammar to a group in `src/code.rs`, and the language, with its extensions and names, to `src/language.rs`; a test checks that each language's group has its grammar.
