# E2EE Preview Smoke Document

This Markdown document exercises the Mermaid diagram worker (`preview_diagram`) and search (`preview_search`) for `MERMAID_NEEDLE_TOKEN`.

```mermaid
flowchart LR
    Alice[Alice Vault] --> Relay[Worker Relay]
    Relay --> Bob[Bob Vault]
```

```rust
fn check() -> bool {
    true
}
```
