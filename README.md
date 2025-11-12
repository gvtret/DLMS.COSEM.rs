# DLMS.COSEM.rs

An experimental implementation of the DLMS/COSEM (SPODES) stack with utilities for
documenting the supported association flows and object models. The implementation
tracks the guidance from the Russian industry standard СТО 34.01-5.1-013-2023 and
the IEC 62056 family of specifications that define compliant DLMS/COSEM behaviour.

## Documentation toolchain

The repository ships with a documentation generator that extracts API comments,
converts the authoritative PDF references located in `docs/`, and renders the
architecture diagrams hosted under `diagrams/`. Run the helper script after
installing the required dependencies:

```bash
sudo apt-get update
sudo apt-get install -y doxygen graphviz plantuml pandoc wkhtmltopdf poppler-utils
./scripts/generate_docs.sh
```

The script produces a bundle in `docs/generated/` containing:

- Doxygen HTML for the Rust sources under `dlms-cosem-rs/src/`.
- A Markdown index that links to PlantUML diagrams and to Markdown conversions of
  each PDF reference (including `docs/СТО 34.01-5.1-013-2023.pdf`).
- Page-by-page figure extractions for every converted PDF, making it easier to
  embed specific visuals in supplementary documentation.

These assets are uploaded in CI so reviewers can inspect the generated output
without rebuilding locally.

## Workspace layout

- `dlms-cosem-rs/` — Rust crate implementing the DLMS/COSEM protocol surface.
- `diagrams/` — PlantUML diagrams describing server, client, and security flows.
- `docs/` — Source documents (PDF/DOCX/TXT) collected from IEC 62056 and СТО
  34.01-5.1-013-2023 publications.
- `scripts/` — Tooling used for documentation and CI automation.

## Contributing

Before submitting a change:

1. Format the Rust sources with `cargo fmt`.
2. Run `cargo clippy --all-targets --all-features` and resolve any warnings.
3. Execute the full test suite via `cargo test --all-features`.
4. Regenerate the documentation bundle when protocol logic changes.

These checks are enforced in CI through `.github/workflows/rust.yml`.
