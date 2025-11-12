#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCS_DIR="$ROOT_DIR/docs/generated"
PLANTUML_OUTPUT_DIR="$DOCS_DIR/plantuml"
MARKDOWN_OUTPUT_DIR="$DOCS_DIR/markdown"

REQUIRED_TOOLS=(doxygen plantuml pandoc wkhtmltopdf pdftohtml pdftoppm)
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: required tool '$tool' is not installed." >&2
    exit 1
  fi
done

shopt -s nullglob

rm -rf "$DOCS_DIR"
mkdir -p "$PLANTUML_OUTPUT_DIR" "$MARKDOWN_OUTPUT_DIR"
PDF_MARKDOWN_DIR="$MARKDOWN_OUTPUT_DIR/pdfs"
mkdir -p "$PDF_MARKDOWN_DIR"

echo "Generating API documentation with Doxygen..."
doxygen "$ROOT_DIR/docs/Doxyfile"

generated_diagrams=()

if compgen -G "$ROOT_DIR/diagrams/*.puml" > /dev/null; then
  echo "Rendering PlantUML diagrams to SVG and PDF..."
  pushd "$ROOT_DIR/diagrams" >/dev/null
  plantuml -tsvg -o ../docs/generated/plantuml *.puml
  plantuml -tpdf -o ../docs/generated/plantuml *.puml
  popd >/dev/null
  for diagram in "$PLANTUML_OUTPUT_DIR"/*.svg; do
    diagram_base="$(basename "$diagram" .svg)"
    generated_diagrams+=("$diagram_base")
  done
else
  echo "No PlantUML diagrams found under $ROOT_DIR/diagrams." >&2
fi

echo "Converting Markdown documentation..."
pandoc "$ROOT_DIR/README.md" -o "$MARKDOWN_OUTPUT_DIR/README.html"
pandoc "$ROOT_DIR/README.md" -o "$MARKDOWN_OUTPUT_DIR/README.pdf" --pdf-engine=wkhtmltopdf

echo "Converting PDF documents to Markdown with embedded page figures..."
converted_pdfs=()
for pdf_file in "$ROOT_DIR"/docs/*.pdf; do
  [ -e "$pdf_file" ] || continue
  pdf_basename="$(basename "$pdf_file")"
  pdf_name="${pdf_basename%.*}"
  safe_name="${pdf_name// /_}"
  tmp_dir="$(mktemp -d)"
  html_output="$tmp_dir/$safe_name.html"
  image_dir="$PDF_MARKDOWN_DIR/${safe_name}_figures"
  markdown_output="$PDF_MARKDOWN_DIR/${safe_name}.md"

  echo "  Processing $pdf_basename"

  pdftohtml -c -noframes "$pdf_file" "$html_output" >/dev/null 2>&1
  if [ ! -f "$html_output" ]; then
    echo "    Failed to convert $pdf_basename to HTML" >&2
    rm -rf "$tmp_dir"
    continue
  fi

  pandoc "$html_output" -f html -t gfm -o "$markdown_output"

  mkdir -p "$image_dir"
  pdftoppm -png "$pdf_file" "$image_dir/page" >/dev/null 2>&1

  if compgen -G "$image_dir/page*.png" > /dev/null; then
    {
      echo ""
      echo "## Extracted Figures"
    } >> "$markdown_output"
    page_index=1
    for image in "$image_dir"/page*.png; do
      image_file="$(basename "$image")"
      echo "![$pdf_name page $page_index](${safe_name}_figures/$image_file)" >> "$markdown_output"
      page_index=$((page_index + 1))
    done
  fi

  rm -rf "$tmp_dir"

  converted_pdfs+=("$pdf_basename|$safe_name")
done

index_file="$MARKDOWN_OUTPUT_DIR/index.md"
{
  echo "# Documentation Bundle"
  echo ""

  echo "## Project Overview"
  echo ""
  echo "- [README (HTML)](README.html)"
  echo "- [README (PDF)](README.pdf)"
  echo ""

  echo "## Converted PDF References"
  echo ""
  if [ "${#converted_pdfs[@]}" -eq 0 ]; then
    echo "No PDF sources were found under docs/."
  else
    for entry in "${converted_pdfs[@]}"; do
      pdf_basename="${entry%%|*}"
      safe_name="${entry##*|}"
      echo "- [${pdf_basename}](pdfs/${safe_name}.md)"
    done
  fi

  echo ""
  echo "## PlantUML Diagrams"
  echo ""
  if [ "${#generated_diagrams[@]}" -eq 0 ]; then
    echo "No PlantUML diagrams were rendered."
  else
    for diagram_base in "${generated_diagrams[@]}"; do
      echo "### ${diagram_base}"
      echo ""
      echo "![${diagram_base}](../plantuml/${diagram_base}.svg)"
      echo ""
    done
  fi
} > "$index_file"

echo "Documentation generated under $DOCS_DIR."
