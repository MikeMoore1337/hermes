# Personal Commander PDF assets

Personal Commander creates basic text and Markdown PDFs without launching a
browser. It uses the `pdf-lib` and `markdown-it` already in the verified BRC
bundle, plus these pinned local inputs:

- `@pdf-lib/fontkit` 1.1.1, from the official npm registry, SHA-256
  `6dd0ae9209fce419b2ed76c97166863167b4df56d75fbe3c7f1d1e6e49c85867`.
  Upstream package metadata and README declare MIT. Staging retains its
  unchanged bundled source, README, package metadata and embedded notices.
  The published package does not contain a separate LICENSE file.
- DejaVu Sans from the installed DejaVu fonts package, SHA-256
  `ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280`.
  Staging retains the accompanying Bitstream Vera/DejaVu copyright notice.

`scripts.h454_personal_pdf_assets.stage` verifies all three source inputs and
the selected archive members before adding them to a disposable release's
`third_party` directory. The normal release manifest must cover the resulting
files. Staging does not download dependencies or execute package hooks.

The tool creates a **new** PDF from basic Markdown and approved local PNG or
JPEG images. It can insert or delete pages in an existing PDF into a distinct,
new output file, and supports page size, margins and landscape orientation.
It rejects overwrites, unsupported glyphs, HTML/CSS and network resources.
Other browser print options and HTML/CSS rendering remain unsupported; this is
not full `write_pdf` parity.
