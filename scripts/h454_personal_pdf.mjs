// Browser-free PDF creation for personal Commander. All assets are pinned by
// the enclosing release manifest; the caller must authorize both paths first.
import path from 'node:path';
import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

const requireBundle = createRequire(new URL('../bundle/package.json', import.meta.url));
const requireAssets = createRequire(import.meta.url);
const MAX_CHARS = 32000;
const MAX_PAGES = 100;

function paragraphs(tokens) {
  const result = [];
  let heading = false;
  const lists = [];
  let itemPrefix = '';
  for (const token of tokens) {
    if (token.type === 'heading_open') heading = true;
    else if (token.type === 'heading_close') heading = false;
    else if (token.type === 'bullet_list_open') lists.push({ ordered: false });
    else if (token.type === 'ordered_list_open') lists.push({ ordered: true, next: Number(token.attrGet('start') ?? 1) });
    else if (token.type === 'bullet_list_close' || token.type === 'ordered_list_close') lists.pop();
    else if (token.type === 'list_item_open') {
      const list = lists[lists.length - 1];
      itemPrefix = list?.ordered ? `${list.next++}. ` : '- ';
    }
    else if (token.type === 'inline') {
      let text = itemPrefix;
      itemPrefix = '';
      for (const part of token.children ?? []) {
        if (part.type === 'image') throw new Error('H454_PDF_IMAGE_UNSUPPORTED');
        if (['text', 'code_inline', 'html_inline'].includes(part.type)) text += part.content;
        if (['softbreak', 'hardbreak'].includes(part.type)) text += '\n';
      }
      result.push({ text, size: heading ? 16 : 11 });
    } else if (['fence', 'code_block', 'html_block'].includes(token.type)) {
      result.push({ text: token.content, size: 10 });
    }
  }
  return result.length ? result : [{ text: '', size: 11 }];
}

export async function createPersonalPdf(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args) ||
      Object.keys(args).some(key => !['path', 'outputPath', 'content', 'options'].includes(key)) ||
      typeof args.path !== 'string' || typeof args.content !== 'string' ||
      args.content.length > MAX_CHARS || args.content.includes('\0') ||
      (args.outputPath !== undefined && typeof args.outputPath !== 'string') ||
      (args.options !== undefined && (!args.options || typeof args.options !== 'object' ||
        Array.isArray(args.options) || Object.keys(args.options).length)))
    throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
  const target = args.outputPath ?? args.path;
  if (path.extname(target).toLowerCase() !== '.pdf') throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
  // Rendering never opens external or local resources. Reject markup that
  // would otherwise look like a successfully rendered image or HTML.
  if (/!\[[^\]\n]*\]\s*\(/.test(args.content) || /<\/?[a-z][a-z0-9-]*(?:\s|\/?>)/i.test(args.content))
    throw new Error('H454_PDF_MARKUP_UNSUPPORTED');

  const { PDFDocument } = requireBundle('pdf-lib');
  const MarkdownIt = requireBundle('markdown-it');
  const fontkit = requireAssets('../third_party/h454-fontkit.cjs');
  const fontBytes = await readFile(new URL('../third_party/h454-DejaVuSans.ttf', import.meta.url));
  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  const font = await doc.embedFont(fontBytes, { subset: true });
  const supported = new Set(font.getCharacterSet());
  const lines = paragraphs(new MarkdownIt({ html: false, linkify: false }).parse(args.content, {}));
  let page, y, pages = 0;
  function nextPage() {
    if (++pages > MAX_PAGES) throw new Error('H454_PDF_TOO_LARGE');
    page = doc.addPage([595.28, 841.89]);
    y = 800;
  }
  function draw(text, size) {
    const step = size * 1.35;
    if (y - step < 42) nextPage();
    if (text) page.drawText(text, { x: 42, y, size, font });
    y -= step;
  }
  nextPage();
  for (const block of lines) {
    for (const cp of block.text) {
      const code = cp.codePointAt(0);
      if (code !== 10 && code !== 13 && code !== 9 && !supported.has(code))
        throw new Error('H454_PDF_GLYPH_UNSUPPORTED');
    }
    for (const original of block.text.replace(/\r\n?/g, '\n').split('\n')) {
      let line = '';
      for (const ch of original.replace(/\t/g, '    ')) {
        if (font.widthOfTextAtSize(line + ch, block.size) > 510 && line) {
          draw(line, block.size);
          line = '';
        }
        line += ch;
      }
      draw(line, block.size);
    }
    y -= 5;
  }
  const bytes = await doc.save();
  if (bytes.length > 8 * 1024 * 1024) throw new Error('H454_PDF_TOO_LARGE');
  await writeFile(target, bytes, { flag: 'wx' });
  return { content: [{ type: 'text', text: `Successfully created PDF: ${target}` }] };
}
