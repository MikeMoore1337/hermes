// Browser-free PDF operations. The adapter authorizes every returned path.
import path from 'node:path';
import { readFile, lstat, open, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { createRequire } from 'node:module';

const requireBundle = createRequire(new URL('../bundle/package.json', import.meta.url));
const requireAssets = createRequire(import.meta.url);
const MAX_CHARS = 32000, MAX_PAGES = 100, MAX_INPUT = 8 * 1024 * 1024, MAX_IMAGES = 16;

function markdownTokens(value) {
  if (typeof value !== 'string' || value.length > MAX_CHARS || value.includes('\0'))
    throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
  if (/<\/?[a-z][a-z0-9-]*(?:\s|\/?>)/i.test(value)) throw new Error('H454_PDF_MARKUP_UNSUPPORTED');
  const MarkdownIt = requireBundle('markdown-it');
  return new MarkdownIt({ html: false, linkify: false }).parse(value, {});
}

function imageSource(raw, base) {
  if (typeof raw !== 'string' || !raw || raw.length > 2048) throw new Error('H454_PDF_IMAGE_SOURCE_UNSUPPORTED');
  try { raw = decodeURIComponent(raw); } catch { throw new Error('H454_PDF_IMAGE_SOURCE_UNSUPPORTED'); }
  if (raw.includes('\0') || /^[a-z][a-z0-9+.-]*:/i.test(raw) && !/^[a-z]:[\\/]/i.test(raw))
    throw new Error('H454_PDF_IMAGE_SOURCE_UNSUPPORTED');
  return path.resolve(path.dirname(base), raw);
}

function blocks(value, base) {
  const result = [], lists = [];
  let heading = false, prefix = '', images = 0;
  for (const token of markdownTokens(value)) {
    if (token.type === 'heading_open') heading = true;
    else if (token.type === 'heading_close') heading = false;
    else if (token.type === 'bullet_list_open') lists.push({ ordered: false });
    else if (token.type === 'ordered_list_open') lists.push({ ordered: true, next: Number(token.attrGet('start') ?? 1) });
    else if (token.type === 'bullet_list_close' || token.type === 'ordered_list_close') lists.pop();
    else if (token.type === 'list_item_open') {
      const list = lists[lists.length - 1];
      prefix = list?.ordered ? `${list.next++}. ` : '- ';
    } else if (token.type === 'inline') {
      let text = prefix; prefix = '';
      for (const part of token.children ?? []) {
        if (part.type === 'image') {
          if (++images > MAX_IMAGES) throw new Error('H454_PDF_TOO_LARGE');
          if (text) result.push({ type: 'text', text, size: heading ? 16 : 11 });
          text = '';
          result.push({ type: 'image', source: imageSource(part.attrGet('src'), base) });
        } else if (['text', 'code_inline', 'html_inline'].includes(part.type)) {
          if (/!\[[^\]\n]*\]\s*\(/.test(part.content)) throw new Error('H454_PDF_IMAGE_SOURCE_UNSUPPORTED');
          text += part.content;
        }
        else if (['softbreak', 'hardbreak'].includes(part.type)) text += '\n';
      }
      if (text) result.push({ type: 'text', text, size: heading ? 16 : 11 });
    } else if (['fence', 'code_block', 'html_block'].includes(token.type))
      result.push({ type: 'text', text: token.content, size: 10 });
  }
  // Invalid URLs can be rendered as plain text by markdown-it; reject instead
  // of silently producing a document without the requested image.
  if (/!\[[^\]\n]*\]\s*\(/.test(value) && !images) throw new Error('H454_PDF_IMAGE_SOURCE_UNSUPPORTED');
  return result.length ? result : [{ type: 'text', text: '', size: 11 }];
}

function lengthInPoints(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value * 0.75;
  if (typeof value !== 'string') throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
  const match = /^\s*(\d+(?:\.\d+)?)(px|in|cm|mm|pt)?\s*$/i.exec(value);
  if (!match) throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
  return Number(match[1]) * ({ px: 0.75, in: 72, cm: 72 / 2.54, mm: 72 / 25.4, pt: 1 }[(match[2] || 'px').toLowerCase()]);
}

function layout(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(k => !['format', 'width', 'height', 'landscape', 'margin'].includes(k)))
    throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
  const formats = { a3: [841.89, 1190.55], a4: [595.28, 841.89], a5: [419.53, 595.28],
    letter: [612, 792], legal: [612, 1008], tabloid: [792, 1224], ledger: [1224, 792] };
  let dimensions = formats.a4;
  if (options.format !== undefined) {
    if (typeof options.format !== 'string' || !formats[options.format.toLowerCase()]) throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
    dimensions = formats[options.format.toLowerCase()];
  } else if (options.width !== undefined || options.height !== undefined) {
    if (options.width === undefined || options.height === undefined) throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
    dimensions = [lengthInPoints(options.width), lengthInPoints(options.height)];
  }
  if (options.landscape !== undefined && typeof options.landscape !== 'boolean') throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
  let [width, height] = dimensions;
  if (options.landscape && width < height) [width, height] = [height, width];
  const margin = options.margin ?? 56;
  let margins;
  if (typeof margin === 'object' && margin !== null && !Array.isArray(margin)) {
    if (Object.keys(margin).some(k => !['top', 'right', 'bottom', 'left'].includes(k))) throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
    margins = Object.fromEntries(['top', 'right', 'bottom', 'left'].map(k => [k, lengthInPoints(margin[k] ?? 0)]));
  } else {
    const size = lengthInPoints(margin);
    margins = { top: size, right: size, bottom: size, left: size };
  }
  if (width < 144 || height < 144 || width > 2000 || height > 2000 ||
      Object.values(margins).some(n => n < 0 || n > 1000) ||
      width - margins.left - margins.right < 72 || height - margins.top - margins.bottom < 72)
    throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
  return { width, height, ...margins };
}

function validateArgs(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args) ||
      Object.keys(args).some(key => !['path', 'outputPath', 'content', 'options'].includes(key)) ||
      typeof args.path !== 'string' || (args.outputPath !== undefined && typeof args.outputPath !== 'string') ||
      (args.options !== undefined && (!args.options || typeof args.options !== 'object' ||
        Array.isArray(args.options) || Object.keys(args.options).some(k => k !== 'pdf_options'))))
    throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
  layout(args.options?.pdf_options);
  const target = args.outputPath ?? args.path;
  if (path.extname(args.path).toLowerCase() !== '.pdf' || path.extname(target).toLowerCase() !== '.pdf')
    throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
  const paths = [args.path, target];
  if (typeof args.content === 'string') {
    for (const item of blocks(args.content, args.path)) if (item.type === 'image') paths.push(item.source);
  } else if (Array.isArray(args.content) && args.content.length > 0 && args.content.length <= 32) {
    if (!args.outputPath || path.resolve(args.path).toLowerCase() === path.resolve(target).toLowerCase())
      throw new Error('H454_PDF_OUTPUT_REQUIRED');
    for (const op of args.content) {
      if (!op || typeof op !== 'object' || Array.isArray(op)) throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
      if (op.type === 'delete') {
        if (Object.keys(op).some(k => !['type', 'pageIndexes'].includes(k)) ||
            !Array.isArray(op.pageIndexes) || !op.pageIndexes.length || op.pageIndexes.length > MAX_PAGES ||
            op.pageIndexes.some(i => !Number.isSafeInteger(i))) throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
      } else if (op.type === 'insert') {
        if (Object.keys(op).some(k => !['type', 'pageIndex', 'markdown', 'sourcePdfPath', 'pdfOptions'].includes(k)) ||
            !Number.isSafeInteger(op.pageIndex) || (typeof op.markdown === 'string') ===
            (typeof op.sourcePdfPath === 'string')) throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
        if (typeof op.sourcePdfPath === 'string') {
          if (op.pdfOptions !== undefined) throw new Error('H454_PDF_OPTIONS_UNSUPPORTED');
          paths.push(op.sourcePdfPath);
        } else {
          layout(op.pdfOptions);
          for (const item of blocks(op.markdown, args.path)) if (item.type === 'image') paths.push(item.source);
        }
      } else throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
    }
  } else throw new Error('H454_PDF_ARGUMENT_UNSUPPORTED');
  if (paths.length > 32) throw new Error('H454_PDF_TOO_LARGE');
  return paths;
}

export function personalPdfPaths(args) { return validateArgs(args); }

async function boundedRead(file, maximum = MAX_INPUT) {
  const before = await lstat(file);
  if (!before.isFile() || before.nlink !== 1 || before.size > maximum) throw new Error('H454_PDF_INPUT_UNSUPPORTED');
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const current = await handle.stat();
    if (!current.isFile() || current.nlink !== 1 || current.dev !== before.dev || current.ino !== before.ino || current.size > maximum)
      throw new Error('H454_PDF_INPUT_UNSUPPORTED');
    const data = await handle.readFile();
    if (data.length > maximum) throw new Error('H454_PDF_TOO_LARGE');
    return data;
  } finally { await handle.close(); }
}

async function render(value, base, PDFDocument, fontkit, fontBytes, pageLayout) {
  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  const font = await doc.embedFont(fontBytes, { subset: true });
  const supported = new Set(font.getCharacterSet());
  let page, y, pages = 0;
  function nextPage() {
    if (++pages > MAX_PAGES) throw new Error('H454_PDF_TOO_LARGE');
    page = doc.addPage([pageLayout.width, pageLayout.height]); y = pageLayout.height - pageLayout.top;
  }
  function draw(text, size) {
    const step = size * 1.35;
    if (y - step < pageLayout.bottom) nextPage();
    if (text) page.drawText(text, { x: pageLayout.left, y, size, font });
    y -= step;
  }
  nextPage();
  for (const block of blocks(value, base)) {
    if (block.type === 'image') {
      const data = await boundedRead(block.source, 5 * 1024 * 1024);
      let image;
      if (data.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) image = await doc.embedPng(data);
      else if (data[0] === 0xff && data[1] === 0xd8) image = await doc.embedJpg(data);
      else throw new Error('H454_PDF_IMAGE_FORMAT_UNSUPPORTED');
      const scale = Math.min(1, (pageLayout.width - pageLayout.left - pageLayout.right) / image.width,
        (pageLayout.height - pageLayout.top - pageLayout.bottom - 20) / image.height);
      const width = image.width * scale, height = image.height * scale;
      if (y - height < pageLayout.bottom) nextPage();
      page.drawImage(image, { x: pageLayout.left, y: y - height, width, height });
      y -= height + 10;
      continue;
    }
    for (const cp of block.text) {
      const code = cp.codePointAt(0);
      if (code !== 10 && code !== 13 && code !== 9 && !supported.has(code))
        throw new Error('H454_PDF_GLYPH_UNSUPPORTED');
    }
    for (const original of block.text.replace(/\r\n?/g, '\n').split('\n')) {
      let line = '';
      for (const ch of original.replace(/\t/g, '    ')) {
        if (font.widthOfTextAtSize(line + ch, block.size) > pageLayout.width - pageLayout.left - pageLayout.right && line) { draw(line, block.size); line = ''; }
        line += ch;
      }
      draw(line, block.size);
    }
    y -= 5;
  }
  return doc;
}

export async function createPersonalPdf(args) {
  validateArgs(args);
  const { PDFDocument } = requireBundle('pdf-lib');
  const fontkit = requireAssets('../third_party/h454-fontkit.cjs');
  const fontBytes = await readFile(new URL('../third_party/h454-DejaVuSans.ttf', import.meta.url));
  let doc;
  if (typeof args.content === 'string') doc = await render(args.content, args.path, PDFDocument, fontkit, fontBytes, layout(args.options?.pdf_options));
  else {
    doc = await PDFDocument.load(await boundedRead(args.path));
    if (doc.getPageCount() > MAX_PAGES) throw new Error('H454_PDF_TOO_LARGE');
    for (const op of args.content) {
      if (op.type === 'delete') {
        const count = doc.getPageCount();
        const indexes = [...new Set(op.pageIndexes.map(i => i < 0 ? count + i : i)
          .filter(i => i >= 0 && i < count))].sort((a, b) => b - a);
        for (const index of indexes) doc.removePage(index);
      } else {
        const count = doc.getPageCount(), index = op.pageIndex < 0 ? count + op.pageIndex : op.pageIndex;
        if (index < 0 || index > count) throw new Error('H454_PDF_INVALID_PAGE');
        const source = typeof op.sourcePdfPath === 'string'
          ? await PDFDocument.load(await boundedRead(op.sourcePdfPath))
          : await render(op.markdown, args.path, PDFDocument, fontkit, fontBytes, layout(op.pdfOptions));
        if (count + source.getPageCount() > MAX_PAGES) throw new Error('H454_PDF_TOO_LARGE');
        const pages = await doc.copyPages(source, source.getPageIndices());
        for (let i = 0; i < pages.length; i++) doc.insertPage(index + i, pages[i]);
      }
    }
  }
  const bytes = await doc.save();
  if (bytes.length > MAX_INPUT) throw new Error('H454_PDF_TOO_LARGE');
  const target = args.outputPath ?? args.path;
  await writeFile(target, bytes, { flag: 'wx' });
  return { content: [{ type: 'text', text: `Successfully wrote PDF: ${target}` }] };
}
